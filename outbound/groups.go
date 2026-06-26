package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/utils"
	"golang.org/x/net/proxy"
)

// HandleResult encapsulates the result of a group's handle operation.
type HandleResult struct {
	Msg        *dns.Msg
	CallerName string
}

type IGroup interface {
	Match(req *dns.Msg) bool
	IsFallback() bool
	Handle(ctx context.Context, req *dns.Msg) *HandleResult
	PostProcess(req *dns.Msg, resp *dns.Msg)
	Start(resolver dns.Handler)
	Stop()
	Name() string
	String() string
	HasGFWList() bool
}

func BuildGroups(globalConf config.Conf) (map[string]IGroup, error) {
	groups := make(map[string]IGroup, len(globalConf.Groups))
	// check non-repeatable flag
	seenGFWList, seenFallback := false, false
	// build groups
	for name, conf := range globalConf.Groups {
		if conf.IsEmptyRule() {
			logrus.Warnf("set empty rule group %s as fallback group", name)
			conf.Fallback = true
		}
		if conf.Fallback && seenFallback {
			return nil, errors.New("only one group can be fallback group")
		}
		if conf.IsSetGFWList() && seenGFWList {
			return nil, errors.New("only one group can use gfw list mode")
		}
		if conf.Fallback {
			seenFallback = true
		}
		if conf.IsSetGFWList() {
			seenGFWList = true
		}
		// parse gfwlist update duration
		gfwListUpdate := time.Hour // default 1h
		if conf.GFWListUpdate != "" {
			d, err := parseDuration(conf.GFWListUpdate)
			if err != nil {
				return nil, fmt.Errorf("parse gfwlist_update %q failed: %w", conf.GFWListUpdate, err)
			}
			gfwListUpdate = d
		}
		g := &groupImpl{
			name:          name,
			fallback:      conf.Fallback,
			gfwListURL:    conf.GFWListURL,
			gfwListFile:   conf.GFWListFile,
			gfwListUpdate: gfwListUpdate,
			noCookie:      conf.NoCookie,
			concurrent:    conf.Concurrent,
			fastestIP:     conf.FastestV4,
			tcpPingPort:   conf.TCPPingPort,
			stopCh:        make(chan struct{}),
			stopped:       make(chan struct{}),
			disableQTypes: map[uint16]bool{},
		}
		// disable query types
		if conf.DisableIPv6 {
			g.disableQTypes[dns.TypeAAAA] = true
		}
		for _, qTypeStr := range conf.DisableQTypes {
			qTypeStr = strings.ToUpper(qTypeStr)
			if _, exists := dns.StringToType[qTypeStr]; !exists {
				return nil, fmt.Errorf("unknown query type: %q", qTypeStr)
			}
			g.disableQTypes[dns.StringToType[qTypeStr]] = true
		}

		// read rules
		text := strings.Join(conf.Rules, "\n")
		g.matcher = matcher.NewABPByText(text)
		if filename := conf.RulesFile; filename != "" {
			m, err := matcher.NewABPByFile(filename, false)
			if err != nil {
				return nil, fmt.Errorf("read rules file %q failed: %w", filename, err)
			}
			g.matcher.Extend(m)
		}
		// gfw list
		if conf.GFWListFile != "" {
			m, err := matcher.NewABPByFile(conf.GFWListFile, true)
			if err != nil {
				return nil, fmt.Errorf("build gfw list failed: %w", err)
			}
			atomic.StorePointer(&g.gfwList, unsafe.Pointer(m))
		}
		// ecs
		if conf.ECS != "" {
			ecs, err := utils.ParseECS(conf.ECS)
			if err != nil {
				return nil, fmt.Errorf("parse ecs %q failed: %w", conf.ECS, err)
			}
			logrus.Debugf("set ecs(%s) for group %s", conf.ECS, name)
			g.withECS = ecs
		}

		g.hijack = make([]string, 0, len(conf.Hijack))
		for _, rule := range conf.Hijack {
			parts := strings.Split(rule, "/")
			if len(parts) != 4 || parts[0] != "" || parts[3] != "" {
				logrus.Warnf("group %s: invalid hijack rule %q, expected format /source/dest/", name, rule)
				continue
			}
			g.hijack = append(g.hijack, rule)
		}

		// proxy
		if conf.Socks5 != "" {
			dialer, err := proxy.SOCKS5("tcp", conf.Socks5, nil, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("build socks5 proxy %q failed: %w", conf.Socks5, err)
			}
			logrus.Debugf("set proxy(%s) for group %s", conf.Socks5, name)
			g.proxy = dialer
		}
		// caller
		var callers []Caller
		for _, addr := range conf.DNS {
			network := "udp"
			if strings.HasSuffix(addr, "/tcp") {
				addr, network = addr[:len(addr)-4], "tcp"
			}
			if addr != "" {
				addr = ensurePort(addr, "53")
				callers = append(callers, NewDNSCaller(addr, network, g.proxy))
			}
		}
		for _, addr := range conf.DoT { // dns over tls服务器，格式为ip:port@serverName
			var serverName string
			if arr := strings.Split(addr, "@"); len(arr) != 2 {
				continue
			} else {
				addr, serverName = arr[0], arr[1]
			}
			if addr != "" && serverName != "" {
				addr = ensurePort(addr, "853")
				callers = append(callers, NewDoTCaller(addr, serverName, g.proxy))
			}
		}
		for _, addr := range conf.DoH { // dns over https服务器
			caller, err := NewDoHCallerV2(addr, g.proxy)
			if err != nil {
				return nil, fmt.Errorf("build doh caller %s failed: %w", addr, err)
			}
			callers = append(callers, caller)
		}
		g.callers = callers
		// ipset
		if name := conf.IPSet; name != "" {
			is, err := ipset.New(name, "hash:ip", &ipset.Params{Timeout: conf.IPSetTTL})
			if err != nil {
				return nil, fmt.Errorf("build ipset %q failed: %w", name, err)
			}
			g.ipSet = ipSetWrapper{is}
		}
		if name := conf.IPSet6; name != "" {
			is, err := ipset.New(name, "hash:ip", &ipset.Params{Timeout: conf.IPSetTTL, HashFamily: "inet6"})
			if err != nil {
				return nil, fmt.Errorf("build ipset %q failed: %w", name, err)
			}
			g.ipSet6 = ipSetWrapper{is}
		}
		g.ipSetCh = make(chan ipSetTask, 1024)
		groups[name] = g
	}

	return groups, nil
}

var (
	_ IGroup = &groupImpl{}
)

type ipSetTask struct {
	val     string
	timeout int
	target  iIPSet
}

type groupImpl struct {
	name     string
	fallback bool

	disableQTypes map[uint16]bool
	matcher       *matcher.ABPlus
	gfwList       unsafe.Pointer // type: *matcher.ABPlus
	gfwListURL    string
	gfwListFile   string         // 本地 gfwlist 文件路径
	gfwListUpdate time.Duration  // gfwlist_url 更新周期

	noCookie bool              // 是否删除请求中的cookie
	withECS  *dns.EDNS0_SUBNET // 是否在请求中附加ECS信息

	callers              []Caller
	concurrent           bool
	proxy                proxy.Dialer
	hijack               []string

	fastestIP   bool // 是否对响应中的IP地址进行测速，找出ping值最低的IP地址
	tcpPingPort int  // 是否使用tcp ping

	ipSet   iIPSet // 将响应中的IPv4地址加入ipset
	ipSet6  iIPSet // 将响应中的IPv4地址加入ipset
	ipSetCh chan ipSetTask

	started int32
	stopCh  chan struct{}
	stopped chan struct{}
}

// callerResult holds the DNS message and the name of the caller that provided it.
type callerResult struct {
	Msg        *dns.Msg
	CallerName string
}

func (g *groupImpl) Name() string     { return g.name }
func (g *groupImpl) String() string   { return "group_" + g.Name() }
func (g *groupImpl) IsFallback() bool { return g.fallback }
func (g *groupImpl) HasGFWList() bool {
	return g.gfwListURL != "" || atomic.LoadPointer(&g.gfwList) != nil
}

func (g *groupImpl) Match(req *dns.Msg) bool {
	domain := ""
	if len(req.Question) > 0 {
		domain = req.Question[0].Name
	}
	if domain == "" {
		return false
	}

	if match, _ := g.matcher.Match(domain); match {
		return true
	}
	if ptr := atomic.LoadPointer(&g.gfwList); ptr != nil {
		if match, _ := (*matcher.ABPlus)(ptr).Match(domain); match {
			return true
		}
	}
	return false
}

func (g *groupImpl) processHijackRules(msg *dns.Msg, reverse bool) {
	if msg == nil {
		return
	}

	for _, rule := range g.hijack {
		parts := strings.Split(rule, "/")
		source := parts[1]
		dest := parts[2]

		for i := range msg.Question {
			if reverse == false {
				if strings.Contains(msg.Question[i].Name, source) {
					msg.Question[i].Name = strings.Replace(msg.Question[i].Name, source, dest, -1)
				}
			} else {
				if strings.Contains(msg.Question[i].Name, dest) {
					msg.Question[i].Name = strings.Replace(msg.Question[i].Name, dest, source, -1)
				}
			}
		}
	}
}

func (g *groupImpl) Handle(ctx context.Context, req *dns.Msg) *HandleResult {
	for _, question := range req.Question {
		if g.disableQTypes[question.Qtype] {
			return nil // disabled
		}
	}
	// 预处理请求
	if g.noCookie || g.withECS != nil {
		req = req.Copy()
		if g.noCookie {
			utils.RemoveEDNSCookie(req)
		}
		if g.withECS != nil {
			utils.SetDefaultECS(req, g.withECS)
		}
	}

	g.processHijackRules(req, false)

	if !g.concurrent && !g.fastestIP {
		// 依次请求上游DNS
		for _, caller := range g.callers {
			resp, err := caller.Call(ctx, req)
			if err != nil {
				logrus.Warnf("group %s call %s failed: %+v", g.name, caller, err)
				continue
			}
			if resp == nil {
				logrus.Warnf("group %s call %s returned empty response", g.name, caller)
				continue
			}
			g.processHijackRules(resp, true)
			return &HandleResult{Msg: resp, CallerName: caller.String()}
		}
		return nil
	}

	// 并发请求上游DNS
	chLen := len(g.callers)
	respCh := make(chan *callerResult, chLen)
	for _, caller := range g.callers {
		go func(caller Caller) {
			resp, err := caller.Call(ctx, req)
			if err == nil && resp != nil {
				g.processHijackRules(resp, true)
				respCh <- &callerResult{Msg: resp, CallerName: caller.String()}
			} else {
				logrus.Warnf("group %s call %s failed: %+v", g.name, caller, err)
				respCh <- nil // Send nil if error, meaning no valid *callerResult
			}
		}(caller)
	}
	// 处理响应
	var qType uint16
	if len(req.Question) > 0 {
		qType = req.Question[0].Qtype
	}
	if (qType == dns.TypeA || qType == dns.TypeAAAA) && g.fastestIP {
		// 测速并返回最快ip
		return g.fastestResp(qType, respCh, chLen)
	}
	// 无需测速，只需返回第一个不为nil的DNS响应
	for i := 0; i < chLen; i++ {
		select {
		case cr := <-respCh:
			if cr != nil && cr.Msg != nil {
				return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
			}
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

func (g *groupImpl) fastestResp(qType uint16, respCh chan *callerResult, chLen int) *HandleResult {
	const (
		maxGoNum    = 15 // 最大并发量
		pingTimeout = 500 * time.Millisecond
	)
	// 从resp ch中提取所有IP地址，并建立IP地址到resp的映射
	allIP := make([]string, 0, maxGoNum)
	respMap := make(map[string]*callerResult, maxGoNum) // Change type
	var firstCR *callerResult                           // Store the first callerResult
	var firstResp *dns.Msg                              // 最早抵达的msg，当测速失败时返回该响应
	var firstRespCallerName string
	for i := 0; i < chLen; i++ {
		cr := <-respCh // Changed resp to cr
		if cr == nil || cr.Msg == nil {
			continue
		}
		if firstCR == nil { // Store the first callerResult
			firstCR = cr
			firstResp = cr.Msg
			firstRespCallerName = cr.CallerName
		}
		for _, answer := range cr.Msg.Answer { // Access cr.Msg
			var ip string
			switch rr := answer.(type) {
			case *dns.A:
				if qType == dns.TypeA {
					ip = rr.A.String()
				}
			case *dns.AAAA:
				if qType == dns.TypeAAAA {
					ip = rr.AAAA.String()
				}
			}
			if ip != "" {
				allIP = append(allIP, ip)
				if _, exists := respMap[ip]; !exists {
					respMap[ip] = cr // Store callerResult
					if len(respMap) >= maxGoNum {
						goto doPing
					}
				}
			}
		}
	}
doPing:
	switch len(respMap) {
	case 0: // 没有任何IP地址
		if firstResp == nil {
			return nil
		}
		return &HandleResult{Msg: firstResp, CallerName: firstRespCallerName}
	case 1: // 只有一个IPv4地址
		for _, cr := range respMap {
			return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
		}
	}
	fastestIP, cost, err := utils.FastestPingIP(allIP, g.tcpPingPort, pingTimeout)
	if err != nil {
		if firstResp == nil {
			return nil
		}
		return &HandleResult{Msg: firstResp, CallerName: firstRespCallerName}
	}
	logrus.Debugf("fastest ip of %s: %s(%dms)", allIP, fastestIP, cost)
	chosenCR := respMap[fastestIP]          // Get the chosen callerResult
	msg := chosenCR.Msg                     // Get Msg from callerResult
	chosenCallerName := chosenCR.CallerName // Get CallerName

	// 删除msg内除fastestIP之外的其它IP记录
	for i := 0; i < len(msg.Answer); i++ {
		switch rr := msg.Answer[i].(type) {
		case *dns.A:
			if qType == dns.TypeA && rr.A.String() != fastestIP {
				goto delThis
			}
		case *dns.AAAA:
			if qType == dns.TypeAAAA && rr.AAAA.String() != fastestIP {
				goto delThis
			}
		}
		continue
	delThis:
		msg.Answer = append(msg.Answer[:i], msg.Answer[i+1:]...)
		i--
	}
	return &HandleResult{Msg: msg, CallerName: chosenCallerName}
}

func (g *groupImpl) PostProcess(_ *dns.Msg, resp *dns.Msg) {
	if resp == nil {
		return
	}
	for _, answer := range resp.Answer {
		var val string
		var target iIPSet
		switch tv := answer.(type) {
		case *dns.A:
			val, target = tv.A.String(), g.ipSet
		case *dns.AAAA:
			val, target = tv.AAAA.String(), g.ipSet6
		}
		if val == "" || target == nil {
			continue
		}
		select {
		case g.ipSetCh <- ipSetTask{val: val, timeout: target.GetTimeout(), target: target}:
		default:
			logrus.Warnf("ipset channel full, skip adding %s", val)
		}
	}
}

// grabGFWList 从远程 URL 拉取 GFWList，返回 base64 解码后的文本内容
func (g *groupImpl) grabGFWList(ctx context.Context) []byte {
	if g.gfwListURL == "" {
		return nil
	}
	client := new(http.Client)
	client.Timeout = 10 * time.Second
	if g.proxy != nil {
		wrap := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return g.proxy.Dial(network, addr)
		}
		client.Transport = &http.Transport{DialContext: wrap}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", g.gfwListURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		logrus.Warnf("get gfw list %q failed: %+v", g.gfwListURL, err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		logrus.Warnf("get gfw list %q failed, status_code: %d", g.gfwListURL, resp.StatusCode)
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Warnf("read gfw list %q failed, error: %+v", g.gfwListURL, err)
		return nil
	}
	if len(data) > 100 {
		logrus.Debugf("gfw list raw data length: %d, first 100 bytes: %q", len(data), data[:100])
	} else {
		logrus.Debugf("gfw list raw data length: %d, content: %q", len(data), data)
	}
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dst, data)
	if err != nil {
		if len(data) > 50 {
			logrus.Warnf("decode gfw list %q failed, error: %+v, first 50 bytes: %q", g.gfwListURL, err, data[:50])
		} else {
			logrus.Warnf("decode gfw list %q failed, error: %+v, content: %q", g.gfwListURL, err, data)
		}
		return nil
	}
	return dst[:n]
}

func (g *groupImpl) Start(resolver dns.Handler) {
	atomic.StoreInt32(&g.started, 1)
	for _, caller := range g.callers {
		caller.Start(resolver)
	}
	// ipset worker
	go func() {
		handleTask := func(task ipSetTask) {
			if err := task.target.Add(task.val, task.timeout); err != nil {
				logrus.Warnf("add %s to ipset<%s> failed: %+v", task.val, task.target.GetName(), err)
			}
		}
		for {
			select {
			case task := <-g.ipSetCh:
				handleTask(task)
			case <-g.stopCh:
				for {
					select {
					case task := <-g.ipSetCh:
						handleTask(task)
					default:
						return
					}
				}
			}
		}
	}()
	// 仅当配置了 gfwlist_url 时才启动后台更新
	if g.gfwListURL != "" {
		tick := time.NewTicker(g.gfwListUpdate)
		go func() {
			defer close(g.stopped)
			defer tick.Stop()
			// 首次启动时立即拉取
			g.refreshGFWList()
			for {
				select {
				case <-tick.C:
					g.refreshGFWList()
				case <-g.stopCh:
					return
				}
			}
		}()
	} else {
		// 没有 URL 更新，直接关闭 stopped
		close(g.stopped)
	}
}

func (g *groupImpl) Stop() {
	if atomic.LoadInt32(&g.started) == 0 {
		return
	}
	logrus.Debugf("stop group %s", g)
	for _, caller := range g.callers {
		caller.Exit()
	}
	close(g.stopCh)
	<-g.stopped
	logrus.Debugf("stop group %s success", g)
}

// ensurePort ensures addr has a port appended. Handles IPv6 addresses correctly.
// If addr already contains a port (e.g. "1.1.1.1:53", "[::1]:53"), it is returned as-is.
// If addr has no port (e.g. "1.1.1.1", "::1", "[::1]"), defaultPort is appended.
func ensurePort(addr, defaultPort string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr // already has port
	}
	// Strip brackets if present (e.g. "[::1]" → "::1") to avoid double-wrapping
	addr = strings.Trim(addr, "[]")
	return net.JoinHostPort(addr, defaultPort)
}

// refreshGFWList 从远程 URL 拉取 GFWList，写回本地文件并热更新匹配规则
func (g *groupImpl) refreshGFWList() {
	text := g.grabGFWList(context.Background())
	if text == nil {
		return
	}
	// 写回本地文件（base64 编码后存储，与原始 gfwlist.txt 格式一致）
	if g.gfwListFile != "" {
		encoded := base64.StdEncoding.EncodeToString(text)
		if err := os.WriteFile(g.gfwListFile, []byte(encoded), 0640); err != nil {
			logrus.Warnf("write gfw list to %q failed: %+v", g.gfwListFile, err)
		} else {
			logrus.Infof("gfw list saved to %q", g.gfwListFile)
		}
	}
	// 热更新匹配规则
	m := matcher.NewABPByText(string(text))
	atomic.StorePointer(&g.gfwList, unsafe.Pointer(m))
}

// parseDuration 解析时间周期字符串，支持 m/h/d 后缀（如 30m、1h、2d）
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	suffix := s[len(s)-1]
	num := s[:len(s)-1]
	var d time.Duration
	var err error
	switch suffix {
	case 'm':
		d, err = time.ParseDuration(num + "m")
	case 'h':
		d, err = time.ParseDuration(num + "h")
	case 'd':
		d, err = time.ParseDuration(num + "h")
		if err == nil {
			d *= 24
		}
	default:
		d, err = time.ParseDuration(s)
	}
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive: %q", s)
	}
	return d, nil
}
