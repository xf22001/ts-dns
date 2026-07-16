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
	"sync"
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
			fastestIP:     conf.FastestIP,
			tcpPingPort:   conf.TCPPingPort,
			pingTimeout:   conf.FastestPingTimeoutMs,
			maxPingIPs:    conf.FastestPingMaxIPs,
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
		for _, caller := range callers {
			wc := &indexedCaller{Caller: caller, index: len(g.allCallers)}
			g.allCallers = append(g.allCallers, wc)
		}
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

// indexedCaller keeps the stable caller index used by per-host states.
type indexedCaller struct {
	Caller
	index int
}

type callerState int64

const (
	callerIdle callerState = iota
	callerActive

	callerReselectInterval     = time.Hour
	callerStatsTTL             = 24 * time.Hour
	callerStatsCleanupInterval = 5 * time.Minute
)

type hostCallerStats struct {
	activeIndex   int
	state         callerState
	seen          bool
	lastUsed      time.Time
	reselectAfter time.Time
}

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
	gfwListFile   string        // 本地 gfwlist 文件路径
	gfwListUpdate time.Duration // gfwlist_url 更新周期

	noCookie bool              // 是否删除请求中的cookie
	withECS  *dns.EDNS0_SUBNET // 是否在请求中附加ECS信息

	proxy  proxy.Dialer
	hijack []string

	fastestIP   bool // 是否对响应中的IP地址进行测速，找出ping值最低的IP地址
	tcpPingPort int  // 是否使用tcp ping
	pingTimeout int  // 测速超时，单位毫秒；<=0 时使用默认值
	maxPingIPs  int  // 参与测速的最大IP数量；<=0 时使用默认值

	allCallers  []*indexedCaller
	hostStats   map[string]*hostCallerStats
	lastCleanup time.Time
	stateMu     sync.RWMutex

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
	Caller     *indexedCaller
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
			if !reverse {
				msg.Question[i].Name = replaceDomainSuffix(msg.Question[i].Name, source, dest)
			} else {
				msg.Question[i].Name = replaceDomainSuffix(msg.Question[i].Name, dest, source)
			}
		}
	}
}

func replaceDomainSuffix(name, source, dest string) string {
	if name == "" || source == "" || dest == "" {
		return name
	}
	original := name
	hasTrailingDot := strings.HasSuffix(name, ".")
	name = dns.Fqdn(name)
	source = dns.Fqdn(source)
	dest = dns.Fqdn(dest)

	var replaced string
	if strings.EqualFold(name, source) {
		replaced = dest
	} else {
		suffix := "." + source
		if len(name) <= len(suffix) || !strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			return original
		}
		replaced = name[:len(name)-len(source)] + dest
	}
	if !hasTrailingDot {
		replaced = strings.TrimSuffix(replaced, ".")
	}
	return replaced
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

	host := queryHost(req)
	candidates := g.candidatesForHost(host)
	if len(candidates) == 0 {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	chLen := len(candidates)
	respCh := g.runCallerAttempts(ctx, host, req, candidates)

	var result *HandleResult
	var qType uint16
	if len(req.Question) > 0 {
		qType = req.Question[0].Qtype
	}
	if (qType == dns.TypeA || qType == dns.TypeAAAA) && g.fastestIP {
		// 测速并返回最快ip
		result = g.fastestResp(ctx, host, qType, respCh, chLen)
	} else {
		result = g.firstResponse(ctx, host, respCh, chLen)
	}

	return result
}

func (g *groupImpl) runCallerAttempts(ctx context.Context, host string, req *dns.Msg, candidates []*indexedCaller) <-chan *callerResult {
	respCh := make(chan *callerResult, len(candidates))
	for _, caller := range candidates {
		go func(caller *indexedCaller) {
			result := g.runCallerAttempt(ctx, host, req, caller)
			select {
			case respCh <- result:
			case <-ctx.Done():
			}
		}(caller)
	}
	return respCh
}

func (g *groupImpl) runCallerAttempt(ctx context.Context, host string, req *dns.Msg, wc *indexedCaller) *callerResult {
	resp, err := wc.Call(ctx, req)
	if err == nil && resp != nil {
		g.processHijackRules(resp, true)
		return &callerResult{Msg: resp, Caller: wc, CallerName: wc.String()}
	}
	if errors.Is(err, context.Canceled) {
		logrus.Debugf("group %s call %s canceled", g.name, wc)
		return nil
	}
	g.recordCallerFailure(host, wc)
	logrus.Warnf("group %s call %s failed: %+v", g.name, wc, err)
	return nil
}

func (g *groupImpl) firstResponse(ctx context.Context, host string, respCh <-chan *callerResult, chLen int) *HandleResult {
	for i := 0; i < chLen; i++ {
		select {
		case cr := <-respCh:
			if cr != nil && cr.Msg != nil {
				g.recordCallerSuccess(host, cr.Caller)
				return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
			}
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

func queryHost(req *dns.Msg) string {
	if req == nil || len(req.Question) == 0 {
		return ""
	}
	return strings.ToLower(dns.Fqdn(req.Question[0].Name))
}

func (g *groupImpl) candidatesForHost(host string) []*indexedCaller {
	g.stateMu.Lock()
	defer g.stateMu.Unlock()

	now := time.Now()
	g.cleanupHostStatsLocked(now)
	entry := g.hostStats[host]
	if entry != nil {
		entry.lastUsed = now
	}
	if entry == nil || !entry.seen {
		return g.allCallerCandidates()
	}
	if entry.state == callerActive && !now.Before(entry.reselectAfter) {
		return g.allCallerCandidates()
	}
	if entry.state == callerActive && entry.activeIndex >= 0 && entry.activeIndex < len(g.allCallers) {
		return []*indexedCaller{g.allCallers[entry.activeIndex]}
	}
	return g.allCallerCandidates()
}

func (g *groupImpl) allCallerCandidates() []*indexedCaller {
	candidates := make([]*indexedCaller, 0, len(g.allCallers))
	for _, caller := range g.allCallers {
		candidates = append(candidates, caller)
	}
	return candidates
}

func (g *groupImpl) recordCallerSuccess(host string, wc *indexedCaller) {
	if wc == nil || wc.index < 0 || wc.index >= len(g.allCallers) {
		return
	}
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	now := time.Now()
	entry := g.ensureHostStatsLocked(host)
	shouldResetReselect := !entry.seen || entry.state != callerActive || entry.activeIndex != wc.index || !now.Before(entry.reselectAfter)
	entry.activeIndex = wc.index
	entry.state = callerActive
	entry.seen = true
	if shouldResetReselect {
		entry.reselectAfter = now.Add(callerReselectInterval)
	}
}

func (g *groupImpl) recordCallerFailure(host string, wc *indexedCaller) {
	if wc == nil || wc.index < 0 || wc.index >= len(g.allCallers) {
		return
	}
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	entry := g.ensureHostStatsLocked(host)
	if !entry.seen || entry.activeIndex == wc.index {
		entry.activeIndex = -1
		entry.state = callerIdle
		entry.seen = true
	}
}

func (g *groupImpl) ensureHostStatsLocked(host string) *hostCallerStats {
	if g.hostStats == nil {
		g.hostStats = make(map[string]*hostCallerStats)
	}
	entry := g.hostStats[host]
	if entry == nil {
		entry = &hostCallerStats{activeIndex: -1}
		g.hostStats[host] = entry
	}
	entry.lastUsed = time.Now()
	return entry
}

func (g *groupImpl) hostStatsSnapshot(host string) hostCallerStats {
	g.stateMu.RLock()
	defer g.stateMu.RUnlock()
	entry := g.hostStats[host]
	if entry == nil {
		return hostCallerStats{activeIndex: -1}
	}
	return *entry
}

func (g *groupImpl) cleanupHostStatsLocked(now time.Time) {
	if !g.lastCleanup.IsZero() && now.Sub(g.lastCleanup) < callerStatsCleanupInterval {
		return
	}
	g.lastCleanup = now
	for host, entry := range g.hostStats {
		if entry != nil && !entry.lastUsed.IsZero() && now.Sub(entry.lastUsed) > callerStatsTTL {
			delete(g.hostStats, host)
		}
	}
}

func (g *groupImpl) fastestResp(ctx context.Context, host string, qType uint16, respCh <-chan *callerResult, chLen int) *HandleResult {
	const (
		defaultMaxGoNum    = 15
		defaultPingTimeout = 500 * time.Millisecond
	)
	maxGoNum := defaultMaxGoNum
	if g.maxPingIPs > 0 {
		maxGoNum = g.maxPingIPs
	}
	pingTimeout := defaultPingTimeout
	if g.pingTimeout > 0 {
		pingTimeout = time.Duration(g.pingTimeout) * time.Millisecond
	}
	// 先选出最快返回的 caller，再在这份响应内选择最快 IP。
	allIP := make([]string, 0, maxGoNum)
	seenIP := make(map[string]struct{}, maxGoNum)
	var cr *callerResult
	for i := 0; i < chLen; i++ {
		select {
		case cr = <-respCh:
		case <-ctx.Done():
			return nil
		}
		if cr == nil || cr.Msg == nil {
			continue
		}
		break
	}
	if cr == nil || cr.Msg == nil {
		return nil
	}

	for _, answer := range cr.Msg.Answer {
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
			if _, exists := seenIP[ip]; exists {
				continue
			}
			seenIP[ip] = struct{}{}
			allIP = append(allIP, ip)
			if len(allIP) >= maxGoNum {
				break
			}
		}
	}

	switch len(allIP) {
	case 0: // 没有任何IP地址
		g.recordCallerSuccess(host, cr.Caller)
		return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
	case 1: // 只有一个IP地址
		g.recordCallerSuccess(host, cr.Caller)
		return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
	}
	pingTO := pingTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < pingTO {
			if remaining <= 0 {
				g.recordCallerSuccess(host, cr.Caller)
				return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
			}
			pingTO = remaining
		}
	}
	fastestIP, cost, err := utils.FastestPingIP(allIP, g.tcpPingPort, pingTO)
	if err != nil {
		g.recordCallerSuccess(host, cr.Caller)
		return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
	}
	logrus.Debugf("fastest ip of %s: %s(%dms)", allIP, fastestIP, cost)
	msg := cr.Msg
	g.recordCallerSuccess(host, cr.Caller)

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
	return &HandleResult{Msg: msg, CallerName: cr.CallerName}
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
	for _, wc := range g.allCallers {
		wc.Start(resolver)
	}
	var wg sync.WaitGroup
	// ipset worker
	wg.Add(1)
	go func() {
		defer wg.Done()
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
		wg.Add(1)
		go func() {
			defer wg.Done()
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
	}
	go func() {
		wg.Wait()
		close(g.stopped)
	}()
}

func (g *groupImpl) Stop() {
	if atomic.LoadInt32(&g.started) == 0 {
		return
	}
	logrus.Debugf("stop group %s", g)
	for _, wc := range g.allCallers {
		wc.Exit()
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
			const maxDuration = time.Duration(1<<63 - 1)
			if d > maxDuration/24 {
				return 0, fmt.Errorf("duration overflows: %q", s)
			}
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
