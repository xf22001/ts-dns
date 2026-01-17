package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	Handle(req *dns.Msg) *HandleResult
	PostProcess(req *dns.Msg, resp *dns.Msg)
	Start(resolver dns.Handler)
	Stop()
	Name() string
	String() string
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
		g := &groupImpl{
			name:                 name,
			fallback:             conf.Fallback,
			matcher:              nil,
			gfwList:              nil,
			gfwListURL:           conf.GFWListURL,
			noCookie:             conf.NoCookie,
			withECS:              nil,
			callers:              nil,
			concurrent:           conf.Concurrent,
			proxy:                nil,
			socks5FallbackDirect: conf.Socks5FallbackDirect,
			hijack:               nil,
			fastestIP:            conf.FastestV4,
			tcpPingPort:          conf.TCPPingPort,
			ipSet:                nil,
			stopCh:               make(chan struct{}),
			stopped:              make(chan struct{}),
			disableQTypes:        map[uint16]bool{},
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
			logrus.Debugf("set ecs(%s) for group %s", conf.ECS, err)
			g.withECS = ecs
		}

		g.hijack = append([]string{}, conf.Hijack...)

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
				if !strings.Contains(addr, ":") {
					addr += ":53"
				}
				callers = append(callers, NewDNSCaller(addr, network, g.proxy, g.socks5FallbackDirect))
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
				if !strings.Contains(addr, ":") {
					addr += ":853"
				}
				callers = append(callers, NewDoTCaller(addr, serverName, g.proxy, g.socks5FallbackDirect))
			}
		}
		for _, addr := range conf.DoH { // dns over https服务器
			caller, err := NewDoHCallerV2(addr, g.proxy, g.socks5FallbackDirect)
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
		groups[name] = g
	}

	return groups, nil
}

var (
	_ IGroup = &groupImpl{}
)

type groupImpl struct {
	name     string
	fallback bool

	disableQTypes map[uint16]bool
	matcher       *matcher.ABPlus
	gfwList       unsafe.Pointer // type: *matcher.ABPlus
	gfwListURL    string

	noCookie bool              // 是否删除请求中的cookie
	withECS  *dns.EDNS0_SUBNET // 是否在请求中附加ECS信息

	callers              []Caller
	concurrent           bool
	proxy                proxy.Dialer
	socks5FallbackDirect bool
	hijack               []string

	fastestIP   bool // 是否对响应中的IP地址进行测速，找出ping值最低的IP地址
	tcpPingPort int  // 是否使用tcp ping

	ipSet  iIPSet // 将响应中的IPv4地址加入ipset
	ipSet6 iIPSet // 将响应中的IPv4地址加入ipset

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
		//logrus.Warnf("group %s", g.name)
		parts := strings.Split(rule, "/")
		if len(parts) != 4 || parts[0] != "" || parts[3] != "" {
			continue // Skip invalid rule
		}
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

func (g *groupImpl) Handle(req *dns.Msg) *HandleResult {
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
			resp, err := caller.Call(req)
			if err != nil {
				logrus.Warnf("group %s call %s failed: %+v", g.name, caller, err)
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
			resp, err := caller.Call(req)
			if err == nil {
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
		if cr := <-respCh; cr != nil {
			return &HandleResult{Msg: cr.Msg, CallerName: cr.CallerName}
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
	var firstCR *callerResult // Store the first callerResult
	var firstResp *dns.Msg    // 最早抵达的msg，当测速失败时返回该响应
	var firstRespCallerName string
	for i := 0; i < chLen; i++ {
		cr := <-respCh // Changed resp to cr
		if cr == nil {
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
	chosenCR := respMap[fastestIP]         // Get the chosen callerResult
	msg := chosenCR.Msg                   // Get Msg from callerResult
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
		if err := target.Add(val, target.GetTimeout()); err != nil {
			logrus.Warnf("add %s to ipset<%s> failed: %+v", val, target.GetName(), err)
		}
	}
}

func (g *groupImpl) grabGFWList() *matcher.ABPlus {
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
	// todo 自闭环解析dns
	req, _ := http.NewRequest("GET", g.gfwListURL, nil)
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
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	if _, err = base64.StdEncoding.Decode(data, dst); err != nil {
		logrus.Warnf("decode gfw list %q failed, error: %+v", g.gfwListURL, err)
		return nil
	}
	return matcher.NewABPByText(string(dst))
}

func (g *groupImpl) Start(resolver dns.Handler) {
	for _, caller := range g.callers {
		caller.Start(resolver)
	}
	lastSuccess := time.Unix(0, 0)
	tick := time.NewTicker(time.Minute)
	go func() {
		for {
			select {
			case <-tick.C:
				if time.Since(lastSuccess).Hours() < 1 {
					// every hour
					continue
				}
				if m := g.grabGFWList(); m != nil {
					atomic.StorePointer(&g.gfwList, unsafe.Pointer(m))
					lastSuccess = time.Now()
				}
			case <-g.stopCh:
				close(g.stopped)
				tick.Stop()
				return
			}
		}
	}()
}

func (g *groupImpl) Stop() {
	logrus.Debugf("stop group %s", g)
	for _, caller := range g.callers {
		caller.Exit()
	}
	close(g.stopCh)
	<-g.stopped
	logrus.Debugf("stop group %s success", g)
}
