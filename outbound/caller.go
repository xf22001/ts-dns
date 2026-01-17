package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/utils"

	"github.com/miekg/dns"
	"github.com/valyala/fastrand"
	"golang.org/x/net/proxy"
)

// Caller 上游DNS请求基类
type Caller interface {
	Call(request *dns.Msg) (r *dns.Msg, err error)
	Start(resolver dns.Handler)
	Exit()
	String() string
}

var (
	_ Caller = &DNSCaller{}
	_ Caller = &DoHCallerV2{}
)

// DNSCaller UDP/TCP/DOT请求类
type DNSCaller struct {
	client               *dns.Client
	server               string
	proxy                proxy.Dialer
	socks5FallbackDirect bool
	conn                 *dns.Conn
}

func (caller *DNSCaller) Start(_ dns.Handler) {}

// Call 向目标上游DNS转发请求
func (caller *DNSCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	if caller.proxy == nil { // 不使用代理，直接发送dns请求
		r, _, err = caller.client.Exchange(request, caller.server)
		return
	}
	// 通过代理连接代理服务器
	var proxyConn net.Conn
	proxyConn, err = caller.proxy.Dial("tcp", caller.server)
	if err != nil {
		if caller.socks5FallbackDirect {
			// logrus.Warnf("DNSCaller %s proxy dial failed: %v, attempting direct connection", caller.server, err)
			// Attempt direct connection
			client := &dns.Client{Net: caller.client.Net} // Create a new client without proxy
			r, _, directErr := client.Exchange(request, caller.server)
			if directErr == nil {
				return r, nil
			}
			// logrus.Warnf("DNSCaller %s direct connection also failed: %v", caller.server, directErr)
		}
		return nil, err // Original proxy error or direct connection failed
	}
	defer func() { _ = proxyConn.Close() }()
	// 打包连接
	caller.conn.Conn = proxyConn
	if caller.client.TLSConfig != nil { // dns over tls
		caller.conn.Conn = tls.Client(proxyConn, caller.client.TLSConfig)
	}
	// 发送dns请求
	if err = caller.conn.WriteMsg(request); err != nil {
		return nil, err
	}
	return caller.conn.ReadMsg()
}

// Exit caller退出时行为
func (caller *DNSCaller) Exit() {}

// String 描述caller
func (caller *DNSCaller) String() string {
	return fmt.Sprintf("DNSCaller<%s/%s>", caller.server, caller.client.Net)
}

// NewDNSCaller 创建一个UDP/TCP Caller，需要服务器地址（ip+端口）、网络类型（udp、tcp），可选代理
func NewDNSCaller(server, network string, proxy proxy.Dialer, socks5FallbackDirect bool) *DNSCaller {
	client := &dns.Client{Net: network}
	return &DNSCaller{client: client, server: server, proxy: proxy, socks5FallbackDirect: socks5FallbackDirect, conn: &dns.Conn{}}
}

// NewDoTCaller 创建一个DoT Caller，需要服务器地址（ip+端口）、证书名称，可选代理
func NewDoTCaller(server, serverName string, proxy proxy.Dialer, socks5FallbackDirect bool) *DNSCaller {
	client := &dns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{ServerName: serverName}}
	return &DNSCaller{client: client, server: server, proxy: proxy, socks5FallbackDirect: socks5FallbackDirect, conn: &dns.Conn{}}
}

// DoHCallerV2 DoT请求类，通过resolver自动解析域名
type DoHCallerV2 struct {
	host                 string
	port                 string
	url                  string
	clients              []*http.Client
	rwMux                sync.RWMutex
	resolver             dns.Handler
	dialer               proxy.Dialer
	directDialer         net.Dialer
	socks5FallbackDirect bool

	satisfyCh chan interface{} // 域名解析完成
	requireCh chan *dns.Msg    // 要求解析域名
	cancelCh  chan interface{} // stop run()
}

func (caller *DoHCallerV2) Start(resolver dns.Handler) {
	caller.resolver = resolver
	go caller.run(time.Hour*24, time.Second)
}

// 后台goroutine，负责定时/按需解析DoH服务器域名
func (caller *DoHCallerV2) run(resolveCycle time.Duration, timeout time.Duration) {
	tick := time.NewTicker(resolveCycle)
	for {
		select {
		case <-tick.C:
			caller.rwMux.Lock()
			caller.resolve(nil, timeout)
			caller.rwMux.Unlock()
		case req := <-caller.requireCh: // getClient()触发
			caller.rwMux.Lock()
			if len(caller.clients) == 0 {
				caller.resolve(req, timeout)
			}
			caller.rwMux.Unlock()
			caller.satisfyCh <- struct{}{} // 通知getClient()
		case <-caller.cancelCh:
			tick.Stop()
			return
		}
	}
}

// 使用resolver，将host解析成ipv4并生成clients
func (caller *DoHCallerV2) resolve(srcReq *dns.Msg, timeout time.Duration) {
	genClient := func(ip string) *http.Client {
		return &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (conn net.Conn, err error) {
				addr := ip + ":" + caller.port // 重写addr
				return caller.dialer.Dial(network, addr)
			},
		}}
	}
	name := caller.host + "."
	if srcReq != nil && len(srcReq.Question) > 0 && srcReq.Question[0].Name == name {
		logrus.Errorf("%s resolve recursive", caller)
		return // 可能是回环解析：DoHCaller想通过ts-dns解析自身域名，但ts-dns将请求转发回DoHCaller
	}
	// 模拟dns请求
	resolveReq := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: 0xffff, RecursionDesired: true, AuthenticatedData: true},
		Question: []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	}
	writer := utils.NewFakeRespWriter()
	done := make(chan interface{}, 1)
	go func() {
		if caller.resolver != nil {
			caller.resolver.ServeDNS(writer, resolveReq)
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		return // 超时直接结束
	}
	// 解析响应中的ipv4地址
	clients := make([]*http.Client, 0, 2)
	ips := make([]string, 0, 2)
	if writer.Msg != nil {
		for _, rr := range writer.Msg.Answer {
			switch resp := rr.(type) {
			case *dns.A:
				clients = append(clients, genClient(resp.A.String()))
				ips = append(ips, resp.A.String())
			}
		}
	}
	if len(clients) > 0 {
		caller.clients = clients
		logrus.Debugf("%s resolve ip %s", caller, ips)
	} else {
		logrus.Warnf("%s resolve ip failed", caller)
	}
}

// 获取一个用于发送DoH查询请求的http客户端
func (caller *DoHCallerV2) getClient(req *dns.Msg) *http.Client {
	caller.rwMux.RLock()
	defer caller.rwMux.RUnlock()
	var n int
	if n = len(caller.clients); n == 0 { // 域名未解析
		caller.rwMux.RUnlock()
		caller.requireCh <- req // 要求解析域名
		<-caller.satisfyCh      // 等待解析完成
		caller.rwMux.RLock()
		if n = len(caller.clients); n == 0 {
			return nil
		}
		goto CHOICE
	}
CHOICE:
	return caller.clients[fastrand.Uint32n(uint32(n))]
}

// Call 向上游DNS转发请求
func (caller *DoHCallerV2) Call(request *dns.Msg) (r *dns.Msg, err error) {
	// --- Original logic using proxy ---
	client := caller.getClient(request)
	if client == nil {
		return nil, errors.New("empty client for doh caller")
	}
	var buf []byte
	if buf, err = request.Pack(); err != nil {
		return nil, err
	}
	var req *http.Request
	contentType, payload := "application/dns-message", bytes.NewBuffer(buf)
	if req, err = http.NewRequest("POST", caller.url, payload); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	var resp *http.Response
	resp, err = client.Do(req)

	if err != nil {
		if caller.socks5FallbackDirect {
			// logrus.Warnf("DoHCallerV2 %s proxy call failed: %v, attempting direct connection", caller.url, err)
			// --- Fallback to direct connection ---
			directClient := &http.Client{Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return caller.directDialer.DialContext(ctx, network, addr)
				},
			}}
			directResp, directErr := directClient.Do(req)
			if directErr == nil {
				resp = directResp // Use the successful direct response
				err = nil         // Clear the error
			} else {
				// logrus.Warnf("DoHCallerV2 %s direct connection also failed: %v", caller.url, directErr)
				return nil, err // Both failed, return original proxy error
			}
		} else {
			return nil, err // Not configured for fallback, return proxy error
		}
	}

	defer func() { _ = resp.Body.Close() }()
	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	if err = msg.Unpack(body); err != nil {
		return nil, err
	}
	return msg, nil
}

// Exit 停止后台goroutine。caller退出时行为
func (caller *DoHCallerV2) Exit() {
	logrus.Debugf("stop caller %s", caller)
	caller.cancelCh <- struct{}{}
	logrus.Debugf("stop caller %s success", caller)
}

// String 描述caller
func (caller *DoHCallerV2) String() string {
	return fmt.Sprintf("DoHCallerV2<%s>", caller.url)
}

// SetResolver 为DoHCaller设置域名解析器，需要在用NewDoHCallerV2()成功后调用一次
func (caller *DoHCallerV2) SetResolver(resolver dns.Handler) {
	caller.resolver = resolver
}

// NewDoHCallerV2 创建一个DoHCaller，需要服务器url，可选代理
func NewDoHCallerV2(rawURL string, proxyDialer proxy.Dialer, socks5FallbackDirect bool) (*DoHCallerV2, error) {
	// 解析url
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("rawURL should be abs url")
	}
	// 提取host、port
	var host, port string
	if i := strings.LastIndex(u.Host, ":"); i == -1 {
		u.Host += ":443"
	}
	if host, port, err = net.SplitHostPort(u.Host); err != nil {
		return nil, err
	}

	directDialer := net.Dialer{Timeout: 3 * time.Second} // Default direct dialer timeout

	// If no proxyDialer is provided, use directDialer as the main dialer
	// Otherwise, keep proxyDialer as the main dialer
	if proxyDialer == nil {
		proxyDialer = &directDialer
	}

	caller := &DoHCallerV2{
		host:                 host,
		port:                 port,
		url:                  u.String(),
		rwMux:                sync.RWMutex{},
		dialer:               proxyDialer,
		directDialer:         directDialer, // Store a direct dialer for fallback
		socks5FallbackDirect: socks5FallbackDirect,
	}
	caller.requireCh = make(chan *dns.Msg, 1)
	caller.satisfyCh = make(chan interface{}, 1)
	caller.cancelCh = make(chan interface{}, 1)
	return caller, nil
}
