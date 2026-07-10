package inbound

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/outbound"
	"github.com/wolf-joe/ts-dns/redirector"
)

// region interface

// IHandler ts-dns service handler
type IHandler interface {
	dns.Handler
	ReloadConfig(conf config.Conf) error
	Stop()
}

// NewHandler Build a service can handle dns request, life cycle start immediately
func NewHandler(conf config.Conf) (IHandler, error) {
	h := new(handlerWrapper)
	if err := h.ReloadConfig(conf); err != nil {
		return nil, err
	}
	return h, nil
}

// endregion

// region wrapper
var (
	_ IHandler = &handlerWrapper{}
)

// todo: add unittest
type handlerWrapper struct {
	lifecycleMu sync.Mutex
	drainMu     sync.RWMutex
	stopped     bool
	handlerPtr  atomic.Pointer[handlerImpl]
}

func (w *handlerWrapper) ReloadConfig(conf config.Conf) error {
	// create & start new handler
	h, err := newHandle(conf)
	if err != nil {
		return fmt.Errorf("make new handler failed: %w", err)
	}

	w.lifecycleMu.Lock()
	if w.stopped {
		w.lifecycleMu.Unlock()
		h.stop()
		return errors.New("handler stopped")
	}
	h.start()
	w.drainMu.Lock()
	old := w.handlerPtr.Swap(h)
	w.drainMu.Unlock()
	w.lifecycleMu.Unlock()

	if old != nil {
		old.stop()
	}
	return nil
}

func (w *handlerWrapper) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	w.drainMu.RLock()
	defer w.drainMu.RUnlock()
	h := w.handlerPtr.Load()
	if h == nil {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		if err := writer.WriteMsg(resp); err != nil {
			logrus.Errorf("write msg failed: %v", err)
		}
		return
	}
	h.ServeDNS(writer, req)
}

func (w *handlerWrapper) Stop() {
	w.lifecycleMu.Lock()
	if w.stopped {
		w.lifecycleMu.Unlock()
		return
	}
	w.stopped = true
	w.drainMu.Lock()
	old := w.handlerPtr.Swap(nil)
	w.drainMu.Unlock()
	w.lifecycleMu.Unlock()
	if old != nil {
		old.stop()
	}
}

// endregion

func newHandle(conf config.Conf) (*handlerImpl, error) {
	var err error
	h := &handlerImpl{
		disableQTypes: map[uint16]bool{},
	}
	// disable query types
	if conf.DisableIPv6 {
		h.disableQTypes[dns.TypeAAAA] = true
	}
	for _, qTypeStr := range conf.DisableQTypes {
		qTypeStr = strings.ToUpper(qTypeStr)
		if _, exists := dns.StringToType[qTypeStr]; !exists {
			return nil, fmt.Errorf("unknown query type: %q", qTypeStr)
		}
		h.disableQTypes[dns.StringToType[qTypeStr]] = true
	}

	// hosts & cache
	h.hosts, err = hosts.NewDNSHosts(conf)
	if err != nil {
		return nil, fmt.Errorf("build hosts failed: %w", err)
	}
	h.cache, err = cache.NewDNSCache(conf)
	if err != nil {
		return nil, fmt.Errorf("build cache failed: %w", err)
	}
	h.groups, err = outbound.BuildGroups(conf)
	if err != nil {
		return nil, fmt.Errorf("build groups failed: %w", err)
	}
	for _, group := range h.groups {
		if group.IsFallback() {
			h.fallbackGroup = group
		}
		h.groupList = append(h.groupList, group)
	}
	sort.Slice(h.groupList, func(i, j int) bool {
		g1, g2 := h.groupList[i], h.groupList[j]
		if g1.IsFallback() != g2.IsFallback() {
			return !g1.IsFallback()
		}
		if g1.HasGFWList() != g2.HasGFWList() {
			return !g1.HasGFWList()
		}
		return g1.Name() < g2.Name()
	})
	if h.fallbackGroup == nil {
		return nil, errors.New("fallback group not found")
	}
	h.redirector, err = redirector.NewRedirector(conf, h.groups)
	if err != nil {
		return nil, fmt.Errorf("build redirector failed: %w", err)
	}
	h.queryTimeout = time.Duration(conf.QueryTimeout) * time.Second
	if h.queryTimeout <= 0 {
		h.queryTimeout = 5 * time.Second
	}
	return h, nil
}

// region impl
type handlerImpl struct {
	disableQTypes map[uint16]bool
	cache         cache.IDNSCache
	hosts         hosts.IDNSHosts
	groups        map[string]outbound.IGroup
	groupList     []outbound.IGroup
	fallbackGroup outbound.IGroup
	redirector    redirector.Redirector
	queryTimeout  time.Duration
}

func (h *handlerImpl) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), h.queryTimeout)
	defer cancel()
	resp := h.handle(ctx, writer, req)
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		}
	if err := writer.WriteMsg(resp); err != nil {
		logrus.Errorf("write msg failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		logrus.Errorf("close writer failed: %v", err)
	}
}

func (h *handlerImpl) handle(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (resp *dns.Msg) {
	// region log
	_info := struct {
		blocked  bool
		hitHosts bool
		hitCache bool
		matched  outbound.IGroup
		fallback bool
		redirect outbound.IGroup
		caller   string // Add caller field for logging
	}{}
	begin := time.Now()
	defer func() {
		fields := logrus.Fields{
			"cost":   strconv.FormatInt(time.Since(begin).Milliseconds(), 10) + "ms",
			"remote": writer.RemoteAddr().String(),
		}
		if _info.blocked {
			fields["blocked"] = true
		}
		if _info.hitHosts {
			fields["hit"] = "hosts"
		} else if _info.hitCache {
			fields["hit"] = "cache"
		}
		if len(req.Question) > 0 {
			fields["question"] = req.Question[0].Name
			fields["q_type"] = dns.TypeToString[req.Question[0].Qtype]
		}
		if _info.matched != nil {
			groupName := _info.matched.Name()
			if _info.fallback {
				groupName = "_" + groupName
			}
			fields["group"] = groupName
		}
		if _info.redirect != nil {
			fields["redir"] = _info.redirect.Name()
		}
		if _info.caller != "" {
			fields["caller"] = _info.caller
		}
		if resp == nil {
			fields["answer"] = 0
		} else {
			fields["answer"] = len(resp.Answer)
			var resolvedIPs []string
			var answers []map[string]interface{}
			for _, rr := range resp.Answer {
				ans := map[string]interface{}{
					"name": rr.Header().Name,
					"type": dns.TypeToString[rr.Header().Rrtype],
					"ttl":  rr.Header().Ttl,
				}
				var val string
				switch v := rr.(type) {
				case *dns.A:
					val = v.A.String()
					resolvedIPs = append(resolvedIPs, val)
				case *dns.AAAA:
					val = v.AAAA.String()
					resolvedIPs = append(resolvedIPs, val)
				case *dns.CNAME:
					val = v.Target
				case *dns.PTR:
					val = v.Ptr
				case *dns.TXT:
					val = strings.Join(v.Txt, " ")
				}
				ans["data"] = val
				ans["value"] = val // Match legacy test expectations
				answers = append(answers, ans)
			}
			// 仅在 Debug 模式下记录详细的 answers 数组和解析后的 IPs，防止 Info 日志过载
			if logrus.GetLevel() >= logrus.DebugLevel {
				if len(resolvedIPs) > 0 {
					fields["resolved_ips"] = strings.Join(resolvedIPs, ", ")
				}
				fields["answers"] = answers
			}
		}
		// 统一使用 Info 记录每次请求的分流决策，提升可观察性
		logrus.WithFields(fields).Info()
	}()
	// endregion
	if len(req.Question) == 0 {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeFormatError)
		return resp
	}
	for _, question := range req.Question {
		if h.disableQTypes[question.Qtype] {
			_info.blocked = true
			resp = new(dns.Msg)
			resp.SetRcode(req, dns.RcodeRefused)
			return resp
		}
	}
	if resp = h.hosts.Get(req); resp != nil {
		_info.hitHosts = true
		return resp
	}
	if resp = h.cache.Get(req); resp != nil {
		_info.hitCache = true
		return resp
	}

	// save original question before any group.Handle (may hijack-rewrite req)
	savedQuestion := make([]dns.Question, len(req.Question))
	copy(savedQuestion, req.Question)

	// handle by matched group
	var matched outbound.IGroup
	var result *outbound.HandleResult
	for _, group := range h.groupList {
		if group.Match(req) {
			matched = group
			result = group.Handle(ctx, req)
			break
		}
	}
	if matched == nil {
		matched = h.fallbackGroup
		result = h.fallbackGroup.Handle(ctx, req)
		_info.fallback = true
	}
	_info.matched = matched
	if result != nil {
		resp = result.Msg
		_info.caller = result.CallerName
	}

	// redirect
	if h.redirector != nil {
		if group := h.redirector(matched, req, resp); group != nil {
			matched = group
			result = group.Handle(ctx, req)
			_info.redirect = group
			if result != nil {
				resp = result.Msg
				_info.caller = result.CallerName
			}
		}
	}

	// restore original question for correct cache key (hijack may have mutated req)
	req.Question = savedQuestion

	// finally
	if matched != nil {
		matched.PostProcess(req, resp)
	}
	h.cache.Set(req, resp)
	return resp
}

func (h *handlerImpl) start() {
	for _, group := range h.groups {
		group.Start(h)
	}
	h.cache.Start()
	logrus.Debugf("start handler success")
}

func (h *handlerImpl) stop() {
	logrus.Debugf("stop handler")
	for _, group := range h.groups {
		group.Stop()
	}
	h.cache.Stop()
	logrus.Debugf("stop handler success")
}

// endregion
