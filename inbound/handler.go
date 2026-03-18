package inbound

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

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
	handlerPtr unsafe.Pointer // type: *handlerImpl
}

func (w *handlerWrapper) ReloadConfig(conf config.Conf) error {
	// create & start new handler
	h, err := newHandle(conf)
	if err != nil {
		return fmt.Errorf("make new handler failed: %w", err)
	}
	h.start()
	// swap handler
	for {
		old := atomic.LoadPointer(&w.handlerPtr)
		if atomic.CompareAndSwapPointer(&w.handlerPtr, old, unsafe.Pointer(h)) {
			if old != nil {
				(*handlerImpl)(old).stop()
			}
			break
		}
	}
	return nil
}

func (w *handlerWrapper) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	(*handlerImpl)(atomic.LoadPointer(&w.handlerPtr)).ServeDNS(writer, req)
}

func (w *handlerWrapper) Stop() {
	for {
		old := atomic.LoadPointer(&w.handlerPtr)
		if old == nil {
			return
		}
		if atomic.CompareAndSwapPointer(&w.handlerPtr, old, nil) {
			(*handlerImpl)(old).stop()
			return
		}
	}
}

// endregion

func newHandle(conf config.Conf) (*handlerImpl, error) {
	var err error
	h := &handlerImpl{
		disableQTypes: map[uint16]bool{},
		cache:         nil,
		hosts:         nil,
		groups:        nil,
		redirector:    nil,
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
	}
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
	}
	if !resp.Response {
		resp.SetReply(req)
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
			fields["hit_hosts"] = true
		}
		if _info.hitCache {
			fields["hit_cache"] = true
		}
		if len(req.Question) > 0 {
			fields["question"] = req.Question[0].Name
			fields["q_type"] = dns.TypeToString[req.Question[0].Qtype]
		}
		if _info.matched != nil {
			if _info.fallback {
				fields["group"] = "_" + _info.matched.Name()
			} else {
				fields["group"] = _info.matched.Name()
			}
		}
		if _info.redirect != nil {
			fields["redir"] = _info.redirect.Name()
		}
		if _info.caller != "" { // Add caller to log fields if available
			fields["caller"] = _info.caller
		}
		if resp == nil {
			fields["answer"] = "nil"
		} else {
			fields["answer"] = len(resp.Answer)
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				var resolvedIPs []string
				var answers []map[string]interface{}
				for _, rr := range resp.Answer {
					ans := map[string]interface{}{
						"name":   rr.Header().Name,
						"type":   dns.TypeToString[rr.Header().Rrtype],
						"ttl":    rr.Header().Ttl,
					}
					switch v := rr.(type) {
					case *dns.A:
						resolvedIPs = append(resolvedIPs, v.A.String())
						ans["data"] = v.A.String()
					case *dns.AAAA:
						resolvedIPs = append(resolvedIPs, v.AAAA.String())
						ans["data"] = v.AAAA.String()
					}
					answers = append(answers, ans)
				}
				if len(resolvedIPs) > 0 {
					fields["resolved_ips"] = strings.Join(resolvedIPs, ", ")
				}
				fields["answers"] = answers
			}
		}
		if _info.blocked || _info.hitCache || _info.hitHosts {
			logrus.WithFields(fields).Debug()
		} else {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.WithFields(fields).Debug()
			} else {
				logrus.WithFields(fields).Info()
			}
		}
	}()
	// endregion
	for _, question := range req.Question {
		if h.disableQTypes[question.Qtype] {
			_info.blocked = true
			return nil // disabled
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

	// handle by matched group
	var matched outbound.IGroup
	var result *outbound.HandleResult
	for _, group := range h.groups {
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
