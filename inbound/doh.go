package inbound

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/utils"
)

// DohHandler is a http.Handler for DNS-over-HTTPS.
type DohHandler struct {
	handler       IHandler
	trustForwarded bool // 是否信任反向代理注入的 X-Forwarded-* 头（明文 HTTP DoH 场景）
}

// NewDohHandler creates a new DohHandler.
// trustForwarded 为 true 时（明文 HTTP DoH 位于受信任的反向代理之后），
// 会从 X-Forwarded-For / X-Forwarded-Proto 还原真实客户端地址与协议。
func NewDohHandler(handler IHandler, trustForwarded bool) *DohHandler {
	return &DohHandler{handler: handler, trustForwarded: trustForwarded}
}

// ServeHTTP implements the http.Handler interface.
func (h *DohHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only handle /dns-query path
	if r.URL.Path != "/dns-query" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var query []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		b64Query := r.URL.Query().Get("dns")
		// Remove padding as RFC 8484 recommends base64url without padding,
		// but some clients might include it.
		b64Query = strings.TrimRight(b64Query, "=")
		query, err = base64.RawURLEncoding.DecodeString(b64Query)
		if err != nil {
			http.Error(w, "invalid dns query", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		query, err = io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(query); err != nil {
		http.Error(w, "failed to unpack dns query", http.StatusBadRequest)
		return
	}

	// Use FakeRespWriter to get the response from the handler.
	// 注入客户端地址与协议：直连时为真实 TCP 对端；位于受信任反代之后时，
	// 从 X-Forwarded-For / X-Forwarded-Proto 还原真实客户端地址与所用协议。
	remoteAddr := r.RemoteAddr
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	if h.trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ip := xffClientIP(xff); ip != "" {
				remoteAddr = replaceHost(remoteAddr, ip)
			}
		}
		if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
			proto = strings.ToLower(strings.TrimSpace(xfp))
		}
	}
	writer := utils.NewFakeRespWriter()
	if ra, err := net.ResolveTCPAddr("tcp", remoteAddr); err == nil {
		writer.SetRemote(ra)
	}
	writer.SetProto(proto)
	h.handler.ServeDNS(writer, req)

	if writer.Msg == nil {
		http.Error(w, "dns query failed", http.StatusInternalServerError)
		return
	}

	resp, err := writer.Msg.Pack()
	if err != nil {
		http.Error(w, "failed to pack dns response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	if minTTL := utils.GetMinTTL(writer.Msg); minTTL > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", minTTL))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// xffClientIP 从 X-Forwarded-For 中取最可信的客户端 IP。
// 受信任的反向代理（如 nginx）通常把请求来源追加到末尾（格式 "client, proxy"），
// 因此最右侧（最后一个）条目才是代理真正看到的直连对端，即真实客户端；
// 左侧条目为客户端可伪造，不可信。各条目可能带端口，需剥离后校验。
func xffClientIP(xff string) string {
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// replaceHost 将 addr(形如 host:port) 的 host 替换为 ip，保留原端口。
// 用于把反向代理的 X-Forwarded-For 还原进日志来源地址。
func replaceHost(addr, ip string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return net.JoinHostPort(ip, port)
	}
	return ip
}
