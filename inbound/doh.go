package inbound

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/utils"
)

// DohHandler is a http.Handler for DNS-over-HTTPS.
type DohHandler struct {
	handler IHandler
}

// NewDohHandler creates a new DohHandler.
func NewDohHandler(handler IHandler) *DohHandler {
	return &DohHandler{handler: handler}
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
		query, err = io.ReadAll(r.Body)
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

	// Use FakeRespWriter to get the response from the handler
	writer := utils.NewFakeRespWriter()
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
