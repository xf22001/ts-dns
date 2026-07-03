package redirector

import (
	"context"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/outbound"
)

type mockGroup struct {
	MockMatch       func(msg *dns.Msg) bool
	MockIsFallback  func() bool
	MockHandle      func(ctx context.Context, req *dns.Msg) *outbound.HandleResult
	MockPostProcess func(req, resp *dns.Msg)
	MockStart       func(resolver dns.Handler)
	MockStop        func()
	MockName        func() string
	MockString      func() string
}

func (m mockGroup) Match(req *dns.Msg) bool { return m.MockMatch(req) }
func (m mockGroup) IsFallback() bool        { return m.MockIsFallback() }
func (m mockGroup) Handle(ctx context.Context, req *dns.Msg) *outbound.HandleResult {
	return m.MockHandle(ctx, req)
}
func (m mockGroup) PostProcess(req *dns.Msg, resp *dns.Msg) { m.MockPostProcess(req, resp) }
func (m mockGroup) Start(resolver dns.Handler)              { m.MockStart(resolver) }
func (m mockGroup) Stop()                                   { m.MockStop() }
func (m mockGroup) Name() string                            { return m.MockName() }
func (m mockGroup) String() string                          { return m.MockString() }
func (m mockGroup) HasGFWList() bool                        { return false }
