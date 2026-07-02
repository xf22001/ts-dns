package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
)

func TestBuildGroups(t *testing.T) {
	gfwListFile := "../matcher/testdata/gfwlist.txt"
	t.Run("fallback", func(t *testing.T) {
		_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
		}})
		assert.Nil(t, err)
		t.Log(err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
		}})
		assert.Nil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
			"g2": {},
		}})
		assert.NotNil(t, err)
		t.Log(err)
	})
	t.Run("gfw", func(t *testing.T) {
		_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: "not_exists.txt"},
		}})
		assert.NotNil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: gfwListFile},
		}})
		assert.Nil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: gfwListFile},
			"g2": {GFWListFile: gfwListFile},
		}})
		assert.NotNil(t, err)
		t.Log(err)
	})
}

type blockingCaller struct{}

func (blockingCaller) Call(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingCaller) Start(dns.Handler) {}
func (blockingCaller) Exit()             {}
func (blockingCaller) String() string    { return "blockingCaller" }

func TestDisableIPv6(t *testing.T) {
	groups, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
		"g1": {DisableIPv6: true, DisableQTypes: []string{"AAAA"}},
	}})
	assert.Nil(t, err)
	g := groups["g1"]
	assert.NotNil(t, g)
	resp := g.Handle(context.Background(), &dns.Msg{
		Question: []dns.Question{{
			Name:   "z.cn.",
			Qtype:  dns.TypeAAAA,
			Qclass: 0,
		}},
	})
	assert.Nil(t, resp)
}

func TestPostProcess(t *testing.T) {
	var v4val, v6val string
	group := &groupImpl{
		ipSet: MockIPSet{
			Name:    "",
			Timeout: 0,
			MockAdd: func(val string, _ int) error { v4val = val; return nil },
		},
		ipSet6: MockIPSet{
			Name:    "",
			Timeout: 0,
			MockAdd: func(val string, _ int) error { v6val = val; return nil },
		},
		ipSetCh: make(chan ipSetTask, 1),
	}
	rr, err := dns.NewRR("z.cn 0 IN A 1.1.1.1")
	assert.Nil(t, err)
	group.PostProcess(nil, &dns.Msg{Answer: []dns.RR{rr}})
	task := <-group.ipSetCh
	_ = task.target.Add(task.val, task.timeout)
	assert.Equal(t, "1.1.1.1", v4val)

	rr, err = dns.NewRR("z.cn 0 IN AAAA ff80::1")
	assert.Nil(t, err)
	group.PostProcess(nil, &dns.Msg{Answer: []dns.RR{rr}})
	task = <-group.ipSetCh
	_ = task.target.Add(task.val, task.timeout)
	assert.Equal(t, "ff80::1", v6val)
}

func TestGroupFastestRespHonorsContext(t *testing.T) {
	group := &groupImpl{
		name:      "test",
		callers:   []Caller{blockingCaller{}},
		fastestIP: true,
	}
	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	resp := group.Handle(ctx, req)

	assert.Nil(t, resp)
	assert.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestGroupFastestRespPingSkippedWhenContextExpired(t *testing.T) {
	// caller returns immediately; context has very short timeout
	// so ping phase gets a reduced timeout and likely falls back to firstResp
	group := &groupImpl{
		name:      "test",
		callers:   []Caller{instantV4Caller{}},
		fastestIP: true,
	}
	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	resp := group.Handle(ctx, req)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Msg.Answer)
}

type instantV4Caller struct{}

func (instantV4Caller) Call(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
	rr, _ := dns.NewRR("z.cn. 60 IN A 1.1.1.1")
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{rr}
	return msg, nil
}

func (instantV4Caller) Start(dns.Handler) {}
func (instantV4Caller) Exit()             {}
func (instantV4Caller) String() string    { return "instantV4Caller" }
