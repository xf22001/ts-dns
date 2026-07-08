package outbound

import (
	"context"
	"fmt"
	"sync/atomic"
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

func TestReplaceDomainSuffix(t *testing.T) {
	cases := []struct {
		name   string
		source string
		dest   string
		want   string
	}{
		{"google.com.", "google.com", "google.cn", "google.cn."},
		{"google.com", "google.com", "google.cn", "google.cn"},
		{"www.google.com.", "google.com", "google.cn", "www.google.cn."},
		{"a.b.google.com.", "google.com", "google.cn", "a.b.google.cn."},
		{"www.Google.com.", "google.com", "google.cn", "www.google.cn."},
		{"notgoogle.com.", "google.com", "google.cn", "notgoogle.com."},
		{"google.com.evil.", "google.com", "google.cn", "google.com.evil."},
		{"mygoogle.com.test.", "google.com", "google.cn", "mygoogle.com.test."},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, replaceDomainSuffix(c.name, c.source, c.dest))
	}
}

func TestParseDurationDayOverflow(t *testing.T) {
	d, err := parseDuration("2d")
	assert.Nil(t, err)
	assert.Equal(t, 48*time.Hour, d)

	_, err = parseDuration("110000d")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "overflows")
}

func TestGroupFastestRespHonorsContext(t *testing.T) {
	group := &groupImpl{
		name:       "test",
		allCallers: []*indexedCaller{{Caller: blockingCaller{}}},
		fastestIP:  true,
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
		allCallers: []*indexedCaller{{Caller: instantV4Caller{}}},
		fastestIP:  true,
	}
	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	resp := group.Handle(ctx, req)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Msg.Answer)
}

func TestGroupFastestRespUsesFirstValidCaller(t *testing.T) {
	fast := &trackCaller{name: "fast", answer: quickV3Answer("z.cn.")}
	slow := &trackCaller{name: "slow", delay: time.Second, answer: quickV3Answer("z.cn.")}
	group := newGroup(fast, slow)
	group.fastestIP = true
	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	resp := group.Handle(ctx, req)

	assert.NotNil(t, resp)
	assert.Less(t, time.Since(start), 500*time.Millisecond)
	assert.Equal(t, int32(1), fast.count())
	assert.True(t, slow.count() >= 1, "slow caller should be started for reselect")
	assert.Equal(t, 0, group.hostStatsSnapshot(queryHost(req)).activeIndex)
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

func quickV3Answer(name string) *dns.Msg {
	rr, _ := dns.NewRR(name + " 60 IN A 1.1.1.1")
	return &dns.Msg{Answer: []dns.RR{rr}}
}

type trackCaller struct {
	name   string
	delay  time.Duration
	fail   bool
	called int32
	answer *dns.Msg
}

func (c *trackCaller) Call(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
	atomic.AddInt32(&c.called, 1)
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.fail {
		return nil, fmt.Errorf("call failed")
	}
	return c.answer, nil
}

func (c *trackCaller) Start(dns.Handler) {}
func (c *trackCaller) Exit()             {}
func (c *trackCaller) String() string    { return "track:" + c.name }
func (c *trackCaller) count() int32      { return atomic.LoadInt32(&c.called) }

func newGroup(callers ...*trackCaller) *groupImpl {
	ws := make([]*indexedCaller, 0, len(callers))
	for _, c := range callers {
		ws = append(ws, &indexedCaller{Caller: c, index: len(ws)})
	}
	return &groupImpl{
		name:       "test",
		allCallers: ws,
	}
}

func TestHostCallerState_InitialAllCallers(t *testing.T) {
	fast := &trackCaller{name: "fast", answer: quickV3Answer("z.cn.")}
	slow := &trackCaller{name: "slow", delay: time.Second}
	group := newGroup(fast, slow)

	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	host := queryHost(req)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp := group.Handle(ctx, req)

	assert.NotNil(t, resp)
	assert.Equal(t, int32(1), fast.count(), "fast should be called")
	assert.True(t, slow.count() >= 1, "slow should be started")
	stats := group.hostStatsSnapshot(host)
	assert.Equal(t, callerActive, stats.state)
	assert.Equal(t, 0, stats.activeIndex)

	callers := group.candidatesForHost(host)
	assert.Equal(t, 1, len(callers))
	assert.Equal(t, "track:fast", callers[0].String())
}

func TestHostCallerState_OnlyActiveCalled(t *testing.T) {
	fast := &trackCaller{name: "fast", answer: quickV3Answer("z.cn.")}
	slow := &trackCaller{name: "slow", delay: time.Second}
	group := newGroup(fast, slow)

	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	group.Handle(ctx, req)
	assert.True(t, slow.count() >= 1, "slow should be called in round 1")
	slowCalled := slow.count()

	// round 2: fast is active, slow is idle and should rest
	group.Handle(ctx, req)
	assert.Equal(t, int32(2), fast.count(), "fast should be called again")
	assert.Equal(t, slowCalled, slow.count(), "slow should not be called while fast remains active")
}

func TestHostCallerState_AllIdleUsesAll(t *testing.T) {
	a := &trackCaller{name: "a", answer: quickV3Answer("z.cn.")}
	b := &trackCaller{name: "b", answer: quickV3Answer("z.cn.")}
	group := newGroup(a, b)

	callers := group.candidatesForHost("z.cn.")
	assert.Equal(t, 2, len(callers), "unknown hosts should start with all callers")
}

func TestHostCallerState_FailedActiveReselectsAll(t *testing.T) {
	active := &trackCaller{name: "active", fail: true}
	next := &trackCaller{name: "next", answer: quickV3Answer("z.cn.")}
	group := newGroup(active, next)

	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	host := queryHost(req)
	group.recordCallerSuccess(host, group.allCallers[0])
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp := group.Handle(ctx, req)
	assert.Nil(t, resp)
	assert.Equal(t, callerIdle, group.hostStatsSnapshot(host).state)
	assert.Equal(t, int32(1), active.count(), "active caller should be tried")
	assert.Equal(t, int32(0), next.count(), "inactive caller should wait until active fails")
	assert.Equal(t, 2, len(group.candidatesForHost(host)), "all callers should join reselect after active failure")

	resp = group.Handle(ctx, req)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(1), next.count(), "all callers should join reselect after active failure")
	stats := group.hostStatsSnapshot(host)
	assert.Equal(t, callerActive, stats.state)
	assert.Equal(t, 1, stats.activeIndex)
}

func TestHostCallerState_ActiveStateVisibleDuringInFlightQuery(t *testing.T) {
	active := &trackCaller{name: "active", delay: 100 * time.Millisecond, answer: quickV3Answer("z.cn.")}
	idle := &trackCaller{name: "idle", answer: quickV3Answer("z.cn.")}
	group := newGroup(active, idle)

	req := &dns.Msg{Question: []dns.Question{{Name: "z.cn.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	host := queryHost(req)
	group.recordCallerSuccess(host, group.allCallers[0])
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan *HandleResult, 1)
	go func() {
		done <- group.Handle(ctx, req)
	}()

	deadline := time.Now().Add(time.Second)
	for active.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, int32(1), active.count())
	callers := group.candidatesForHost(host)
	assert.Equal(t, 1, len(callers))
	assert.Equal(t, "track:active", callers[0].String())

	assert.NotNil(t, <-done)
	assert.Equal(t, int32(0), idle.count(), "idle caller should not be started by the in-flight query")
}

func TestHostCallerState_IsScopedByHost(t *testing.T) {
	fast := &trackCaller{name: "fast", answer: quickV3Answer("a.test.")}
	slow := &trackCaller{name: "slow", answer: quickV3Answer("a.test.")}
	group := newGroup(fast, slow)

	hostA := "a.test."
	hostB := "b.test."
	group.recordCallerSuccess(hostA, group.allCallers[0])

	callers := group.candidatesForHost(hostA)
	assert.Equal(t, 1, len(callers))
	assert.Equal(t, "track:fast", callers[0].String())

	callers = group.candidatesForHost(hostB)
	assert.Equal(t, 2, len(callers), "a new host should start with all callers")
}

func TestHostCallerState_ReselectsAllAfterInterval(t *testing.T) {
	fast := &trackCaller{name: "fast", answer: quickV3Answer("z.cn.")}
	slow := &trackCaller{name: "slow", answer: quickV3Answer("z.cn.")}
	group := newGroup(fast, slow)
	host := "z.cn."

	group.recordCallerSuccess(host, group.allCallers[0])

	callers := group.candidatesForHost(host)
	assert.Equal(t, 1, len(callers), "active caller should be used until reselect interval")

	group.stateMu.Lock()
	group.hostStats[host].reselectAfter = time.Now().Add(-time.Second)
	group.stateMu.Unlock()

	callers = group.candidatesForHost(host)
	assert.Equal(t, 2, len(callers))
	assert.Equal(t, "track:fast", callers[0].String())
	assert.Equal(t, "track:slow", callers[1].String())
}

func TestHostCallerState_SuccessDoesNotExtendSameActiveWindow(t *testing.T) {
	fast := &trackCaller{name: "fast", answer: quickV3Answer("z.cn.")}
	group := newGroup(fast)
	host := "z.cn."

	group.recordCallerSuccess(host, group.allCallers[0])
	firstReselectAfter := group.hostStatsSnapshot(host).reselectAfter
	time.Sleep(time.Millisecond)

	group.recordCallerSuccess(host, group.allCallers[0])

	assert.Equal(t, firstReselectAfter, group.hostStatsSnapshot(host).reselectAfter)
}

func TestHostCallerState_OnlySelectedResponseBecomesActive(t *testing.T) {
	fast := &trackCaller{name: "fast", answer: quickV3Answer("z.cn.")}
	slow := &trackCaller{name: "slow", answer: quickV3Answer("z.cn.")}
	group := newGroup(fast, slow)
	host := "z.cn."
	respCh := make(chan *callerResult, 2)
	respCh <- &callerResult{Msg: fast.answer, Caller: group.allCallers[0], CallerName: group.allCallers[0].String()}
	respCh <- &callerResult{Msg: slow.answer, Caller: group.allCallers[1], CallerName: group.allCallers[1].String()}

	resp := group.firstResponse(context.Background(), host, respCh, 2)

	assert.NotNil(t, resp)
	stats := group.hostStatsSnapshot(host)
	assert.Equal(t, callerActive, stats.state)
	assert.Equal(t, 0, stats.activeIndex)
}

func TestHostCallerStats_CleanupExpiredHosts(t *testing.T) {
	active := &trackCaller{name: "active", answer: quickV3Answer("z.cn.")}
	group := newGroup(active)
	oldHost := "old.test."
	newHost := "new.test."

	group.recordCallerSuccess(oldHost, group.allCallers[0])
	group.recordCallerSuccess(newHost, group.allCallers[0])
	group.stateMu.Lock()
	group.hostStats[oldHost].lastUsed = time.Now().Add(-callerStatsTTL - time.Second)
	group.stateMu.Unlock()

	_ = group.candidatesForHost(newHost)

	group.stateMu.RLock()
	_, oldExists := group.hostStats[oldHost]
	_, newExists := group.hostStats[newHost]
	group.stateMu.RUnlock()
	assert.False(t, oldExists)
	assert.True(t, newExists)
}
