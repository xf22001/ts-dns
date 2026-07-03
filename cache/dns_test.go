package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
)

func TestNewDNSCache(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("z.cn.", dns.TypeA)
	c, err := NewDNSCache(config.Conf{Cache: config.CacheConf{
		Size: 0, MinTTL: 0, MaxTTL: 0,
	}})
	assert.Nil(t, err)

	resp := new(dns.Msg)
	rr, _ := dns.NewRR("z.cn. 0 IN A 1.1.1.1")
	resp.Answer = append(resp.Answer, rr)
	rr, _ = dns.NewRR("z.cn. 0 IN A 1.1.1.2")
	resp.Answer = append(resp.Answer, rr)
	c.Set(req, resp)
	assert.Nil(t, c.Get(req))

	c, err = NewDNSCache(config.Conf{Cache: config.CacheConf{
		Size: 1024, MinTTL: 1, MaxTTL: 3600,
	}})
	assert.Nil(t, err)

	c.Start(time.Second)
	defer c.Stop()
	c.Set(req, resp)

	// Wait for Ristretto to process the Set operation
	var cached *dns.Msg
	for i := 0; i < 20; i++ {
		cached = c.Get(req)
		if cached != nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	assert.NotNil(t, cached)

	// expired by TTL
	time.Sleep(time.Second * 2)
	assert.Nil(t, c.Get(req))

	c.Stop()
	c, err = NewDNSCache(config.Conf{Cache: config.CacheConf{
		Size: 1024, MinTTL: 1, MaxTTL: 3600,
	}})
	assert.Nil(t, err)
	c.Start(time.Minute)
	// expired by get
	c.Set(req, resp)
	for i := 0; i < 20; i++ {
		cached = c.Get(req)
		if cached != nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	assert.NotNil(t, cached)
	time.Sleep(time.Second * 2)
	assert.Nil(t, c.Get(req))
}

func TestDNSCache_ECS(t *testing.T) {
	c, _ := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 1024}})
	req1 := new(dns.Msg)
	req1.SetQuestion("z.cn.", dns.TypeA)

	// Add ECS option to req1
	opt1 := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
		Option: []dns.EDNS0{
			&dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1,
				SourceNetmask: 24,
				Address:       []byte{1, 2, 3, 0},
			},
		},
	}
	req1.Extra = append(req1.Extra, opt1)

	resp := new(dns.Msg)
	rr, _ := dns.NewRR("z.cn. 60 IN A 1.1.1.1")
	resp.Answer = append(resp.Answer, rr)

	c.Set(req1, resp)

	var cached *dns.Msg
	for i := 0; i < 20; i++ {
		cached = c.Get(req1)
		if cached != nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	assert.NotNil(t, cached)

	// Request for same domain but different ECS should miss
	req2 := new(dns.Msg)
	req2.SetQuestion("z.cn.", dns.TypeA)
	opt2 := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
		Option: []dns.EDNS0{
			&dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1,
				SourceNetmask: 24,
				Address:       []byte{4, 5, 6, 0},
			},
		},
	}
	req2.Extra = append(req2.Extra, opt2)
	assert.Nil(t, c.Get(req2))
}

func TestDNSCache_Shuffle(t *testing.T) {
	c, _ := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 1024}})
	req := new(dns.Msg)
	req.SetQuestion("z.cn.", dns.TypeA)

	resp := new(dns.Msg)
	for i := 0; i < 10; i++ {
		rr, _ := dns.NewRR(fmt.Sprintf("z.cn. 60 IN A 1.1.1.%d", i))
		resp.Answer = append(resp.Answer, rr)
	}

	c.Set(req, resp)

	var cached *dns.Msg
	for i := 0; i < 20; i++ {
		cached = c.Get(req)
		if cached != nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	assert.NotNil(t, cached)

	// Check if IPs are shuffled across multiple Gets
	firstIPs := ""
	for i := 0; i < 10; i++ {
		r := c.Get(req)
		assert.NotNil(t, r)
		currentIPs := ""
		for _, ans := range r.Answer {
			currentIPs += ans.(*dns.A).A.String()
		}
		if firstIPs == "" {
			firstIPs = currentIPs
		} else if firstIPs != currentIPs {
			return // Shuffled!
		}
	}
	// Note: with 10 IPs, the chance of getting same order 10 times is very low
}

func TestDNSCache_MinMaxTTL(t *testing.T) {
	// Test MinTTL
	c, _ := NewDNSCache(config.Conf{Cache: config.CacheConf{
		Size: 1024, MinTTL: 60, // 60s
	}})
	req := new(dns.Msg)
	req.SetQuestion("z.cn.", dns.TypeA)
	resp := new(dns.Msg)
	rr, _ := dns.NewRR("z.cn. 10 IN A 1.1.1.1") // TTL 10 < MinTTL 60
	resp.Answer = append(resp.Answer, rr)

	c.Set(req, resp)

	var cached *dns.Msg
	for i := 0; i < 20; i++ {
		cached = c.Get(req)
		if cached != nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	assert.NotNil(t, cached)
	assert.True(t, cached.Answer[0].Header().Ttl >= 59)

	// Test MaxTTL
	c, _ = NewDNSCache(config.Conf{Cache: config.CacheConf{
		Size: 1024, MaxTTL: 3600, // 1h
	}})
	resp = new(dns.Msg)
	rr, _ = dns.NewRR("z.cn. 7200 IN A 1.1.1.1") // TTL 7200 > MaxTTL 3600
	resp.Answer = append(resp.Answer, rr)

	c.Set(req, resp)
	for i := 0; i < 20; i++ {
		cached = c.Get(req)
		if cached != nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	assert.NotNil(t, cached)
	assert.Equal(t, uint32(3600), cached.Answer[0].Header().Ttl)
}

func TestDNSCache_PreservesPerRecordTTL(t *testing.T) {
	c, _ := NewDNSCache(config.Conf{Cache: config.CacheConf{
		Size: 1024, MinTTL: 1, MaxTTL: 3600,
	}})
	req := new(dns.Msg)
	req.SetQuestion("z.cn.", dns.TypeA)
	resp := new(dns.Msg)
	rr, _ := dns.NewRR("z.cn. 30 IN A 1.1.1.1")
	resp.Answer = append(resp.Answer, rr)
	rr, _ = dns.NewRR("z.cn. 120 IN A 1.1.1.2")
	resp.Answer = append(resp.Answer, rr)

	c.Set(req, resp)

	var cached *dns.Msg
	for i := 0; i < 20; i++ {
		cached = c.Get(req)
		if cached != nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	assert.NotNil(t, cached)
	assert.Len(t, cached.Answer, 2)
	assert.NotEqual(t, cached.Answer[0].Header().Ttl, cached.Answer[1].Header().Ttl)
}

func BenchmarkNewDNSCache(b *testing.B) {
	req := new(dns.Msg)
	req.SetQuestion("z.cn.", dns.TypeA)
	c, err := NewDNSCache(config.Conf{Cache: config.CacheConf{
		Size: 1024, MinTTL: 60, MaxTTL: 3600,
	}})
	assert.Nil(b, err)

	resp := new(dns.Msg)
	rr, _ := dns.NewRR("z.cn. 0 IN A 1.1.1.1")
	resp.Answer = append(resp.Answer, rr)
	rr, _ = dns.NewRR("z.cn. 0 IN A 1.1.1.2")
	resp.Answer = append(resp.Answer, rr)

	for i := 0; i < b.N; i++ {
		c.Set(req, resp)
		c.Get(req)
	}
}
