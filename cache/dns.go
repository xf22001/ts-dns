package cache

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
	"github.com/valyala/fastrand"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/utils"
)

const (
	DefaultMinTTL = time.Minute    // DefaultMinTTL 默认dns缓存最小有效期
	DefaultMaxTTL = 24 * time.Hour // DefaultMaxTTL 默认dns缓存最大有效期
)

// IDNSCache cache dns response for dns request
type IDNSCache interface {
	// Get find cached response
	Get(req *dns.Msg) *dns.Msg
	// Set save response to cache
	Set(req *dns.Msg, resp *dns.Msg)
	// Start life cycle begin
	Start(cleanTick ...time.Duration)
	// Stop life cycle end
	Stop()
}

func NewDNSCache(conf config.Conf) (IDNSCache, error) {
	minTTL, maxTTL := DefaultMinTTL, DefaultMaxTTL
	if conf.Cache.MinTTL > 0 {
		minTTL = time.Second * time.Duration(conf.Cache.MinTTL)
	}
	if conf.Cache.MaxTTL > 0 {
		maxTTL = time.Second * time.Duration(conf.Cache.MaxTTL)
	}
	if minTTL > maxTTL {
		return nil, fmt.Errorf("min ttl(%d) larger than max ttl(%d)", conf.Cache.MinTTL, conf.Cache.MaxTTL)
	}

	if conf.Cache.Size <= 0 {
		return &dnsCache{maxSize: 0}, nil
	}

	// Ristretto configuration
	// NumCounters: 10 * maxSize (recommended for frequency tracking)
	// MaxCost: maxSize (number of items)
	// BufferItems: 64 (recommended)
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: int64(conf.Cache.Size) * 10,
		MaxCost:     int64(conf.Cache.Size),
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}

	c := &dnsCache{
		cache:   cache,
		maxSize: conf.Cache.Size,
		minTTL:  minTTL,
		maxTTL:  maxTTL,
	}
	return c, nil
}

var (
	_ IDNSCache = &dnsCache{}
)

type cacheItem struct {
	resp      *dns.Msg
	expiredAt int64
}

type dnsCache struct {
	cache   *ristretto.Cache
	maxSize int
	minTTL  time.Duration
	maxTTL  time.Duration
}

func (c *dnsCache) cacheKey(req *dns.Msg) string {
	question := req.Question[0]
	key := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := utils.FormatECS(req); subnet != "" {
		key += "." + subnet
	}
	return strings.ToLower(key)
}

func (c *dnsCache) Get(req *dns.Msg) *dns.Msg {
	if c.maxSize <= 0 || c.cache == nil {
		return nil
	}
	// check cache
	key := c.cacheKey(req)
	val, exists := c.cache.Get(key)
	if !exists {
		return nil
	}
	item := val.(cacheItem)
	// ttl countdown
	ttl := item.expiredAt - time.Now().Unix()
	if ttl <= 0 {
		c.cache.Del(key)
		return nil
	}
	r := item.resp.Copy()
	r.SetReply(req)
	for i := 0; i < len(r.Answer); i++ {
		r.Answer[i].Header().Ttl = uint32(ttl)
	}
	// shuffle ip
	first := uint32(len(r.Answer))
	for ; first > 0; first-- {
		if t := r.Answer[first-1].Header().Rrtype; t != dns.TypeA && t != dns.TypeAAAA {
			break
		}
	}
	if ips := r.Answer[first:]; len(ips) > 1 {
		for i := uint32(len(ips) - 1); i > 0; i-- {
			j := fastrand.Uint32n(i + 1)
			ips[i], ips[j] = ips[j], ips[i]
		}
	}
	return r
}

func (c *dnsCache) Set(req *dns.Msg, resp *dns.Msg) {
	if c.maxSize <= 0 || c.cache == nil || resp == nil || len(resp.Answer) == 0 {
		return
	}
	// copy resp to avoid data race
	resp = resp.Copy()
	// reset ttl
	var expire = c.maxTTL
	for _, answer := range resp.Answer {
		if ttl := time.Duration(answer.Header().Ttl) * time.Second; ttl < expire {
			expire = ttl
		}
	}
	if expire < c.minTTL {
		expire = c.minTTL
	}
	for i := 0; i < len(resp.Answer); i++ {
		resp.Answer[i].Header().Ttl = uint32(expire.Seconds())
	}
	// set cache
	key := c.cacheKey(req)
	expiredAt := time.Now().Add(expire).Unix()
	// Ristretto automatically handles TTL with Cost and expiration
	// We use 1 as cost for each DNS entry
	c.cache.SetWithTTL(key, cacheItem{resp: resp, expiredAt: expiredAt}, 1, expire)
}

func (c *dnsCache) Start(_cleanTick ...time.Duration) {
	// Ristretto handles background cleanup automatically
}

func (c *dnsCache) Stop() {
	if c.cache != nil {
		c.cache.Close()
	}
}
