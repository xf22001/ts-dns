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
		BufferItems: 256,
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
	cachedAt  int64
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
	now := time.Now().Unix()
	// ttl countdown
	ttl := item.expiredAt - now
	if ttl <= 0 {
		c.cache.Del(key)
		return nil
	}
	r := item.resp.Copy()
	r.SetReply(req)
	elapsed := now - item.cachedAt
	if elapsed < 0 {
		elapsed = 0
	}
	for i := 0; i < len(r.Answer); i++ {
		answerTTL := int64(r.Answer[i].Header().Ttl) - elapsed
		if answerTTL <= 0 {
			c.cache.Del(key)
			return nil
		}
		r.Answer[i].Header().Ttl = uint32(answerTTL)
	}
	// shuffle A/AAAA records among themselves for basic load balancing
	ipIdx := make([]int, 0, len(r.Answer))
	for i, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			ipIdx = append(ipIdx, i)
		}
	}
	// in-place Fisher-Yates shuffle, only swapping A/AAAA-typed records
	for i := len(ipIdx) - 1; i > 0; i-- {
		j := int(fastrand.Uint32n(uint32(i + 1)))
		r.Answer[ipIdx[i]], r.Answer[ipIdx[j]] = r.Answer[ipIdx[j]], r.Answer[ipIdx[i]]
	}
	return r
}

func (c *dnsCache) Set(req *dns.Msg, resp *dns.Msg) {
	if c.maxSize <= 0 || c.cache == nil || resp == nil || len(resp.Answer) == 0 {
		return
	}
	// copy resp to avoid data race
	resp = resp.Copy()
	// Clamp each RR TTL independently while using the shortest one as cache TTL.
	var expire = c.maxTTL
	for _, answer := range resp.Answer {
		ttl := time.Duration(answer.Header().Ttl) * time.Second
		if ttl < c.minTTL {
			ttl = c.minTTL
		}
		if ttl > c.maxTTL {
			ttl = c.maxTTL
		}
		answer.Header().Ttl = uint32(ttl.Seconds())
		if ttl < expire {
			expire = ttl
		}
	}
	// set cache
	key := c.cacheKey(req)
	now := time.Now()
	expiredAt := now.Add(expire).Unix()
	// Ristretto automatically handles TTL with Cost and expiration
	// We use 1 as cost for each DNS entry
	c.cache.SetWithTTL(key, cacheItem{resp: resp, cachedAt: now.Unix(), expiredAt: expiredAt}, 1, expire)
	c.cache.Wait()
}

func (c *dnsCache) Start(_cleanTick ...time.Duration) {
	// Ristretto handles background cleanup automatically
}

func (c *dnsCache) Stop() {
	if c.cache != nil {
		c.cache.Close()
	}
}
