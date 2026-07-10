package inbound

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/outbound"
	"github.com/wolf-joe/ts-dns/utils"
)

func buildReq(name string, qType uint16) *dns.Msg {
	if name != "" && name[len(name)-1] != '.' {
		name += "."
	}
	return &dns.Msg{Question: []dns.Question{{
		Name: name, Qtype: qType,
	}}}
}

func Test_handlerImpl_ServeDNS(t *testing.T) {
}

func TestNewHandler(t *testing.T) {
	h, err := NewHandler(config.Conf{
		HostsFiles:    nil,
		Hosts:         nil,
		Cache:         config.CacheConf{},
		Groups:        map[string]config.Group{"default": {}},
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	})
	assert.Nil(t, err)
	assert.NotNil(t, h)

	err = h.ReloadConfig(config.Conf{
		HostsFiles:    nil,
		Hosts:         nil,
		Cache:         config.CacheConf{},
		Groups:        map[string]config.Group{"default": {}},
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	})
	assert.Nil(t, err)
	rw := utils.NewFakeRespWriter()
	h.ServeDNS(rw, buildReq("ip.cn", dns.TypeA))
	assert.NotNil(t, rw.Msg)
	h.Stop()
	h.Stop()

	_, err = NewHandler(config.Conf{
		HostsFiles:    []string{"not_exists.txt"},
		Hosts:         nil,
		Cache:         config.CacheConf{},
		Groups:        nil,
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	})
	assert.NotNil(t, err)
	t.Log(err)
}

func Test_newHandle(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	defaultConf := config.Conf{
		HostsFiles: nil,
		Hosts: map[string]string{
			"z.cn.": "1.1.1.1", "v6.cn.": "2001:db8:85a3::8a2e:370:7334",
		},
		Cache:         config.CacheConf{},
		Groups:        map[string]config.Group{"fallback": {}},
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	}
	t.Run("hosts", func(t *testing.T) {
		conf := defaultConf
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("z.cn.", dns.TypeA))
		assert.NotNil(t, rw.Msg)
		assert.NotEmpty(t, rw.Msg.Answer)

		rw = utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("v6.cn.", dns.TypeAAAA))
		assert.NotNil(t, rw.Msg)
		assert.NotEmpty(t, rw.Msg.Answer)
	})
	t.Run("disable", func(t *testing.T) {
		conf := defaultConf
		conf.DisableQTypes = []string{"???"}
		_, err := newHandle(conf)
		assert.NotNil(t, err)
		t.Log(err)

		conf.DisableQTypes = []string{"A"}
		conf.DisableIPv6 = true
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)
		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("z.cn.", dns.TypeA))
		assert.NotNil(t, rw.Msg)
		assert.Nil(t, rw.Msg.Answer)
		assert.Equal(t, dns.RcodeRefused, rw.Msg.Rcode)

		rw = utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("v6.cn.", dns.TypeAAAA))
		assert.NotNil(t, rw.Msg)
		assert.Nil(t, rw.Msg.Answer)
		assert.Equal(t, dns.RcodeRefused, rw.Msg.Rcode)
	})

	t.Run("all upstreams fail -> SERVFAIL", func(t *testing.T) {
		// 没有配置任何上游（dns/dot/doh 都为空）的兜底组，
		// Handle 会因 candidate 为空直接返回 nil，
		// ServeDNS 应当返回 SERVFAIL 以区分“查询失败”和“真实空结果”。
		conf := defaultConf
		conf.Cache.Size = 0
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("any.nonexistent.invalid.", dns.TypeA))
		assert.NotNil(t, rw.Msg)
		assert.Equal(t, dns.RcodeServerFailure, rw.Msg.Rcode)
		assert.Nil(t, rw.Msg.Answer)
	})
	t.Run("cache", func(t *testing.T) {
		conf := defaultConf
		conf.Cache.Size = 100
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		req := buildReq("a.cn.", dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr1, _ := dns.NewRR("a.cn. 60 IN A 1.1.1.1")
		rr2, _ := dns.NewRR("a.cn. 60 IN AAAA ::1")
		resp.Answer = []dns.RR{rr1, rr2}

		h.cache.Set(req, resp)
		// Ristretto is asynchronous
		time.Sleep(time.Millisecond * 200)

		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, req)
		assert.NotNil(t, rw.Msg)
		assert.Equal(t, 2, len(rw.Msg.Answer))
	})
	t.Run("empty question", func(t *testing.T) {
		conf := defaultConf
		conf.Cache.Size = 100
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, new(dns.Msg))
		assert.NotNil(t, rw.Msg)
		assert.Equal(t, dns.RcodeFormatError, rw.Msg.Rcode)
	})
	t.Run("group", func(t *testing.T) {
		conf := defaultConf
		conf.Groups["a"] = config.Group{
			Rules: []string{"a.cn."},
		}
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		var srcGroup outbound.IGroup
		h.redirector = func(src outbound.IGroup, req, resp *dns.Msg) outbound.IGroup {
			srcGroup = src
			return src
		}

		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("a.cn.", dns.TypeA))
		assert.NotNil(t, srcGroup)
		assert.Equal(t, "a", srcGroup.Name())
	})
}
