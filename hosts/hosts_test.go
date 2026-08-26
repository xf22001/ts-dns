package hosts

import (
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"gopkg.in/yaml.v3"
)

func buildReq(host string, qType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.Question = append(msg.Question, dns.Question{
		Name:   host,
		Qtype:  qType,
		Qclass: 0,
	})
	return msg
}

func TestLinuxHosts(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	cfg := config.Conf{HostsFiles: []string{
		"testdata/linux_style.txt",
	}}
	r, err := NewDNSHosts(cfg)
	assert.Nil(t, err)
	assert.NotNil(t, r)

	cases := []struct {
		host  string
		query uint16
		isNil bool
		resp  string
	}{
		{"x.cn", dns.TypeA, true, ""},
		{"z.cn", dns.TypeA, false, "z.cn.\t0\tIN\tA\t1.1.2.2"},
		{"b.cn", dns.TypeA, false, "b.cn.\t0\tIN\tA\t1.1.3.3"},
		{"b", dns.TypeA, false, "b.\t0\tIN\tA\t1.1.3.3"},
		{"a.b.cn", dns.TypeA, true, ""},
	}
	for _, c := range cases {
		t.Log(c)
		resp := r.Get(buildReq(c.host, c.query))
		assert.Nil(t, err)
		if c.isNil {
			assert.Nil(t, resp)
		} else {
			assert.NotNil(t, resp)
			assert.Equal(t, 1, len(resp.Answer))
			assert.Equal(t, c.resp, resp.Answer[0].String())
		}
	}
}

func TestNewHostReader(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	cfg := config.Conf{Hosts: map[string]config.StringSlice{
		"z.cn": {"1.1.1.1"},
	}, HostsFiles: []string{
		"testdata/test.txt",
	}}
	r, err := NewDNSHosts(cfg)
	assert.Nil(t, err)
	assert.NotNil(t, r)

	resp := r.Get(buildReq("z.cn.", dns.TypeA))
	assert.NotNil(t, resp)
	assert.Equal(t, "z.cn.\t0\tIN\tA\t1.1.1.1", resp.Answer[0].String())

	cases := []struct {
		host  string
		query uint16
		isNil bool
	}{
		{"z.cn", dns.TypeA, false},
		{"z.cn", dns.TypeAAAA, true},
		{"comment1.com", dns.TypeA, true},
		{"comment2.com", dns.TypeA, true},
		{"space_suffix.com", dns.TypeA, false},
		{"hello.wildcard1.com", dns.TypeA, false},
		{"a.wildcard2.com", dns.TypeA, false},
		{"v6.com", dns.TypeA, true},
		{"v6.com", dns.TypeAAAA, false},
	}
	for _, c := range cases {
		t.Log(c)
		resp = r.Get(buildReq(c.host, c.query))
		assert.Nil(t, err)
		if c.isNil {
			assert.Nil(t, resp)
		} else {
			assert.NotNil(t, resp)
		}
	}

	cfg = config.Conf{HostsFiles: []string{
		"testdata/invalid.txt",
	}}
	_, err = NewDNSHosts(cfg)
	t.Logf("%+v", err)
	assert.NotNil(t, err)

	cfg = config.Conf{HostsFiles: []string{
		"testdata/not_exists.txt",
	}}
	_, err = NewDNSHosts(cfg)
	t.Logf("%+v", err)
	assert.NotNil(t, err)
}

func TestHostReader_MultiIPAndDualStack(t *testing.T) {
	cfg := config.Conf{
		Hosts: map[string]config.StringSlice{
			"multi.example.com": {"1.1.1.1", "1.0.0.1", "2606:4700::1111", "2606:4700::1001"},
			"v4only.example.com": {"1.2.3.4", "1.2.3.5"},
			"v6only.example.com": {"2001:db8::1"},
			"*.wild.example.com": {"10.0.0.1", "10.0.0.2", "fc00::1"},
			"comma.example.com":  {"192.168.1.1, 192.168.1.2"},
			"dup.example.com":    {"172.16.0.1", "172.16.0.1"},
		},
	}
	r, err := NewDNSHosts(cfg)
	assert.Nil(t, err)
	assert.NotNil(t, r)

	// Dual-stack domain: A query
	respA := r.Get(buildReq("multi.example.com.", dns.TypeA))
	assert.NotNil(t, respA)
	assert.Equal(t, 2, len(respA.Answer))
	assert.Equal(t, "multi.example.com.\t0\tIN\tA\t1.1.1.1", respA.Answer[0].String())
	assert.Equal(t, "multi.example.com.\t0\tIN\tA\t1.0.0.1", respA.Answer[1].String())

	// Dual-stack domain: AAAA query
	respAAAA := r.Get(buildReq("multi.example.com.", dns.TypeAAAA))
	assert.NotNil(t, respAAAA)
	assert.Equal(t, 2, len(respAAAA.Answer))
	assert.Equal(t, "multi.example.com.\t0\tIN\tAAAA\t2606:4700::1111", respAAAA.Answer[0].String())
	assert.Equal(t, "multi.example.com.\t0\tIN\tAAAA\t2606:4700::1001", respAAAA.Answer[1].String())

	// Dual-stack domain: unsupported query type (e.g. TXT) returns nil
	respTXT := r.Get(buildReq("multi.example.com.", dns.TypeTXT))
	assert.Nil(t, respTXT)

	// IPv4 only domain: A query succeeds, AAAA query returns nil
	respV4A := r.Get(buildReq("v4only.example.com.", dns.TypeA))
	assert.NotNil(t, respV4A)
	assert.Equal(t, 2, len(respV4A.Answer))
	respV4AAAA := r.Get(buildReq("v4only.example.com.", dns.TypeAAAA))
	assert.Nil(t, respV4AAAA)

	// IPv6 only domain: AAAA query succeeds, A query returns nil
	respV6AAAA := r.Get(buildReq("v6only.example.com.", dns.TypeAAAA))
	assert.NotNil(t, respV6AAAA)
	assert.Equal(t, 1, len(respV6AAAA.Answer))
	respV6A := r.Get(buildReq("v6only.example.com.", dns.TypeA))
	assert.Nil(t, respV6A)

	// Wildcard with multiple IPs and dual-stack
	respWildA := r.Get(buildReq("sub.wild.example.com.", dns.TypeA))
	assert.NotNil(t, respWildA)
	assert.Equal(t, 2, len(respWildA.Answer))
	assert.Equal(t, "sub.wild.example.com.\t0\tIN\tA\t10.0.0.1", respWildA.Answer[0].String())
	assert.Equal(t, "sub.wild.example.com.\t0\tIN\tA\t10.0.0.2", respWildA.Answer[1].String())

	respWildAAAA := r.Get(buildReq("sub.wild.example.com.", dns.TypeAAAA))
	assert.NotNil(t, respWildAAAA)
	assert.Equal(t, 1, len(respWildAAAA.Answer))
	assert.Equal(t, "sub.wild.example.com.\t0\tIN\tAAAA\tfc00::1", respWildAAAA.Answer[0].String())

	// Comma-separated IPs
	respComma := r.Get(buildReq("comma.example.com.", dns.TypeA))
	assert.NotNil(t, respComma)
	assert.Equal(t, 2, len(respComma.Answer))

	// Deduplicated IPs
	respDup := r.Get(buildReq("dup.example.com.", dns.TypeA))
	assert.NotNil(t, respDup)
	assert.Equal(t, 1, len(respDup.Answer))

	// Empty request
	assert.Nil(t, r.Get(&dns.Msg{}))
}

func TestHostsFiles_MultiIPAndDualStack(t *testing.T) {
	content := `
# Linux style with multiple lines and dual-stack
1.1.1.1 host1.lan
1.1.1.2 host1.lan
2606::1 host1.lan

# Linux style wildcard
10.0.0.1 *.wild.lan
2606::2 *.wild.lan

# Domain style with multiple IPs on same line
host2.lan 2.2.2.1 2.2.2.2 2606::3
`
	tmpFile, err := os.CreateTemp("", "hosts_test_*.txt")
	assert.Nil(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString(content)
	assert.Nil(t, err)
	_ = tmpFile.Close()

	r, err := NewDNSHosts(config.Conf{
		HostsFiles: []string{tmpFile.Name()},
	})
	assert.Nil(t, err)
	assert.NotNil(t, r)

	// host1.lan A query -> 2 IPv4
	resp1A := r.Get(buildReq("host1.lan", dns.TypeA))
	assert.NotNil(t, resp1A)
	assert.Equal(t, 2, len(resp1A.Answer))
	assert.Equal(t, "host1.lan.\t0\tIN\tA\t1.1.1.1", resp1A.Answer[0].String())
	assert.Equal(t, "host1.lan.\t0\tIN\tA\t1.1.1.2", resp1A.Answer[1].String())

	// host1.lan AAAA query -> 1 IPv6
	resp1AAAA := r.Get(buildReq("host1.lan", dns.TypeAAAA))
	assert.NotNil(t, resp1AAAA)
	assert.Equal(t, 1, len(resp1AAAA.Answer))
	assert.Equal(t, "host1.lan.\t0\tIN\tAAAA\t2606::1", resp1AAAA.Answer[0].String())

	// *.wild.lan wildcard dual stack
	respWildA := r.Get(buildReq("a.wild.lan", dns.TypeA))
	assert.NotNil(t, respWildA)
	assert.Equal(t, 1, len(respWildA.Answer))
	assert.Equal(t, "a.wild.lan.\t0\tIN\tA\t10.0.0.1", respWildA.Answer[0].String())

	respWildAAAA := r.Get(buildReq("a.wild.lan", dns.TypeAAAA))
	assert.NotNil(t, respWildAAAA)
	assert.Equal(t, 1, len(respWildAAAA.Answer))
	assert.Equal(t, "a.wild.lan.\t0\tIN\tAAAA\t2606::2", respWildAAAA.Answer[0].String())

	// host2.lan A query -> 2 IPv4
	resp2A := r.Get(buildReq("host2.lan", dns.TypeA))
	assert.NotNil(t, resp2A)
	assert.Equal(t, 2, len(resp2A.Answer))
	assert.Equal(t, "host2.lan.\t0\tIN\tA\t2.2.2.1", resp2A.Answer[0].String())
	assert.Equal(t, "host2.lan.\t0\tIN\tA\t2.2.2.2", resp2A.Answer[1].String())

	// host2.lan AAAA query -> 1 IPv6
	resp2AAAA := r.Get(buildReq("host2.lan", dns.TypeAAAA))
	assert.NotNil(t, resp2AAAA)
	assert.Equal(t, 1, len(resp2AAAA.Answer))
	assert.Equal(t, "host2.lan.\t0\tIN\tAAAA\t2606::3", resp2AAAA.Answer[0].String())
}

func TestHostReaderWildcardUsesMostSpecificPattern(t *testing.T) {
	r, err := NewDNSHosts(config.Conf{Hosts: map[string]config.StringSlice{
		"*.example.com":     {"1.1.1.1"},
		"*.sub.example.com": {"2.2.2.2"},
	}})
	assert.Nil(t, err)

	resp := r.Get(buildReq("a.sub.example.com.", dns.TypeA))
	assert.NotNil(t, resp)
	assert.Equal(t, "a.sub.example.com.\t0\tIN\tA\t2.2.2.2", resp.Answer[0].String())
}

func TestYAMLUnmarshaling(t *testing.T) {
	yamlContent := `
hosts:
  "single.example.com": "1.1.1.1"
  "list.example.com":
    - "1.1.1.1"
    - "2.2.2.2"
  "inline.example.com": ["1.1.1.1", "2606::1"]
`
	var conf config.Conf
	err := yaml.Unmarshal([]byte(yamlContent), &conf)
	assert.Nil(t, err)
	assert.Equal(t, config.StringSlice{"1.1.1.1"}, conf.Hosts["single.example.com"])
	assert.Equal(t, config.StringSlice{"1.1.1.1", "2.2.2.2"}, conf.Hosts["list.example.com"])
	assert.Equal(t, config.StringSlice{"1.1.1.1", "2606::1"}, conf.Hosts["inline.example.com"])

	r, err := NewDNSHosts(conf)
	assert.Nil(t, err)

	respSingle := r.Get(buildReq("single.example.com", dns.TypeA))
	assert.NotNil(t, respSingle)
	assert.Equal(t, 1, len(respSingle.Answer))

	respList := r.Get(buildReq("list.example.com", dns.TypeA))
	assert.NotNil(t, respList)
	assert.Equal(t, 2, len(respList.Answer))

	respInlineA := r.Get(buildReq("inline.example.com", dns.TypeA))
	assert.NotNil(t, respInlineA)
	assert.Equal(t, 1, len(respInlineA.Answer))

	respInlineAAAA := r.Get(buildReq("inline.example.com", dns.TypeAAAA))
	assert.NotNil(t, respInlineAAAA)
	assert.Equal(t, 1, len(respInlineAAAA.Answer))

	// Test invalid YAML node type
	invalidYaml := `
hosts:
  "bad.example.com":
    nested: "value"
`
	var badConf config.Conf
	err = yaml.Unmarshal([]byte(invalidYaml), &badConf)
	assert.NotNil(t, err)

	// Test Invalid IP error
	invalidIPConf := config.Conf{
		Hosts: map[string]config.StringSlice{
			"bad.com": {"999.999.999.999"},
		},
	}
	_, err = NewDNSHosts(invalidIPConf)
	assert.NotNil(t, err)
}

func BenchmarkHostReader_Regexp(b *testing.B) {
	hosts, err := NewDNSHosts(config.Conf{Hosts: map[string]config.StringSlice{
		"z.cn":    {"1.1.1.1"},
		"*.wd.cn": {"1.1.1.1"},
	}})
	assert.Nil(b, err)
	req := buildReq("test.wd.cn", dns.TypeA)
	for i := 0; i < b.N; i++ {
		resp := hosts.Get(req)
		assert.NotNil(b, resp)
	}
}

func BenchmarkHostReader_Domain(b *testing.B) {
	r, err := NewDNSHosts(config.Conf{Hosts: map[string]config.StringSlice{
		"z.cn":    {"1.1.1.1"},
		"*.wd.cn": {"1.1.1.1"},
	}})
	assert.Nil(b, err)
	req := buildReq("z.cn", dns.TypeA)
	for i := 0; i < b.N; i++ {
		resp := r.Get(req)
		assert.NotNil(b, resp)
	}
}
