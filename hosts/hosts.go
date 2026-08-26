package hosts

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/config"
)

// region interface

type IDNSHosts interface {
	Get(req *dns.Msg) *dns.Msg
}

type hostPattern struct {
	pattern string
	reg     *regexp.Regexp
	ips     []ipInfo
}

func splitIPs(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})
}

func containsIP(list []ipInfo, target ipInfo) bool {
	for _, ip := range list {
		if ip.val == target.val && ip._type == target._type {
			return true
		}
	}
	return false
}

func NewDNSHosts(conf config.Conf) (IDNSHosts, error) {
	domainMap := make(map[string][]ipInfo, len(conf.Hosts))
	patternMap := make(map[string]*hostPattern, len(conf.Hosts))

	addDomainIP := func(domain string, ip ipInfo) {
		if !containsIP(domainMap[domain], ip) {
			domainMap[domain] = append(domainMap[domain], ip)
		}
	}

	addPatternIP := func(host, patternHost string, reg *regexp.Regexp, ip ipInfo) {
		if p, exists := patternMap[host]; exists {
			if !containsIP(p.ips, ip) {
				p.ips = append(p.ips, ip)
			}
			return
		}
		patternMap[host] = &hostPattern{
			pattern: patternHost,
			reg:     reg,
			ips:     []ipInfo{ip},
		}
	}

	load := func(host string, ipStrs ...string) error {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return nil
		}
		for _, rawIP := range ipStrs {
			subIPs := splitIPs(rawIP)
			if len(subIPs) == 0 {
				continue
			}
			for _, ipStr := range subIPs {
				ip := buildIPInfo(ipStr)
				if ip == zeroIP {
					return fmt.Errorf("parse %q to ip failed", ipStr)
				}
				if !strings.ContainsAny(host, "*?") {
					addDomainIP(host, ip)
					continue
				}
				// wildcard to regexp
				patternHost := host
				patternHost = strings.Replace(patternHost, ".", "\\.", -1)
				patternHost = strings.Replace(patternHost, "*", ".*", -1)
				patternHost = strings.Replace(patternHost, "?", ".", -1)
				reg, err := regexp.Compile("^" + patternHost + "$")
				if err != nil {
					return fmt.Errorf("build host regexp %q failed: %w", host, err)
				}
				addPatternIP(host, patternHost, reg, ip)
			}
		}
		return nil
	}

	// parse hosts
	for host, ips := range conf.Hosts {
		if err := load(host, ips...); err != nil {
			return nil, err
		}
	}

	// parse hosts files
	files := make([]*os.File, 0, len(conf.HostsFiles))
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, filename := range conf.HostsFiles {
		logrus.Debugf("load hosts file %q", filename)
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("load hosts file %q error: %w", filename, err)
		}
		files = append(files, file)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// parse each line
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue // ignore comment
			}
			parts := strings.FieldsFunc(line, unicode.IsSpace)
			if len(parts) < 2 {
				continue
			}
			if ip := buildIPInfo(parts[0]); ip != zeroIP {
				// linux style hosts file: <ip> <domain1> <domain2> ...
				for _, domain := range parts[1:] {
					domain = strings.ToLower(strings.TrimSpace(domain))
					if domain == "" {
						continue
					}
					if strings.ContainsAny(domain, "*?") {
						patternHost := domain
						patternHost = strings.Replace(patternHost, ".", "\\.", -1)
						patternHost = strings.Replace(patternHost, "*", ".*", -1)
						patternHost = strings.Replace(patternHost, "?", ".", -1)
						reg, err := regexp.Compile("^" + patternHost + "$")
						if err != nil {
							return nil, fmt.Errorf("build host regexp %q failed: %w", domain, err)
						}
						addPatternIP(domain, patternHost, reg, ip)
					} else {
						addDomainIP(domain, ip)
					}
				}
				continue
			}
			if err = load(parts[0], parts[1:]...); err != nil {
				return nil, fmt.Errorf("load hosts file %q error: %w", filename, err)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("load hosts file %q error: %w", filename, err)
		}
	}

	patterns := make([]hostPattern, 0, len(patternMap))
	for _, p := range patternMap {
		patterns = append(patterns, *p)
	}
	sort.Slice(patterns, func(i, j int) bool {
		if len(patterns[i].pattern) != len(patterns[j].pattern) {
			return len(patterns[i].pattern) > len(patterns[j].pattern)
		}
		return patterns[i].pattern < patterns[j].pattern
	})
	return &HostReader{
		domainMap: domainMap,
		patterns:  patterns,
	}, nil
}

// endregion

// region impl
var (
	zeroIP           = ipInfo{}
	_      IDNSHosts = &HostReader{}
)

type ipInfo struct {
	val   string
	_type uint16
}

func (i ipInfo) Record(host string) string {
	if i._type == dns.TypeA {
		return host + " 0 IN A " + i.val
	}
	return host + " 0 IN AAAA " + i.val
}

func buildIPInfo(val string) ipInfo {
	ip := net.ParseIP(val)
	if ip == nil {
		return zeroIP
	}
	if ip.To4() != nil {
		return ipInfo{val: val, _type: dns.TypeA}
	} else if ip.To16() != nil {
		return ipInfo{val: val, _type: dns.TypeAAAA}
	}
	return zeroIP
}

// HostReader 管理hosts
type HostReader struct {
	domainMap map[string][]ipInfo
	patterns  []hostPattern
}

func (h *HostReader) Get(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return nil
	}
	// todo dns大小写不敏感
	host, qType := strings.ToLower(req.Question[0].Name), req.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}

	getIPs := func(host string) ([]ipInfo, bool) {
		if res, exists := h.domainMap[host]; exists {
			return res, true
		}
		for _, pattern := range h.patterns {
			if pattern.reg.MatchString(host) {
				return pattern.ips, true
			}
		}
		return nil, false
	}
	ips, exists := getIPs(host)
	if !exists && strings.HasSuffix(host, ".") {
		ips, exists = getIPs(host[:len(host)-1])
	}
	if !exists {
		return nil
	}

	var answers []dns.RR
	for _, ip := range ips {
		if ip._type == qType {
			rr, err := dns.NewRR(ip.Record(host))
			if err != nil {
				logrus.Errorf("build dns rr failed: %+v", err)
				continue
			}
			answers = append(answers, rr)
		}
	}
	if len(answers) == 0 {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = answers
	return resp
}

// endregion
