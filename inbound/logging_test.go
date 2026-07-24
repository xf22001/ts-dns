package inbound

import (
	"bytes"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/utils"
)

// Add a mutex to prevent race conditions on the global logrus logger
var logrusLock sync.Mutex

func TestLoggingOfAllAnswerTypes(t *testing.T) {
	logrusLock.Lock()
	defer logrusLock.Unlock()

	// 1. Setup logrus to capture output
	var logBuffer bytes.Buffer
	originalOutput := logrus.StandardLogger().Out
	originalFormatter := logrus.StandardLogger().Formatter
	originalLevel := logrus.StandardLogger().Level

	logrus.SetOutput(&logBuffer)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.DebugLevel) // Must be DebugLevel for 'answers' field

	defer func() {
		logrus.SetOutput(originalOutput)
		logrus.SetFormatter(originalFormatter)
		logrus.SetLevel(originalLevel)
	}()

	// 2. Create a handler with cache enabled
	conf := config.Conf{
		Cache:  config.CacheConf{Size: 100},
		Groups: map[string]config.Group{"fallback": {}},
	}
	h, err := newHandle(conf)
	assert.Nil(t, err)
	assert.NotNil(t, h)

	// 3. Create request and response messages
	domain := "test-log.com."
	req := buildReq(domain, dns.TypeA)
	cnameRR, _ := dns.NewRR(domain + " 300 IN CNAME real.com.")
	aRR, _ := dns.NewRR("real.com. 300 IN A 1.2.3.4")
	aaaaRR, _ := dns.NewRR("real.com. 300 IN AAAA ::1")
	respWithAllTypes := new(dns.Msg)
	respWithAllTypes.SetReply(req)
	respWithAllTypes.Answer = []dns.RR{cnameRR, aRR, aaaaRR}

	// 4. Set the response in the cache and WAIT for it to be processed
	// Ristretto admission can take several tries or a small delay
	for i := 0; i < 50; i++ {
		h.cache.Set(req, respWithAllTypes)
		if h.cache.Get(req) != nil {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	if h.cache.Get(req) == nil {
		t.Fatal("Failed to seed cache for test")
	}

	// Clear logs generated during setup
	logBuffer.Reset()

	// 5. Call ServeDNS to trigger the handler and logging
	rw := utils.NewFakeRespWriter()
	h.ServeDNS(rw, req)

	// 6. Parse and verify the log output
	var logEntry map[string]interface{}
	foundLog := false
	logLines := strings.Split(logBuffer.String(), "\n")
	for _, line := range logLines {
		if line == "" {
			continue
		}
		var currentEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &currentEntry); err != nil {
			continue
		}

		if q, ok := currentEntry["question"]; ok && strings.TrimSuffix(q.(string), ".") == "test-log.com" {
			logEntry = currentEntry
			foundLog = true
			break
		}
	}

	if !foundLog {
		t.Fatalf("Log entry not found. Buffer: %s", logBuffer.String())
	}

	// 7. Assertions
	assert.Equal(t, float64(3), logEntry["answer"])
	assert.Equal(t, "cache", logEntry["hit"])

	answersField, ok := logEntry["answers"]
	assert.True(t, ok, "Log missing 'answers' field")
	answersList := answersField.([]interface{})
	assert.Equal(t, 3, len(answersList))

	// Sort answers by type to handle cache shuffling
	sort.Slice(answersList, func(i, j int) bool {
		return answersList[i].(map[string]interface{})["type"].(string) < answersList[j].(map[string]interface{})["type"].(string)
	})

	// Expected sorted types: A, AAAA, CNAME
	assert.Equal(t, "A", answersList[0].(map[string]interface{})["type"])
	assert.Equal(t, "1.2.3.4", answersList[0].(map[string]interface{})["value"])
	assert.Equal(t, "AAAA", answersList[1].(map[string]interface{})["type"])
	assert.Equal(t, "::1", answersList[1].(map[string]interface{})["value"])
	assert.Equal(t, "CNAME", answersList[2].(map[string]interface{})["type"])
	assert.Equal(t, "real.com.", answersList[2].(map[string]interface{})["value"])
}

// findLogEntry 在 logrus 输出中查找指定 question 的日志条目
func findLogEntry(t *testing.T, buf bytes.Buffer, domain string) map[string]interface{} {
	t.Helper()
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if q, ok := entry["question"]; ok && strings.TrimSuffix(q.(string), ".") == domain {
			return entry
		}
	}
	t.Fatalf("log entry for %s not found. buffer: %s", domain, buf.String())
	return nil
}

// TestLoggingProtoAndInternal 验证：
//  1. DoH（FakeRespWriter 注入真实地址 + proto=https）能正确记录 remote 与 proto；
//  2. 内部解析（SetInternal）不打客户端查询日志。
func TestLoggingProtoAndInternal(t *testing.T) {
	logrusLock.Lock()
	defer logrusLock.Unlock()

	var logBuffer bytes.Buffer
	originalOutput := logrus.StandardLogger().Out
	originalFormatter := logrus.StandardLogger().Formatter
	originalLevel := logrus.StandardLogger().Level

	logrus.SetOutput(&logBuffer)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)

	defer func() {
		logrus.SetOutput(originalOutput)
		logrus.SetFormatter(originalFormatter)
		logrus.SetLevel(originalLevel)
	}()

	conf := config.Conf{
		Cache:  config.CacheConf{Size: 100},
		Groups: map[string]config.Group{"fallback": {}},
	}
	h, err := newHandle(conf)
	assert.Nil(t, err)
	assert.NotNil(t, h)

	seedCache := func(domain string) *dns.Msg {
		req := buildReq(domain, dns.TypeA)
		aRR, _ := dns.NewRR(domain + " 300 IN A 1.2.3.4")
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{aRR}
		for i := 0; i < 50; i++ {
			h.cache.Set(req, resp)
			if h.cache.Get(req) != nil {
				break
			}
			time.Sleep(time.Millisecond * 10)
		}
		if h.cache.Get(req) == nil {
			t.Fatal("failed to seed cache for test")
		}
		return req
	}

	// 1. DoH：注入真实客户端地址 + proto=https
	dohDomain := "doh-client.com."
	req := seedCache(dohDomain)
	logBuffer.Reset()
	rwDoH := utils.NewFakeRespWriter()
	rwDoH.SetRemote(&net.TCPAddr{IP: net.ParseIP("9.9.9.9"), Port: 53000})
	rwDoH.SetProto("https")
	h.ServeDNS(rwDoH, req)

	entry := findLogEntry(t, logBuffer, strings.TrimSuffix(dohDomain, "."))
	assert.Equal(t, "9.9.9.9", entry["remote"], "DoH 应记录真实客户端地址")
	assert.Equal(t, "https", entry["proto"], "DoH 协议应为 https")
	assert.Equal(t, "cache", entry["hit"])

	// 2. 内部解析：不应产生客户端查询日志
	internalDomain := "internal-resolve.com."
	internalReq := buildReq(internalDomain, dns.TypeA)
	logBuffer.Reset()
	rwInternal := utils.NewFakeRespWriter()
	rwInternal.SetInternal()
	h.ServeDNS(rwInternal, internalReq)
	assert.NotContains(t, logBuffer.String(), "internal-resolve.com",
		"内部解析不应出现在客户端查询日志中")
}
