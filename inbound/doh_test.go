package inbound

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
)

// TestDohXForwarded 验证 DoH handler 在受信任(反代)场景下从
// X-Forwarded-For / X-Forwarded-Proto 还原真实客户端地址与协议；
// 非受信任场景应忽略这些头。
func TestDohXForwarded(t *testing.T) {
	logrusLock.Lock()
	defer logrusLock.Unlock()

	var logBuffer bytes.Buffer
	origOut := logrus.StandardLogger().Out
	origFmt := logrus.StandardLogger().Formatter
	origLvl := logrus.StandardLogger().Level
	logrus.SetOutput(&logBuffer)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)
	defer func() {
		logrus.SetOutput(origOut)
		logrus.SetFormatter(origFmt)
		logrus.SetLevel(origLvl)
	}()

	conf := config.Conf{
		Cache:  config.CacheConf{Size: 100},
		Groups: map[string]config.Group{"fallback": {}},
	}
	handler, err := NewHandler(conf)
	assert.Nil(t, err)
	defer handler.Stop()

	domain := "xff-test.com."
	req := buildReq(domain, dns.TypeA)
	body, err := req.Pack()
	assert.Nil(t, err)

	makeReq := func(remote, xff, xfp string, trust bool) map[string]interface{} {
		logBuffer.Reset()
		r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/dns-message")
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		w := httptest.NewRecorder()
		NewDohHandler(handler, trust).ServeHTTP(w, r)

		for _, line := range strings.Split(logBuffer.String(), "\n") {
			if line == "" {
				continue
			}
			var e map[string]interface{}
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				continue
			}
			if q, ok := e["question"]; ok && strings.TrimSuffix(q.(string), ".") == strings.TrimSuffix(domain, ".") {
				return e
			}
		}
		t.Fatalf("no log for %s. buffer: %s", domain, logBuffer.String())
		return nil
	}

	// 受信任 + XFF（nginx 追加）：取最后一个（代理直连对端）为真实客户端，忽略左侧伪造值
	e := makeReq("127.0.0.1:12345", "203.0.113.9, 10.0.0.1", "https", true)
	assert.Equal(t, "10.0.0.1", e["remote"], "应取 XFF 最后一个(代理直连)IP，忽略左侧伪造值")
	assert.Equal(t, "https", e["proto"], "应取 X-Forwarded-Proto")

	// 受信任但无 XFF：回退到真实对端
	e = makeReq("127.0.0.1:12345", "", "", true)
	assert.Equal(t, "127.0.0.1", e["remote"])
	assert.Equal(t, "http", e["proto"])

	// 非受信任 + XFF：必须忽略伪造头，使用真实对端
	e = makeReq("127.0.0.1:12345", "203.0.113.9, 10.0.0.1", "https", false)
	assert.Equal(t, "127.0.0.1", e["remote"], "非受信任场景不得信任 XFF")
	assert.Equal(t, "http", e["proto"])
}
