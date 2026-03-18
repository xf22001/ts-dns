package inbound

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

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
	logrus.SetLevel(logrus.DebugLevel)

	defer func() {
		logrus.SetOutput(originalOutput)
		logrus.SetFormatter(originalFormatter)
		logrus.SetLevel(originalLevel)
	}()

	// 2. Create a handler with cache enabled
	conf := config.Conf{
		Cache:  config.CacheConf{Size: 10},
		Groups: map[string]config.Group{"fallback": {}}, // Need a fallback group
	}
	h, err := newHandle(conf)
	assert.Nil(t, err)
	assert.NotNil(t, h)

	// Clear any logs that might have been generated during handler creation
	logBuffer.Reset()

	// 3. Create request and response messages
	req := buildReq("test.com.", dns.TypeA) // Use FQDN
	cnameRR, _ := dns.NewRR("test.com. 300 IN CNAME real.com.")
	aRR, _ := dns.NewRR("real.com. 300 IN A 1.2.3.4")
	aaaaRR, _ := dns.NewRR("real.com. 300 IN AAAA ::1")
	respWithAllTypes := new(dns.Msg)
	respWithAllTypes.SetReply(req)
	respWithAllTypes.Answer = []dns.RR{cnameRR, aRR, aaaaRR}

	// 4. Set the response in the cache
	h.cache.Set(req, respWithAllTypes)

	// 5. Call ServeDNS to trigger the handler and logging
	rw := utils.NewFakeRespWriter()
	h.ServeDNS(rw, req)

	// 6. Parse and verify the log output
	var logEntry map[string]interface{}
	foundLog := false
	logLines := strings.Split(logBuffer.String(), "\n")
	t.Logf("Captured %d log lines", len(logLines))
	for _, line := range logLines {
		if line == "" {
			continue
		}
		var currentEntry map[string]interface{}
		err = json.Unmarshal([]byte(line), &currentEntry)
		assert.Nil(t, err, "Log output line should be valid JSON: "+line)

		if question, ok := currentEntry["question"]; ok && question == "test.com." {
			logEntry = currentEntry
			foundLog = true
			break
		}
	}

	assert.True(t, foundLog, "Should find the log entry for the test question")
	if !foundLog {
		t.Log("Full log buffer:\n" + logBuffer.String())
		t.FailNow()
	}

	// 7. Assertions
	assert.Equal(t, float64(3), logEntry["answer"], "Log should show answer count of 3")

	answersField, ok := logEntry["answers"]
	assert.True(t, ok, "Log should contain 'answers' field")

	answersList, ok := answersField.([]interface{})
	assert.True(t, ok, "'answers' field should be a list of objects")
	assert.Equal(t, 3, len(answersList), "Should have 3 records in answers list")

	// Check CNAME record
	cnameRecord := answersList[0].(map[string]interface{})
	assert.Equal(t, "CNAME", cnameRecord["type"])
	assert.Equal(t, cnameRR.Header().Name, cnameRecord["name"])
	assert.Equal(t, "real.com.", cnameRecord["value"])

	// Check A record
	aRecord := answersList[1].(map[string]interface{})
	assert.Equal(t, "A", aRecord["type"])
	assert.Equal(t, aRR.Header().Name, aRecord["name"])
	assert.Equal(t, "1.2.3.4", aRecord["value"])

	// Check AAAA record
	aaaaRecord := answersList[2].(map[string]interface{})
	assert.Equal(t, "AAAA", aaaaRecord["type"])
	assert.Equal(t, aaaaRR.Header().Name, aaaaRecord["name"])
	assert.Equal(t, "::1", aaaaRecord["value"])

	t.Log("Found and verified log:", logEntry)
}
