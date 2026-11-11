package tools

import (
	"strings"
	"testing"
)

// Regression: an MCP caller could point osvBaseUrl at any plain-http host and
// receive the package inventory there.
func TestCheckAgentOSVBaseURL(t *testing.T) {
	allowed := []string{"https://api.osv.dev", "https://mirror.example:8443/osv", "http://127.0.0.1:8080", "http://[::1]:9000", "http://localhost:3000"}
	for _, raw := range allowed {
		if err := checkAgentOSVBaseURL(raw); err != nil {
			t.Errorf("%s rejected: %v", raw, err)
		}
	}
	rejected := []string{"http://attacker.example", "http://10.0.0.5", "http://127.0.0.1.attacker.example", "https://u:p@mirror.example"}
	for _, raw := range rejected {
		err := checkAgentOSVBaseURL(raw)
		if err == nil {
			t.Errorf("%s accepted", raw)
			continue
		}
		if strings.Contains(err.Error(), "u:p") {
			t.Errorf("error echoes credentials: %v", err)
		}
	}
}
