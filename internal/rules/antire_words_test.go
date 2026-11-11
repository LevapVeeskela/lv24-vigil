package rules

import (
	"strings"
	"testing"
)

func TestAntiREPathWords(t *testing.T) {
	got := strings.Join(antirePathWords(`ios/Runner/RunnerDebug.entitlements`), ",")
	if got != "ios,runner,runner,debug,entitlements" {
		t.Fatalf("words = %s", got)
	}
}
