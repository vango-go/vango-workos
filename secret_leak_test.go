package workos

import (
	"strings"
	"testing"
)

func assertNoSecretLeak(t *testing.T, s string, extras ...string) {
	t.Helper()

	deny := []string{
		"access_token",
		"refresh_token",
		"eyJ",
	}
	deny = append(deny, extras...)

	for _, token := range deny {
		if token == "" {
			continue
		}
		if strings.Contains(s, token) {
			t.Fatalf("unexpected secret-like token %q in string %q", token, s)
		}
	}
}
