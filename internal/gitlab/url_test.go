package gitlab

import (
	"strings"
	"testing"
)

func TestNormalizeGitLabURL(t *testing.T) {
	accepted := map[string]string{
		"":                                "https://gitlab.com",
		"  https://gitlab.com/  ":         "https://gitlab.com",
		"https://gitlab.example.com":      "https://gitlab.example.com",
		"https://example.com/gitlab/":     "https://example.com/gitlab",
		"https://gitlab.example.com:8443": "https://gitlab.example.com:8443",
		"http://localhost:8080":           "http://localhost:8080",
		"http://127.0.0.1:3000/":          "http://127.0.0.1:3000",
		"http://[::1]:3000":               "http://[::1]:3000",
	}
	for raw, want := range accepted {
		got, err := NormalizeURL(raw)
		if err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}

	rejected := map[string]string{
		"http://gitlab.example.com":           "must use https",
		"ftp://gitlab.example.com":            "must use https",
		"gitlab.example.com":                  "absolute URL",
		"https://user:secret@gitlab.com":      "must not contain credentials",
		"https://gitlab.com/?private_token=x": "must not contain a query or fragment",
		"https://gitlab.com/#x":               "must not contain a query or fragment",
		"https://git\x7flab.com":              "absolute URL",
	}
	for raw, want := range rejected {
		_, err := NormalizeURL(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("NormalizeURL(%q) error = %v, want it to contain %q", raw, err, want)
			continue
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("the error echoes the credentials: %v", err)
		}
	}
}
