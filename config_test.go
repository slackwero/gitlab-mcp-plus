package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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
		got, err := normalizeGitLabURL(raw)
		if err != nil || got != want {
			t.Errorf("normalizeGitLabURL(%q) = %q, %v; want %q", raw, got, err, want)
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
		_, err := normalizeGitLabURL(raw)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("normalizeGitLabURL(%q) error = %v, want it to contain %q", raw, err, want)
			continue
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("the error echoes the credentials: %v", err)
		}
	}
}

func TestApp_RejectsOversizedResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"filler":"` + strings.Repeat("x", 200) + `"}}`))
	}))
	t.Cleanup(srv.Close)

	app := NewApp("test-token", srv.URL)
	app.maxResponseBytes = 100
	if _, err := app.graphql(context.Background(), "query { x }", nil); err == nil || !strings.Contains(err.Error(), "larger than 100 bytes") {
		t.Errorf("graphql error = %v", err)
	}
	if _, err := app.rest(context.Background(), "GET", "/x", nil); err == nil || !strings.Contains(err.Error(), "larger than 100 bytes") {
		t.Errorf("rest error = %v", err)
	}
	if _, _, err := app.restList(context.Background(), "/x"); err == nil || !strings.Contains(err.Error(), "larger than 100 bytes") {
		t.Errorf("restList error = %v", err)
	}
}
