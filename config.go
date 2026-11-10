package main

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

const defaultGitLabURL = "https://gitlab.com"

// normalizeGitLabURL validates the GitLab instance URL and returns it without a
// trailing slash; empty means gitlab.com. The token travels with every request,
// so the URL must use https: plain http is accepted only for a GitLab on the
// loopback interface. Errors never echo the URL, which may carry credentials.
func normalizeGitLabURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultGitLabURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", errors.New("the GitLab URL must be an absolute URL such as https://gitlab.example.com")
	}
	if u.User != nil {
		return "", errors.New("the GitLab URL must not contain credentials: pass the token through GITLAB_TOKEN")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", errors.New("the GitLab URL must not contain a query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", errors.New("the GitLab URL must use https: over http the token would travel unencrypted (http is accepted only for localhost)")
		}
	default:
		return "", errors.New("the GitLab URL must use https")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
