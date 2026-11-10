package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// validateGitLabToken pings the GitLab GraphQL API with the given token and
// returns the username of the authenticated user. It verifies that the token
// is valid and has the 'api' scope before the MCP server is registered.
func validateGitLabToken(ctx context.Context, client *http.Client, gitlabURL, token string) (string, error) {
	body := map[string]any{
		"query": "{ currentUser { username } }",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(gitlabURL, "/") + "/api/graphql"
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	// The answer is a username or a short error: 1 MiB is far more than enough.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return "", fmt.Errorf("HTTP 401: invalid or expired token")
	case http.StatusForbidden:
		return "", fmt.Errorf("HTTP 403: token lacks sufficient permissions")
	case http.StatusOK:
		// ok
	default:
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var result struct {
		Data struct {
			CurrentUser *struct {
				Username string `json:"username"`
			} `json:"currentUser"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("invalid response: %w", err)
	}
	if len(result.Errors) > 0 {
		msgs := make([]string, 0, len(result.Errors))
		for _, e := range result.Errors {
			msgs = append(msgs, e.Message)
		}
		return "", fmt.Errorf("GraphQL: %s", strings.Join(msgs, "; "))
	}
	if result.Data.CurrentUser == nil {
		return "", fmt.Errorf("token lacks the 'api' scope or permission to query currentUser")
	}
	return result.Data.CurrentUser.Username, nil
}
