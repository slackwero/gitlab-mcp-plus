// Package gitlab is the client for the GitLab GraphQL and REST APIs used by the MCP tools.
package gitlab

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

// defaultMaxResponseBytes caps what is read from a single GitLab response, so
// a misbehaving instance or proxy cannot exhaust the memory of the server.
const defaultMaxResponseBytes = 32 << 20

// Client calls the GitLab APIs with a token. It is safe for concurrent use.
type Client struct {
	token     string
	endpoint  string
	gitlabURL string
	client    *http.Client

	maxResponseBytes int64
}

// NewClient returns a client for the GitLab instance at gitlabURL (gitlab.com
// when empty), authenticated with token. Validate the URL with NormalizeURL
// first.
func NewClient(token, gitlabURL string) *Client {
	if gitlabURL == "" {
		gitlabURL = defaultURL
	}
	return &Client{
		token:     token,
		endpoint:  gitlabURL + "/api/graphql",
		gitlabURL: gitlabURL,
		client:    &http.Client{Timeout: 30 * time.Second},

		maxResponseBytes: defaultMaxResponseBytes,
	}
}

// readBody reads a GitLab response body, refusing one larger than
// maxResponseBytes instead of buffering it whole.
func (c *Client) readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, fmt.Errorf("GitLab response is larger than %d bytes", c.maxResponseBytes)
	}
	return body, nil
}

// GraphQL runs a GraphQL document and returns its data. A response with a
// non-empty errors list is an error, even when GitLab answers HTTP 200.
func (c *Client) GraphQL(ctx context.Context, query string, variables map[string]any) (map[string]any, error) {
	body := map[string]any{
		"query":     query,
		"variables": variables,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := c.readBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitLab API %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if errs, ok := result["errors"]; ok {
		if errList, ok := errs.([]any); ok && len(errList) > 0 {
			var msgs []string
			for _, e := range errList {
				if em, ok := e.(map[string]any); ok {
					if msg, ok := em["message"].(string); ok {
						msgs = append(msgs, msg)
					}
				}
			}
			return nil, fmt.Errorf("%s", strings.Join(msgs, "; "))
		}
	}

	data, ok := result["data"]
	if !ok {
		return nil, fmt.Errorf("no data returned from GitLab GraphQL API")
	}

	dataMap, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected data format from GitLab GraphQL API")
	}

	return dataMap, nil
}

// REST runs a REST request on /api/v4 and decodes a JSON object response; an
// empty body decodes to an empty map.
func (c *Client) REST(ctx context.Context, method, path string, body any) (map[string]any, error) {
	url := c.gitlabURL + "/api/v4" + path

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := c.readBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GitLab REST %d: %s", resp.StatusCode, string(respBody))
	}

	if len(respBody) == 0 {
		return map[string]any{}, nil
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result, nil
}

// RESTList runs a REST GET whose response is a JSON array and also returns the
// X-Next-Page header for offset pagination.
func (c *Client) RESTList(ctx context.Context, path string) ([]any, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.gitlabURL+"/api/v4"+path, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := c.readBody(resp)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("GitLab REST %d: %s", resp.StatusCode, string(respBody))
	}

	var result []any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, "", fmt.Errorf("unmarshal response: %w", err)
	}
	return result, resp.Header.Get("X-Next-Page"), nil
}
