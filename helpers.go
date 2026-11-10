package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// queryResolveID returns the global ID of a project or group. Expand it with
// scopedQuery before sending it.
const queryResolveID = "query($fullPath: ID!) { __SCOPE__(fullPath: $fullPath) { id } }"

// scopePlaceholder marks the root field of a document shared by projects and
// groups.
const scopePlaceholder = "__SCOPE__"

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// pageSize reads the "first" argument: 20 when it is absent or below 1, and
// never more than GitLab's maximum page of 100.
func pageSize(args map[string]any) int {
	first, _ := args["first"].(float64)
	switch {
	case first < 1:
		return defaultPageSize
	case first > maxPageSize:
		return maxPageSize
	}
	return int(first)
}

// scopedQuery turns a document template into its project or group variant by
// replacing the __SCOPE__ root field with scope.
func scopedQuery(tmpl, scope string) string {
	return strings.Replace(tmpl, scopePlaceholder, scope, 1)
}

// gid returns the GitLab global ID of a model from a bare numeric ID. A value
// that is already a global ID is returned unchanged.
func gid(model, id string) string {
	if strings.HasPrefix(id, "gid://") {
		return id
	}
	return "gid://gitlab/" + model + "/" + id
}

// gidList reads a required list argument of IDs and normalizes each one to a
// global ID of model. It rejects more than limit entries and any entry that is
// not a non-empty string locally, so GitLab is never asked for more than its
// API accepts nor for fewer IDs than the caller gave.
func gidList(param, model string, arg any, limit int) ([]string, error) {
	ids, err := limitedStrings(param, arg, limit)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%s is required", param)
	}
	for i, id := range ids {
		ids[i] = gid(model, id)
	}
	return ids, nil
}

// limitedStrings reads a list argument of non-blank strings with a cap of
// limit entries and returns them trimmed. It is all or nothing, unlike the
// lenient stringList: a write tool must act on exactly the entries it was
// given, so one invalid entry rejects the whole list. An absent or null
// argument is an empty list: the caller decides whether the argument is
// required.
func limitedStrings(param string, arg any, limit int) ([]string, error) {
	if arg == nil {
		return []string{}, nil
	}
	items, ok := arg.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", param)
	}
	if len(items) > limit {
		return nil, fmt.Errorf("%s accepts at most %d entries (got %d)", param, limit, len(items))
	}
	out := make([]string, len(items))
	for i, item := range items {
		s, _ := item.(string)
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("%s must contain only non-empty strings (entry %d is not)", param, i+1)
		}
		out[i] = s
	}
	return out, nil
}

// resolveGID returns the global ID of the project or group at path. scope is
// "project" or "group".
func (a *App) resolveGID(ctx context.Context, scope, path string) (string, error) {
	data, err := a.graphql(ctx, scopedQuery(queryResolveID, scope), map[string]any{"fullPath": path})
	if err != nil {
		return "", fmt.Errorf("resolving %s '%s': %w", scope, path, err)
	}
	id, _ := mapGet(data, scope)["id"].(string)
	if id == "" {
		return "", fmt.Errorf("%s '%s' not found", capitalize(scope), path)
	}
	return id, nil
}

// payloadError turns the errors list of a mutation payload into a tool error,
// or returns nil when the mutation reported none.
func payloadError(action string, payload map[string]any) *mcp.CallToolResult {
	errs := getErrorStrings(payload)
	if len(errs) == 0 {
		return nil
	}
	return errResult(fmt.Sprintf("Failed to %s: %s", action, strings.Join(errs, ", ")))
}
