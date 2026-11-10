package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestListDependencies_ForwardsFilters(t *testing.T) {
	const response = `{"data":{"project":{"dependencies":{"nodes":[{"name":"lodash","vulnerabilityCount":2}],
	  "pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`
	app, fake := newFakeGitLab(t, response)
	res, err := app.handleListDependencies(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "component_names": []any{"lodash"}, "package_managers": []any{"npm"},
	}))
	if text := resultText(t, res, err); !strings.Contains(text, `"name": "lodash"`) {
		t.Errorf("result = %s", text)
	}
	vars := fake.lastCall(t).Variables
	if !reflect.DeepEqual(vars["componentNames"], []any{"lodash"}) || !reflect.DeepEqual(vars["packageManagers"], []any{"NPM"}) {
		t.Errorf("variables = %v", vars)
	}
	if _, present := vars["sort"]; present {
		t.Errorf("sort must not be sent")
	}
}

func TestListDependencies_SendsUppercasedSort(t *testing.T) {
	const response = `{"data":{"group":{"dependencies":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`
	app, fake := newFakeGitLab(t, response)
	res, err := app.handleListDependencies(context.Background(), callTool(map[string]any{
		"group_path": "acme", "sort": " severity_desc ", "first": float64(5), "after": "abc",
	}))
	resultText(t, res, err)
	vars := fake.lastCall(t).Variables
	if vars["sort"] != "SEVERITY_DESC" || vars["first"] != float64(5) || vars["after"] != "abc" || vars["fullPath"] != "acme" {
		t.Errorf("variables = %v", vars)
	}
	if !strings.Contains(fake.lastCall(t).Query, "group(fullPath: $fullPath)") {
		t.Errorf("query was not scoped to group: %s", fake.lastCall(t).Query)
	}
}

func TestListDependencies_NullRootIsNotFound(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"project":null}}`)
	res, err := app.handleListDependencies(context.Background(), callTool(map[string]any{"project_path": "acme/missing"}))
	if msg := errorText(t, res, err); msg != "Project 'acme/missing' not found" {
		t.Errorf("message = %q", msg)
	}
}

func TestListDependencies_NullDependenciesIsExplained(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"project":{"dependencies":null}}}`)
	res, err := app.handleListDependencies(context.Background(), callTool(map[string]any{"project_path": "acme/app"}))
	want := "Project 'acme/app' has no dependency data available (not licensed or not permitted)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

const emptyViolations = `{"data":{"group":{"projectComplianceViolations":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`

func TestListComplianceViolations_BuildsFilters(t *testing.T) {
	app, fake := newScriptedGitLab(t, []string{`{"data":{"project":{"id":"gid://gitlab/Project/9"}}}`, emptyViolations}, nil)
	res, err := app.handleListComplianceViolations(context.Background(), callTool(map[string]any{
		"group_path": "acme", "status": []any{"detected"}, "created_after": " 2026-11-01 ", "project_path": "acme/app",
	}))
	resultText(t, res, err)
	want := map[string]any{"status": []any{"DETECTED"}, "createdAfter": "2026-11-01", "projectId": "gid://gitlab/Project/9"}
	if got := fake.graphQLCalls()[1].Variables["filters"]; !reflect.DeepEqual(got, want) {
		t.Errorf("filters = %v", got)
	}

	app, fake = newScriptedGitLab(t, []string{emptyViolations}, nil)
	res, err = app.handleListComplianceViolations(context.Background(), callTool(map[string]any{"group_path": "acme", "created_before": "  "}))
	resultText(t, res, err)
	if got := fake.graphQLCalls()[0].Variables["filters"]; !reflect.DeepEqual(got, map[string]any{}) {
		t.Errorf("without filters, want an empty object, got %v", got)
	}
}

func TestListComplianceViolations_RejectsInvalidDates(t *testing.T) {
	for _, param := range []string{"created_after", "created_before"} {
		app, fake := newFakeGitLab(t, emptyViolations)
		res, err := app.handleListComplianceViolations(context.Background(), callTool(map[string]any{
			"group_path": "acme", param: "11/01/2026",
		}))
		if msg := errorText(t, res, err); msg != param+" must be YYYY-MM-DD" {
			t.Errorf("message = %q", msg)
		}
		if n := len(fake.graphQLCalls()); n != 0 {
			t.Errorf("%s: %d requests were sent before validation", param, n)
		}
	}
}

func TestListComplianceViolations_UnknownProjectIsNotFound(t *testing.T) {
	app, fake := newScriptedGitLab(t, []string{`{"data":{"project":null}}`}, nil)
	res, err := app.handleListComplianceViolations(context.Background(), callTool(map[string]any{
		"group_path": "acme", "project_path": "acme/missing",
	}))
	if msg := errorText(t, res, err); msg != "Project 'acme/missing' not found" {
		t.Errorf("message = %q", msg)
	}
	if n := len(fake.graphQLCalls()); n != 1 {
		t.Errorf("requests = %d, want only the project lookup", n)
	}
}

func TestListComplianceViolations_NullGroupIsNotFound(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"group":null}}`)
	res, err := app.handleListComplianceViolations(context.Background(), callTool(map[string]any{"group_path": "acme/missing"}))
	if msg := errorText(t, res, err); msg != "Group 'acme/missing' not found" {
		t.Errorf("message = %q", msg)
	}
}

func TestListComplianceViolations_NullViolationsIsExplained(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"group":{"projectComplianceViolations":null}}}`)
	res, err := app.handleListComplianceViolations(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	want := "Group 'acme' has no compliance violation data available (not licensed or not permitted)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

func TestGetSecurityScannerCoverage_ComputesPercent(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"group":{"analyzerStatuses":[
	  {"analyzerType":"SAST","success":20196,"failure":13,"notConfigured":11547,"stale":2502,"totalProjectsCount":34258},
	  {"analyzerType":"DAST","success":0,"failure":0,"notConfigured":0,"stale":0,"totalProjectsCount":0}]}}}`)
	res, err := app.handleGetSecurityScannerCoverage(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	var out struct {
		Group     string
		Analyzers []struct {
			AnalyzerType    string
			NotConfigured   int
			CoveragePercent float64
		}
	}
	if err := json.Unmarshal([]byte(resultText(t, res, err)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Group != "acme" {
		t.Errorf("group = %q, want acme", out.Group)
	}
	if len(out.Analyzers) != 2 || out.Analyzers[0].CoveragePercent != 58.95 || out.Analyzers[0].NotConfigured != 11547 {
		t.Errorf("analyzers = %+v", out.Analyzers)
	}
	if out.Analyzers[1].CoveragePercent != 0 {
		t.Errorf("with no projects the percentage must be 0, got %v", out.Analyzers[1].CoveragePercent)
	}
}

func TestGetSecurityScannerCoverage_NullGroupIsNotFound(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"group":null}}`)
	res, err := app.handleGetSecurityScannerCoverage(context.Background(), callTool(map[string]any{"group_path": "acme/missing"}))
	if msg := errorText(t, res, err); msg != "Group 'acme/missing' not found" {
		t.Errorf("message = %q", msg)
	}
}

func TestGetSecurityScannerCoverage_NullStatusesIsExplained(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"group":{"analyzerStatuses":null}}}`)
	res, err := app.handleGetSecurityScannerCoverage(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	want := "Group 'acme' has no scanner coverage data available (not licensed or not permitted)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

func TestGetSecurityScannerCoverage_RequiresGroupPath(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{}}`)
	res, err := app.handleGetSecurityScannerCoverage(context.Background(), callTool(map[string]any{}))
	if msg := errorText(t, res, err); msg != "group_path is required" {
		t.Errorf("message = %q", msg)
	}
	if n := len(fake.graphQLCalls()); n != 0 {
		t.Errorf("%d requests were sent before validation", n)
	}
}

func TestGetVulnerabilityTrend(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{"project":{"vulnerabilitiesCountByDay":{"nodes":[{"date":"2026-11-01","total":36}]}}}}`)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "start_date": "2026-11-01", "end_date": "2026-11-10",
	}))
	if text := resultText(t, res, err); !strings.Contains(text, `"total": 36`) {
		t.Errorf("result = %s", text)
	}
	vars := fake.lastCall(t).Variables
	if vars["startDate"] != "2026-11-01" || vars["endDate"] != "2026-11-10" {
		t.Errorf("variables = %v", vars)
	}

	res, err = app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "start_date": "2026-11-10", "end_date": "2026-11-01",
	}))
	if msg := errorText(t, res, err); msg != "start_date must be on or before end_date" {
		t.Errorf("message = %q", msg)
	}

	app, _ = newFakeGitLab(t, `{"errors":[{"message":"Request timed out. Please try a less complex query or a smaller set of records."}]}`)
	res, err = app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	if msg := errorText(t, res, err); msg != "get_vulnerability_trend: GitLab timed out. Use a shorter date range or a subgroup" {
		t.Errorf("message = %q", msg)
	}
}

func TestGetVulnerabilityTrend_DefaultsToLast30Days(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{"group":{"vulnerabilitiesCountByDay":{"nodes":[]}}}}`)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	resultText(t, res, err)
	vars := fake.lastCall(t).Variables
	end := time.Now().UTC().Format(dateLayout)
	start := time.Now().UTC().AddDate(0, 0, -30).Format(dateLayout)
	if vars["endDate"] != end || vars["startDate"] != start {
		t.Errorf("variables = %v, want %s..%s", vars, start, end)
	}
}

func TestGetVulnerabilityTrend_RejectsInvalidDates(t *testing.T) {
	for _, param := range []string{"start_date", "end_date"} {
		app, fake := newFakeGitLab(t, `{"data":{}}`)
		res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{
			"group_path": "acme", param: "11/01/2026",
		}))
		if msg := errorText(t, res, err); msg != param+" must be YYYY-MM-DD" {
			t.Errorf("message = %q", msg)
		}
		if n := len(fake.graphQLCalls()); n != 0 {
			t.Errorf("%s: %d requests were sent before validation", param, n)
		}
	}
}

func TestGetVulnerabilityTrend_NullRootAndNullHistory(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"project":null}}`)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{"project_path": "acme/missing"}))
	if msg := errorText(t, res, err); msg != "Project 'acme/missing' not found" {
		t.Errorf("message = %q", msg)
	}

	app, _ = newFakeGitLab(t, `{"data":{"group":{"vulnerabilitiesCountByDay":null}}}`)
	res, err = app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	want := "Group 'acme' has no vulnerability history available (not licensed or not permitted)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

const trendPage1 = `{"data":{"project":{"vulnerabilitiesCountByDay":{"nodes":[{"date":"2026-11-01","total":1},{"date":"2026-11-02","total":2}],
  "pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}}}`

const trendPage2 = `{"data":{"project":{"vulnerabilitiesCountByDay":{"nodes":[{"date":"2026-11-03","total":3}],
  "pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`

func TestGetVulnerabilityTrend_FollowsPages(t *testing.T) {
	app, fake := newScriptedGitLab(t, []string{trendPage1, trendPage2}, nil)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "start_date": "2026-11-01", "end_date": "2026-11-03",
	}))
	var out struct {
		Days []struct {
			Date  string
			Total int
		}
	}
	if err := json.Unmarshal([]byte(resultText(t, res, err)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Days) != 3 || out.Days[0].Date != "2026-11-01" || out.Days[2].Date != "2026-11-03" || out.Days[2].Total != 3 {
		t.Errorf("days = %+v", out.Days)
	}
	calls := fake.graphQLCalls()
	if len(calls) != 2 {
		t.Fatalf("requests = %d, want 2", len(calls))
	}
	if calls[0].Variables["first"] != float64(100) {
		t.Errorf("first = %v, want 100", calls[0].Variables["first"])
	}
	if _, present := calls[0].Variables["after"]; present {
		t.Errorf("the first page must not send after")
	}
	if calls[1].Variables["after"] != "c1" {
		t.Errorf("second page after = %v, want c1", calls[1].Variables["after"])
	}
	for _, want := range []string{"first: $first", "after: $after", "pageInfo { hasNextPage endCursor }"} {
		if !strings.Contains(calls[0].Query, want) {
			t.Errorf("query lacks %q", want)
		}
	}
}

func TestGetVulnerabilityTrend_PageCapIsAnError(t *testing.T) {
	app, fake := newFakeGitLab(t, trendPage1)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{"project_path": "acme/app"}))
	want := "get_vulnerability_trend: more than 500 days returned; use a shorter range"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
	if n := len(fake.graphQLCalls()); n != 5 {
		t.Errorf("requests = %d, want 5", n)
	}
}

func TestGetVulnerabilityTrend_NoNodesIsEmptyArray(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"group":{"vulnerabilitiesCountByDay":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	if text := resultText(t, res, err); !strings.Contains(text, `"days": []`) {
		t.Errorf("result = %s", text)
	}
}

func TestGetVulnerabilityTrend_EndDateAloneDefaultsStart(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{"group":{"vulnerabilitiesCountByDay":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{
		"group_path": "acme", "end_date": "2026-01-15",
	}))
	resultText(t, res, err)
	vars := fake.lastCall(t).Variables
	if vars["startDate"] != "2025-12-16" || vars["endDate"] != "2026-01-15" {
		t.Errorf("variables = %v, want 2025-12-16..2026-01-15", vars)
	}
}

func TestIsGitLabTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"graphql message", errors.New("Request timed out. Please try a less complex query"), true},
		{"context deadline", fmt.Errorf("execute request: %w", context.DeadlineExceeded), true},
		{"client timeout text", errors.New(`execute request: Post "x": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`), true},
		{"502", errors.New("GitLab API 502: bad gateway"), true},
		{"504", errors.New("GitLab API 504: gateway timeout"), true},
		{"connect failure", errors.New("execute request: dial tcp: connect: connection refused"), false},
		{"500", errors.New("GitLab API 500: boom"), false},
	} {
		if got := isGitLabTimeout(tc.err); got != tc.want {
			t.Errorf("%s: isGitLabTimeout = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGetVulnerabilityTrend_UnmappedErrorKeepsPrefix(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"errors":[{"message":"connect: refused"}]}`)
	res, err := app.handleGetVulnerabilityTrend(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	msg := errorText(t, res, err)
	if strings.Contains(msg, "timed out") || !strings.Contains(msg, "connect: refused") {
		t.Errorf("message = %q", msg)
	}
}
