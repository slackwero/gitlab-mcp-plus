package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	fakeGraphQLPath = "/api/graphql"
	fakeRESTPrefix  = "/api/v4"
)

// fakeNotFound is what the fake GitLab answers to a REST route it has no script for.
var fakeNotFound = fakeResponse{status: http.StatusNotFound, body: `{"message":"404 Not Found"}`}

// graphQLCall is a GraphQL request as the fake GitLab received it.
type graphQLCall struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// restCall is a REST request as the fake GitLab received it. Path is the
// escaped path without the /api/v4 prefix, so "%2F" in a project path stays
// visible.
type restCall struct {
	Method, Path string
	Query        url.Values
	Body         map[string]any
}

// fakeResponse is a scripted answer; status 0 means 200.
type fakeResponse struct {
	status int
	body   string
}

// fakeGitLab answers GraphQL requests from a script, in order, and REST
// requests from a route table. It records every request so tests can check
// what each tool sent.
type fakeGitLab struct {
	graphQLResponses []string
	restRoutes       map[string]fakeResponse

	mu         sync.Mutex
	graphQLLog []graphQLCall
	restLog    []restCall
}

// newScriptedGitLab starts a fake GitLab. The i-th GraphQL request receives
// graphQL[i] and the last response repeats once the script runs out. A REST
// request is answered by routes["METHOD /path"], or with a 404 when the route
// is not scripted.
func newScriptedGitLab(t *testing.T, graphQL []string, routes map[string]fakeResponse) (*App, *fakeGitLab) {
	t.Helper()
	fake := &fakeGitLab{graphQLResponses: graphQL, restRoutes: routes}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.serve(t, w, r)
	}))
	t.Cleanup(srv.Close)
	return NewApp("test-token", srv.URL), fake
}

// newFakeGitLab answers every GraphQL request with the same response.
func newFakeGitLab(t *testing.T, response string) (*App, *fakeGitLab) {
	t.Helper()
	return newScriptedGitLab(t, []string{response}, nil)
}

func (f *fakeGitLab) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("reading the body: %v", err)
	}

	var resp fakeResponse
	path := r.URL.EscapedPath()
	switch {
	case r.Method == http.MethodPost && path == fakeGraphQLPath:
		resp = f.serveGraphQL(t, raw)
	case strings.HasPrefix(path, fakeRESTPrefix+"/"):
		resp = f.serveREST(t, r, strings.TrimPrefix(path, fakeRESTPrefix), raw)
	default:
		t.Errorf("unexpected request to the fake GitLab: %s %s", r.Method, r.URL)
		resp = fakeNotFound
	}

	status := resp.status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, resp.body)
}

func (f *fakeGitLab) serveGraphQL(t *testing.T, raw []byte) fakeResponse {
	var call graphQLCall
	if err := json.Unmarshal(raw, &call); err != nil {
		t.Errorf("invalid GraphQL body: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.graphQLLog = append(f.graphQLLog, call)
	if len(f.graphQLResponses) == 0 {
		t.Errorf("unexpected GraphQL request, the test scripted none: %s", call.Query)
		return fakeResponse{status: http.StatusInternalServerError, body: `{"message":"no scripted GraphQL response"}`}
	}
	i := min(len(f.graphQLLog), len(f.graphQLResponses)) - 1
	return fakeResponse{body: f.graphQLResponses[i]}
}

func (f *fakeGitLab) serveREST(t *testing.T, r *http.Request, path string, raw []byte) fakeResponse {
	call := restCall{Method: r.Method, Path: path, Query: r.URL.Query()}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &call.Body); err != nil {
			t.Errorf("invalid REST body: %v", err)
		}
	}

	f.mu.Lock()
	f.restLog = append(f.restLog, call)
	f.mu.Unlock()

	if resp, ok := f.restRoutes[r.Method+" "+path]; ok {
		return resp
	}
	return fakeNotFound
}

// graphQLCalls returns the GraphQL requests received so far, in order.
func (f *fakeGitLab) graphQLCalls() []graphQLCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.graphQLLog)
}

// restCalls returns the REST requests received so far, in order.
func (f *fakeGitLab) restCalls() []restCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.restLog)
}

func (f *fakeGitLab) lastCall(t *testing.T) graphQLCall {
	t.Helper()
	calls := f.graphQLCalls()
	if len(calls) == 0 {
		t.Fatal("the tool sent no GraphQL request")
	}
	return calls[len(calls)-1]
}

func callTool(args map[string]any) mcp.CallToolRequest {
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return req
}

// resultText returns the result text and fails if the tool reported an error.
func resultText(t *testing.T, res *mcp.CallToolResult, err error) string {
	t.Helper()
	text := contentText(t, res, err)
	if res.IsError {
		t.Fatalf("the tool reported an error: %s", text)
	}
	return text
}

// errorText returns the error message and fails if the tool did not report an
// error.
func errorText(t *testing.T, res *mcp.CallToolResult, err error) string {
	t.Helper()
	text := contentText(t, res, err)
	if !res.IsError {
		t.Fatalf("the tool did not report an error, result: %s", text)
	}
	return text
}

// contentText returns the text of the first content block of a tool result.
func contentText(t *testing.T, res *mcp.CallToolResult, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("the handler returned an error: %v", err)
	}
	if res == nil {
		t.Fatal("the handler returned no result")
	}
	if len(res.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type: %T", res.Content[0])
	}
	return text.Text
}

// fieldArgs returns the text of the arguments the GraphQL document passes to a
// field, that is, whatever sits between "field(" and its closing parenthesis.
func fieldArgs(t *testing.T, query, field string) string {
	t.Helper()
	start := strings.Index(query, field+"(")
	if start < 0 {
		return ""
	}
	rest := query[start+len(field)+1:]
	end := strings.Index(rest, ")")
	if end < 0 {
		t.Fatalf("unterminated arguments for %s", field)
	}
	return rest[:end]
}

// registeredTools starts the real MCP server and asks it for tools/list, so
// tests see exactly what a client sees.
func registeredTools(t *testing.T) map[string]mcp.Tool {
	t.Helper()
	s := server.NewMCPServer("gitlab-mcp-plus", "test")
	NewApp("test-token", "http://gitlab.invalid").registerTools(s)

	msg := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	raw, err := json.Marshal(s.HandleMessage(context.Background(), msg))
	if err != nil {
		t.Fatalf("marshaling tools/list: %v", err)
	}
	var resp struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("invalid tools/list response: %v", err)
	}
	tools := make(map[string]mcp.Tool, len(resp.Result.Tools))
	for _, tool := range resp.Result.Tools {
		tools[tool.Name] = tool
	}
	return tools
}

const vulnerabilitiesResponse = `{"data":{"%s":{
  "vulnerabilitySeveritiesCount":{"critical":2,"high":3,"medium":0,"low":0,"info":0,"unknown":0},
  "vulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`

func TestListVulnerabilities_SortUsesGitLabEnumCase(t *testing.T) {
	// VulnerabilitySort is one of GitLab's few lowercase enums: sending
	// SEVERITY_DESC makes the API reject the whole request.
	tests := []struct {
		name string
		sort string
		want string
	}{
		{"value as the tool advertises it", "detected_desc", "detected_desc"},
		{"uppercase sent by the client", "SEVERITY_ASC", "severity_asc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, fake := newFakeGitLab(t, strings.Replace(vulnerabilitiesResponse, "%s", "project", 1))

			res, err := app.handleListVulnerabilities(context.Background(), callTool(map[string]any{
				"project_path": "group/project",
				"sort":         tt.sort,
			}))
			resultText(t, res, err)

			if got := fake.lastCall(t).Variables["sort"]; got != tt.want {
				t.Errorf("sort variable = %v, want %q", got, tt.want)
			}
		})
	}
}

func TestListVulnerabilities_ReportTypeEnumMatchesGitLab(t *testing.T) {
	// Literal list of VulnerabilityReportType in the gitlab.com schema.
	// Advertising a value GitLab does not know (formerly SAST_ADVANCED) makes
	// the query fail; omitting one prevents filtering by that type.
	want := []string{
		"SAST", "DEPENDENCY_SCANNING", "CONTAINER_SCANNING", "DAST",
		"SECRET_DETECTION", "COVERAGE_FUZZING", "API_FUZZING",
		"CLUSTER_IMAGE_SCANNING", "CONTAINER_SCANNING_FOR_REGISTRY",
		"SARIF", "GENERIC",
	}

	tool, ok := registeredTools(t)["list_vulnerabilities"]
	if !ok {
		t.Fatal("list_vulnerabilities is not registered")
	}
	prop, _ := tool.InputSchema.Properties["report_type"].(map[string]any)
	items, _ := prop["items"].(map[string]any)
	rawEnum, _ := items["enum"].([]any)

	got := make(map[string]bool, len(rawEnum))
	for _, v := range rawEnum {
		got[v.(string)] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("report type %q is missing", w)
		}
		delete(got, w)
	}
	for extra := range got {
		t.Errorf("report type %q does not exist in GitLab", extra)
	}
}

func TestListVulnerabilities_CountsHonorFilters(t *testing.T) {
	// totalCount and severityCounts must describe the same set as nodes: if
	// the count does not receive the filters, it returns the total for the
	// whole project or group.
	filters := []string{"$severity", "$state", "$reportType", "$scanner", "$hasIssues", "$hasResolution",
		"$identifierName", "$hasMergeRequest", "$hasAiResolution", "$hasRemediations", "$dismissalReason"}

	for _, scope := range []string{"project", "group"} {
		t.Run(scope, func(t *testing.T) {
			app, fake := newFakeGitLab(t, strings.Replace(vulnerabilitiesResponse, "%s", scope, 1))

			res, err := app.handleListVulnerabilities(context.Background(), callTool(map[string]any{
				scope + "_path": "group/project",
				"severity":      []any{"CRITICAL", "HIGH"},
				"state":         []any{"DETECTED"},
			}))
			text := resultText(t, res, err)

			query := fake.lastCall(t).Query
			for _, field := range []string{"vulnerabilitySeveritiesCount", "vulnerabilities"} {
				args := fieldArgs(t, query, field)
				for _, f := range filters {
					if !strings.Contains(args, f) {
						t.Errorf("%s does not receive the %s filter (args: %q)", field, f, args)
					}
				}
			}

			var out struct {
				TotalCount int `json:"totalCount"`
			}
			if err := json.Unmarshal([]byte(text), &out); err != nil {
				t.Fatalf("result is not JSON: %v", err)
			}
			if out.TotalCount != 5 {
				t.Errorf("totalCount = %d, want 5 (2 critical + 3 high)", out.TotalCount)
			}
		})
	}
}

func TestListVulnerabilities_ForwardsNewFilters(t *testing.T) {
	app, fake := newFakeGitLab(t, strings.Replace(vulnerabilitiesResponse, "%s", "project", 1))
	res, err := app.handleListVulnerabilities(context.Background(), callTool(map[string]any{
		"project_path":      "group/project",
		"identifier_name":   "CVE-2026-1234",
		"has_merge_request": false,
		"has_ai_resolution": true,
		"dismissal_reason":  []any{"FALSE_POSITIVE"},
	}))
	resultText(t, res, err)

	vars := fake.lastCall(t).Variables
	want := map[string]any{
		"identifierName": "CVE-2026-1234", "hasMergeRequest": false, "hasAiResolution": true,
		"dismissalReason": []any{"FALSE_POSITIVE"},
	}
	for k, w := range want {
		if !reflect.DeepEqual(vars[k], w) {
			t.Errorf("variable %s = %v, want %v", k, vars[k], w)
		}
	}
	if _, present := vars["hasRemediations"]; present {
		t.Errorf("hasRemediations was not requested and must not be sent")
	}
}

func TestGetVulnerability_ShowsWhenConnectionsAreTruncated(t *testing.T) {
	// The document reads only the first 10 merge requests and severity
	// overrides: hasNextPage tells the client that there are more.
	app, fake := newFakeGitLab(t, `{"data":{"vulnerability":{"id":"gid://gitlab/Vulnerability/7",
	  "mergeRequests":{"nodes":[],"pageInfo":{"hasNextPage":true}},
	  "severityOverrides":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}`)
	res, err := app.handleGetVulnerability(context.Background(), callTool(map[string]any{"id": "7"}))
	if text := resultText(t, res, err); !strings.Contains(text, `"hasNextPage": true`) {
		t.Errorf("result = %s", text)
	}

	query := strings.Join(strings.Fields(fake.lastCall(t).Query), " ")
	for _, want := range []string{
		"mergeRequests(first: 10) { nodes { iid title state webUrl } pageInfo { hasNextPage } }",
		"severityOverrides(first: 10) { nodes { originalSeverity newSeverity createdAt author { username } } pageInfo { hasNextPage } }",
	} {
		if !strings.Contains(query, want) {
			t.Errorf("query lacks %q", want)
		}
	}
}

func TestListPipelineSecurityFindings_ForwardsFilters(t *testing.T) {
	// The tool advertises report_type and severity: if they do not reach the
	// query, the client believes it is filtering and receives every finding.
	const response = `{"data":{"project":{"pipeline":{"securityReportFindings":{
      "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}}`
	app, fake := newFakeGitLab(t, response)

	res, err := app.handleListPipelineSecurityFindings(context.Background(), callTool(map[string]any{
		"project_path": "group/project",
		"pipeline_iid": "42",
		"report_type":  []any{"SAST", "dependency_scanning"},
		"severity":     []any{"CRITICAL", "high"},
	}))
	resultText(t, res, err)

	call := fake.lastCall(t)
	// GitLab expects both filters in lowercase and rejects unknown severities.
	wantReportType := []any{"sast", "dependency_scanning"}
	if got := call.Variables["reportType"]; !reflect.DeepEqual(got, wantReportType) {
		t.Errorf("reportType variable = %v, want %v", got, wantReportType)
	}
	wantSeverity := []any{"critical", "high"}
	if got := call.Variables["severity"]; !reflect.DeepEqual(got, wantSeverity) {
		t.Errorf("severity variable = %v, want %v", got, wantSeverity)
	}

	args := fieldArgs(t, call.Query, "securityReportFindings")
	for _, f := range []string{"$reportType", "$severity"} {
		if !strings.Contains(args, f) {
			t.Errorf("securityReportFindings does not receive the %s filter (args: %q)", f, args)
		}
	}
}

func TestListGroupProjects_ArchivedFilter(t *testing.T) {
	// Group.projects includes archived projects by default (includeArchived
	// is true): excluding them requires includeArchived=false;
	// archivedOnly=false excludes nothing.
	const response = `{"data":{"group":{"projects":{
      "nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`

	tests := []struct {
		name                string
		args                map[string]any
		wantIncludeArchived any
		wantArchivedOnly    any
	}{
		{"EXCLUDE excludes archived projects", map[string]any{"archived": "EXCLUDE"}, false, nil},
		{"archived_only=false excludes archived projects", map[string]any{"archived_only": false}, false, nil},
		{"ONLY returns archived projects only", map[string]any{"archived": "ONLY"}, nil, true},
		{"archived_only=true returns archived projects only", map[string]any{"archived_only": true}, nil, true},
		{"INCLUDE does not filter", map[string]any{"archived": "INCLUDE"}, nil, nil},
		{"no filter sends nothing", map[string]any{}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, fake := newFakeGitLab(t, response)
			tt.args["group_path"] = "group"

			res, err := app.handleListGroupProjects(context.Background(), callTool(tt.args))
			resultText(t, res, err)

			call := fake.lastCall(t)
			if got := call.Variables["includeArchived"]; got != tt.wantIncludeArchived {
				t.Errorf("includeArchived variable = %v, want %v", got, tt.wantIncludeArchived)
			}
			if got := call.Variables["archivedOnly"]; got != tt.wantArchivedOnly {
				t.Errorf("archivedOnly variable = %v, want %v", got, tt.wantArchivedOnly)
			}
			if args := fieldArgs(t, call.Query, "projects"); !strings.Contains(args, "$includeArchived") {
				t.Errorf("projects does not receive $includeArchived (args: %q)", args)
			}
		})
	}
}

func TestGetDuoAIMetrics_FiltersCodeSuggestionsInGitLab(t *testing.T) {
	// GitLab must apply the IDE or language filter: trimming the ideNames
	// list on the client leaves the counters unfiltered.
	const response = `{"data":{"group":{"id":"gid://gitlab/Group/1","aiMetrics":{
      "duoChatContributorsCount":4,"duoUsedCount":9,"rootCauseAnalysisUsersCount":1,
      "codeReview":{},
      "codeSuggestions":{"contributorsCount":3,"shownCount":200,"acceptedCount":50,
        "languages":["go"],"acceptedLinesOfCode":80,"shownLinesOfCode":400,"ideNames":["VS Code"]},
      "agentPlatformChats":{"createdSessionEventCount":7,"flowMetrics":[]},
      "agentPlatformFlows":{"createdSessionEventCount":2}}}}}`
	app, fake := newFakeGitLab(t, response)

	res, err := app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"group_path": "group",
		"start_date": "2026-10-01",
		"end_date":   "2026-10-31",
		"ide_names":  []any{"VS Code"},
		"languages":  []any{"go", "python"},
	}))
	text := resultText(t, res, err)

	call := fake.lastCall(t)
	if got, want := call.Variables["ideNames"], []any{"VS Code"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ideNames variable = %v, want %v", got, want)
	}
	if got, want := call.Variables["languages"], []any{"go", "python"}; !reflect.DeepEqual(got, want) {
		t.Errorf("languages variable = %v, want %v", got, want)
	}
	args := fieldArgs(t, call.Query, "codeSuggestions")
	for _, f := range []string{"$ideNames", "$languages"} {
		if !strings.Contains(args, f) {
			t.Errorf("codeSuggestions does not receive the %s filter (args: %q)", f, args)
		}
	}

	var out struct {
		CodeSuggestions struct {
			AcceptanceRate float64  `json:"acceptanceRate"`
			IDENames       []string `json:"ideNames"`
		} `json:"codeSuggestions"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	if out.CodeSuggestions.AcceptanceRate != 25 {
		t.Errorf("acceptanceRate = %v, want 25 (50 out of 200)", out.CodeSuggestions.AcceptanceRate)
	}
	if want := []string{"VS Code"}; !reflect.DeepEqual(out.CodeSuggestions.IDENames, want) {
		t.Errorf("ideNames = %v, want %v", out.CodeSuggestions.IDENames, want)
	}
}

func TestGetDuoAIMetrics_WithoutFiltersSendsNone(t *testing.T) {
	// Without ide_names or languages the request must not carry those
	// filters: an empty list is not the same as "no filter".
	const response = `{"data":{"group":{"id":"gid://gitlab/Group/1","aiMetrics":{
      "codeReview":{},"codeSuggestions":{},"agentPlatformChats":{},"agentPlatformFlows":{}}}}}`
	app, fake := newFakeGitLab(t, response)

	res, err := app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"group_path": "group",
		"start_date": "2026-10-01",
		"end_date":   "2026-10-31",
	}))
	resultText(t, res, err)

	vars := fake.lastCall(t).Variables
	for _, key := range []string{"ideNames", "languages"} {
		if v, present := vars[key]; present {
			t.Errorf("%s variable = %v, it must not be sent", key, v)
		}
	}
}

func TestTools_DeclareSafetyAnnotations(t *testing.T) {
	// MCP clients use these annotations to decide what they may run without
	// confirmation. A read tool without readOnlyHint is treated as a
	// destructive write; a write tool marked readOnly would run without
	// asking. Every new tool must be classified here.
	type hints struct{ readOnly, destructive bool }
	read := hints{readOnly: true, destructive: false}
	additive := hints{readOnly: false, destructive: false}
	stateChange := hints{readOnly: false, destructive: true}

	want := map[string]hints{
		"list_vulnerabilities":              read,
		"get_vulnerability":                 read,
		"get_vulnerability_statistics":      read,
		"list_pipeline_security_findings":   read,
		"list_vulnerability_scanners":       read,
		"list_security_policies":            read,
		"list_scan_execution_policies":      read,
		"list_compliance_frameworks":        read,
		"get_duo_ai_metrics":                read,
		"list_duo_user_metrics":             read,
		"get_duo_seat_usage":                read,
		"list_duo_seat_users":               read,
		"get_gitlab_credits_usage":          read,
		"get_ai_governance_metrics":         read,
		"list_ai_governance_sessions":       read,
		"get_ai_governance_session":         read,
		"list_ai_catalog_items":             read,
		"list_ai_flow_triggers":             read,
		"list_dependencies":                 read,
		"list_compliance_violations":        read,
		"get_security_scanner_coverage":     read,
		"get_vulnerability_trend":           read,
		"get_group":                         read,
		"list_groups":                       read,
		"list_descendant_groups":            read,
		"list_group_projects":               read,
		"list_group_members":                read,
		"list_group_audit_events":           read,
		"list_group_merge_requests":         read,
		"vulnerability_confirm":             stateChange,
		"vulnerability_dismiss":             stateChange,
		"vulnerability_resolve":             stateChange,
		"vulnerability_revert_to_detected":  stateChange,
		"create_project":                    additive,
		"create_group":                      additive,
		"fork_project":                      additive,
		"delete_branch":                     stateChange,
		"vulnerabilities_bulk_dismiss":      stateChange,
		"vulnerabilities_override_severity": stateChange,
		"vulnerabilities_link_issue":        additive,
		"vulnerabilities_set_due_date":      stateChange,
		"start_vulnerability_workflow":      stateChange,
		"get_vulnerability_workflow":        read,
		"cancel_vulnerability_workflow":     stateChange,
	}

	tools := registeredTools(t)
	for name, tool := range tools {
		w, ok := want[name]
		if !ok {
			t.Errorf("tool %q is not classified: add it to this test as a read or write tool", name)
			continue
		}
		ann := tool.Annotations
		if ann.ReadOnlyHint == nil || *ann.ReadOnlyHint != w.readOnly {
			t.Errorf("%s: readOnlyHint = %v, want %v", name, deref(ann.ReadOnlyHint), w.readOnly)
		}
		if ann.DestructiveHint == nil || *ann.DestructiveHint != w.destructive {
			t.Errorf("%s: destructiveHint = %v, want %v", name, deref(ann.DestructiveHint), w.destructive)
		}
	}
	for name := range want {
		if _, ok := tools[name]; !ok {
			t.Errorf("tool %q is expected but not registered", name)
		}
	}
}

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func TestBuildAIDashboard_NewSections(t *testing.T) {
	var metrics map[string]any
	fixture := `{"codeContributorsCount":2028,
	  "chat":{"requestDuoChatResponseEventCount":368,"completeDuoChatResponseEventCount":580,
	          "toolSucceededDuoChatEventCount":12641,"toolFailedDuoChatEventCount":654},
	  "mcp":{"startMcpToolCallEventCount":52120,"finishMcpToolCallEventCount":52119},
	  "troubleshoot":{"troubleshootJobEventCount":17},
	  "codeReview":{"publishDuoCodeReviewCommentsEventCount":5,"approveMergeRequestDuoCodeReviewEventCount":3,
	          "findNoIssuesDuoCodeReviewAfterReviewEventCount":2151,"encounterDuoCodeReviewErrorDuringReviewEventCount":308},
	  "codeSuggestions":{},
	  "agentPlatformChats":{"createdSessionEventCount":1103},
	  "agentPlatformFlows":{"createdSessionEventCount":2500},
	  "agentPlatform":{"createdSessionEventCount":3603,"startedSessionEventCount":3500,"finishedSessionEventCount":3000,
	          "droppedSessionEventCount":40,"stoppedSessionEventCount":60,"resumedSessionEventCount":7,
	          "flowMetrics":[{"flowType":"chat","sessionsCount":1103,"usersCount":314,"completionRate":91.5,"medianExecutionTime":12.3}]}}`
	if err := json.Unmarshal([]byte(fixture), &metrics); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(buildAIDashboard(metrics, ""))
	var got struct {
		Summary       struct{ CodeContributorsCount int }
		Chat          struct{ RequestCount, ResponseCount, ToolSucceededCount, ToolFailedCount int }
		MCP           struct{ ToolCallsStarted, ToolCallsFinished int } `json:"mcp"`
		Troubleshoot  struct{ JobCount int }
		CodeReview    struct{ CommentsPublishedCount, ApprovalsCount, NoIssuesFoundCount, ErrorCount int }
		AgentPlatform map[string]json.RawMessage
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.CodeContributorsCount != 2028 || got.Chat.RequestCount != 368 || got.Chat.ResponseCount != 580 ||
		got.Chat.ToolSucceededCount != 12641 || got.Chat.ToolFailedCount != 654 {
		t.Errorf("summary/chat = %+v %+v", got.Summary, got.Chat)
	}
	if got.MCP.ToolCallsStarted != 52120 || got.MCP.ToolCallsFinished != 52119 || got.Troubleshoot.JobCount != 17 {
		t.Errorf("mcp/troubleshoot = %+v %+v", got.MCP, got.Troubleshoot)
	}
	if got.CodeReview.CommentsPublishedCount != 5 || got.CodeReview.ApprovalsCount != 3 ||
		got.CodeReview.NoIssuesFoundCount != 2151 || got.CodeReview.ErrorCount != 308 {
		t.Errorf("codeReview = %+v", got.CodeReview)
	}
	var sessions struct{ Created, Started, Finished, Dropped, Stopped, Resumed int }
	if err := json.Unmarshal(got.AgentPlatform["sessions"], &sessions); err != nil {
		t.Fatal(err)
	}
	if sessions.Created != 3603 || sessions.Started != 3500 || sessions.Finished != 3000 ||
		sessions.Dropped != 40 || sessions.Stopped != 60 || sessions.Resumed != 7 {
		t.Errorf("sessions = %+v", sessions)
	}
	if _, old := got.AgentPlatform["chatFlowMetrics"]; old {
		t.Errorf("chatFlowMetrics must be replaced by flowMetrics")
	}
	if !strings.Contains(string(got.AgentPlatform["flowMetrics"]), `"completionRate":91.5`) {
		t.Errorf("flowMetrics = %s", got.AgentPlatform["flowMetrics"])
	}
}

func TestGetDuoAIMetrics_ProjectScope(t *testing.T) {
	const response = `{"data":{"project":{"id":"gid://gitlab/Project/1","aiMetrics":{
	  "duoUsedCount":4,"codeReview":{},"codeSuggestions":{},"agentPlatformChats":{},"agentPlatformFlows":{},"agentPlatform":{}}}}}`
	app, fake := newFakeGitLab(t, response)
	res, err := app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "start_date": "2026-10-01", "end_date": "2026-10-31",
	}))
	text := resultText(t, res, err)
	call := fake.lastCall(t)
	if !strings.Contains(call.Query, "project(fullPath: $fullPath)") || call.Variables["fullPath"] != "acme/app" {
		t.Errorf("query does not use the project scope: vars = %v", call.Variables)
	}
	if !strings.Contains(text, `"project": "acme/app"`) || strings.Contains(text, `"group"`) {
		t.Errorf("result = %s", text)
	}

	res, err = app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "group_path": "acme",
	}))
	if msg := errorText(t, res, err); msg != "provide either project_path or group_path, not both" {
		t.Errorf("message = %q", msg)
	}
}

func TestGetDuoAIMetrics_RequiresScope(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{}}`)
	res, err := app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"start_date": "2026-10-01", "end_date": "2026-10-31",
	}))
	if msg := errorText(t, res, err); msg != "either project_path or group_path is required" {
		t.Errorf("message = %q", msg)
	}
	if calls := fake.graphQLCalls(); len(calls) != 0 {
		t.Errorf("GitLab was called %d times without a scope", len(calls))
	}
}

func TestGetDuoAIMetrics_NullProjectRootIsPlainNotFound(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"project":null}}`)
	res, err := app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"project_path": "acme/ghost", "start_date": "2026-10-01", "end_date": "2026-10-31",
	}))
	if msg := errorText(t, res, err); msg != "Project 'acme/ghost' not found" {
		t.Errorf("message = %q", msg)
	}
}

func TestGetDuoAIMetrics_NullMetricsIsNotZeroUsage(t *testing.T) {
	const want = "Project 'acme/app' has no Duo metrics available (not licensed or not permitted)"
	app, fake := newFakeGitLab(t, `{"data":{"project":{"id":"gid://gitlab/Project/1","aiMetrics":null}}}`)
	res, err := app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "start_date": "2026-10-01", "end_date": "2026-10-31",
	}))
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}

	// With several periods the first one that hits the null ends the call.
	app, fake = newFakeGitLab(t, `{"data":{"project":{"id":"gid://gitlab/Project/1","aiMetrics":null}}}`)
	res, err = app.handleGetDuoAIMetrics(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "start_date": "2026-10-01", "end_date": "2026-10-31", "periods": float64(3),
	}))
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("periods: message = %q, want %q", msg, want)
	}
	if n := len(fake.graphQLCalls()); n != 1 {
		t.Errorf("GraphQL calls = %d, want 1", n)
	}
}

func TestListSecurityPolicies_TypeAndYaml(t *testing.T) {
	const response = `{"data":{"group":{"securityPolicies":{"nodes":[{"name":"Required SAST","type":"Scan execution"}]}}}}`
	app, fake := newFakeGitLab(t, response)
	res, err := app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	resultText(t, res, err)
	vars := fake.lastCall(t).Variables
	if vars["withYaml"] != false || vars["relationship"] != "INHERITED" {
		t.Errorf("defaults: %v", vars)
	}
	if _, present := vars["type"]; present {
		t.Errorf("type must not be sent without policy_type")
	}

	res, err = app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{
		"group_path": "acme", "policy_type": "scan_execution_policy", "include_yaml": true, "relationship": "DESCENDANT",
	}))
	resultText(t, res, err)
	vars = fake.lastCall(t).Variables
	if vars["type"] != "SCAN_EXECUTION_POLICY" || vars["withYaml"] != true || vars["relationship"] != "DESCENDANT" {
		t.Errorf("variables = %v", vars)
	}

	res, err = app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{
		"group_path": "acme", "policy_type": "  ", "include_yaml": nil,
	}))
	resultText(t, res, err)
	vars = fake.lastCall(t).Variables
	if _, present := vars["type"]; present || vars["withYaml"] != false {
		t.Errorf("blank type and null include_yaml: %v", vars)
	}

	res, err = app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "relationship": "DESCENDANT",
	}))
	if msg := errorText(t, res, err); msg != "relationship DESCENDANT is only valid with group_path" {
		t.Errorf("message = %q", msg)
	}

	res, err = app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{
		"group_path": "acme", "include_yaml": "yes",
	}))
	if msg := errorText(t, res, err); msg != "include_yaml must be a boolean" {
		t.Errorf("message = %q", msg)
	}
}

func TestListSecurityPolicies_NullShapes(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"project":null}}`)
	res, err := app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{"project_path": "acme/app"}))
	if msg := errorText(t, res, err); msg != "Project 'acme/app' not found" {
		t.Errorf("null root: %q", msg)
	}

	app, _ = newFakeGitLab(t, `{"data":{"group":{"securityPolicies":null}}}`)
	res, err = app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	want := "Group 'acme' has no security policy data available (not licensed or not permitted)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("null securityPolicies: %q", msg)
	}
}

func TestListSecurityPolicies_RequestsPageInfo(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{"group":{"securityPolicies":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}}`)
	res, err := app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	if text := resultText(t, res, err); !strings.Contains(text, `"hasNextPage": true`) {
		t.Errorf("result = %s", text)
	}
	if q := fake.lastCall(t).Query; !strings.Contains(q, "pageInfo { hasNextPage }") {
		t.Errorf("query does not request pageInfo: %s", q)
	}
	if d := registeredTools(t)["list_security_policies"].Description; !strings.Contains(d, "pageInfo.hasNextPage is true when more policies exist") {
		t.Errorf("description lacks the truncation note: %s", d)
	}
}

func TestListSecurityPolicies_NormalizesRelationship(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{"project":{"securityPolicies":{"nodes":[]}}}}`)
	res, err := app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "relationship": " descendant ",
	}))
	if msg := errorText(t, res, err); msg != "relationship DESCENDANT is only valid with group_path" {
		t.Errorf("message = %q", msg)
	}
	if n := len(fake.graphQLCalls()); n != 0 {
		t.Errorf("%d requests were sent before validation", n)
	}

	app, fake = newFakeGitLab(t, `{"data":{"group":{"securityPolicies":{"nodes":[]}}}}`)
	res, err = app.handleListSecurityPolicies(context.Background(), callTool(map[string]any{
		"group_path": "acme", "relationship": " direct ",
	}))
	resultText(t, res, err)
	if got := fake.lastCall(t).Variables["relationship"]; got != "DIRECT" {
		t.Errorf("relationship = %v, want DIRECT", got)
	}
}
