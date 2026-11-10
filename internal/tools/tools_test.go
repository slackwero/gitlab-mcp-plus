package tools

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

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
