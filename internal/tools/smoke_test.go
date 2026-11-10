//go:build smoke

package tools

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/slackwero/gitlab-mcp-plus/internal/gitlab"
)

// Real GitLab targets of the smoke test, set with SMOKE_GROUP (a top-level
// group) and SMOKE_PROJECT (a project path); TestSmoke skips when either is
// missing. smokeProjectGroup is the project's parent group: group merge
// requests exclude subgroups, so only a group with projects of its own
// returns any.
var (
	smokeGroup        = os.Getenv("SMOKE_GROUP")
	smokeProject      = os.Getenv("SMOKE_PROJECT")
	smokeProjectGroup = path.Dir(smokeProject)
)

// smokeChainedTools are the tools the chained step of TestSmoke calls: it
// lists one vulnerability and feeds its ID to get_vulnerability, and lists one
// AI governance session and feeds its ID to get_ai_governance_session. They go
// through the same read-only guard as smokeCases.
var smokeChainedTools = []string{
	"list_vulnerabilities", "get_vulnerability",
	"list_ai_governance_sessions", "get_ai_governance_session",
}

// smokeSubgroupCases are the top-level-only tools called on a subgroup: GitLab
// has no seat or credits data there, so each call must come back as an error
// result. They go through the same read-only guard as smokeCases.
var smokeSubgroupCases = []struct {
	tool string
	args map[string]any
}{
	{"get_duo_seat_usage", map[string]any{"group_path": smokeProjectGroup}},
	{"get_gitlab_credits_usage", map[string]any{"group_path": smokeProjectGroup, "top_users": 2}},
}

// smokeWorkflowCase reads the latest SAST false positive detection run of
// smokeProject. A project that never ran the workflow answers with
// smokeNoWorkflowExecution, which also passes; any other error fails. It goes
// through the same read-only guard as smokeCases. The workflow start and
// cancel tools are never called here: a run consumes GitLab Credits and may
// create merge requests.
var smokeWorkflowCase = struct {
	tool string
	args map[string]any
}{"get_vulnerability_workflow", map[string]any{"project_path": smokeProject, "workflow": "SAST_FP_DETECTION_V1"}}

// smokeNoWorkflowExecution is the only error smokeWorkflowCase accepts.
var smokeNoWorkflowExecution = "No SAST_FP_DETECTION_V1 execution found for project '" + smokeProject + "'"

// smokeNoDuoData is the error the Duo metrics tools return when the scope
// exists but GitLab has no Duo data for it. A project without Duo data may
// end this way, so the two Duo project-scope cases (allowUnavailable) accept
// it and log which one it was.
const smokeNoDuoData = "available (not licensed or not permitted)"

// smokeDay returns the UTC day offset days from today as YYYY-MM-DD.
func smokeDay(offset int) string {
	return time.Now().UTC().AddDate(0, 0, offset).Format(dateLayout)
}

// smokeCase is one tool call of the smoke table. Only a case with
// allowUnavailable set may answer with smokeNoDuoData; every other case must
// succeed.
type smokeCase struct {
	tool             string
	args             map[string]any
	allowUnavailable bool
}

// smokeCases holds one call per read tool that needs no ID from a previous
// call. TestSmoke refuses any tool without readOnlyHint, so this table can
// never run a write against real GitLab.
var smokeCases = []smokeCase{
	{"list_vulnerabilities", map[string]any{"project_path": smokeProject, "first": 2}, false},
	{"list_vulnerabilities", map[string]any{"project_path": smokeProject, "first": 2, "has_merge_request": false}, false},
	{"get_vulnerability_statistics", map[string]any{"project_path": smokeProject}, false},
	{"list_vulnerability_scanners", map[string]any{"project_path": smokeProject}, false},
	{"list_security_policies", map[string]any{"group_path": smokeGroup}, false},
	{"list_security_policies", map[string]any{"group_path": smokeGroup, "policy_type": "SCAN_EXECUTION_POLICY", "include_yaml": true}, false},
	{"list_scan_execution_policies", map[string]any{"group_path": smokeGroup}, false},
	{"list_compliance_frameworks", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"get_duo_ai_metrics", map[string]any{"group_path": smokeGroup}, false},
	{"get_duo_ai_metrics", map[string]any{"project_path": smokeProject}, true},
	{"list_duo_user_metrics", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"list_duo_user_metrics", map[string]any{"project_path": smokeProject, "first": 2}, true},
	{"get_duo_seat_usage", map[string]any{"group_path": smokeGroup}, false},
	{"list_duo_seat_users", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"get_gitlab_credits_usage", map[string]any{"group_path": smokeGroup, "top_users": 2}, false},
	{"get_ai_governance_metrics", map[string]any{"group_path": smokeGroup, "top": 2}, false},
	{"list_ai_governance_sessions", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"list_ai_catalog_items", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"list_ai_flow_triggers", map[string]any{"project_path": smokeProject, "first": 2}, false},
	{"list_dependencies", map[string]any{"project_path": smokeProject, "first": 2}, false},
	{"list_compliance_violations", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"list_compliance_violations", map[string]any{"group_path": smokeGroup, "status": []string{"DETECTED"}, "created_after": smokeDay(-30), "project_path": smokeProject, "first": 2}, false},
	{"list_security_policies", map[string]any{"group_path": smokeProjectGroup, "relationship": "DESCENDANT"}, false},
	{"list_dependencies", map[string]any{"group_path": smokeProjectGroup, "sort": "SEVERITY_DESC", "package_managers": []string{"npm"}, "first": 2}, false},
	{"get_security_scanner_coverage", map[string]any{"group_path": smokeGroup}, false},
	// Not smokeGroup: GitLab times out on a long range of the top-level group.
	{"get_vulnerability_trend", map[string]any{"project_path": smokeProject}, false},
	{"get_vulnerability_trend", map[string]any{"group_path": smokeProjectGroup, "start_date": smokeDay(-1), "end_date": smokeDay(0)}, false},
	// 120 days: one page of 100 and a second one, so the cursor is sent to GitLab.
	{"get_vulnerability_trend", map[string]any{"project_path": smokeProject, "start_date": smokeDay(-119), "end_date": smokeDay(0)}, false},
	{"get_group", map[string]any{"group_path": smokeGroup}, false},
	{"list_groups", map[string]any{"search": smokeGroup, "first": 2}, false},
	{"list_descendant_groups", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"list_group_projects", map[string]any{"group_path": smokeGroup, "include_subgroups": true, "first": 2}, false},
	{"list_group_members", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"list_group_audit_events", map[string]any{"group_path": smokeGroup, "first": 2}, false},
	{"list_group_merge_requests", map[string]any{"group_path": smokeProjectGroup, "first": 2}, false},
}

// TestSmoke runs the read tools against real GitLab through the real MCP
// server, the same path a client takes, and fails on any tool error.
func TestSmoke(t *testing.T) {
	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		t.Skip("GITLAB_TOKEN is not set")
	}
	if smokeGroup == "" || smokeProject == "" {
		t.Skip("SMOKE_GROUP and SMOKE_PROJECT must name a real top-level group and project")
	}

	names := slices.Clone(smokeChainedTools)
	for _, c := range smokeCases {
		names = append(names, c.tool)
	}
	for _, c := range smokeSubgroupCases {
		names = append(names, c.tool)
	}
	names = append(names, smokeWorkflowCase.tool)
	tools := registeredTools(t)
	for _, name := range names {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("smoke case for an unregistered tool: %s", name)
		}
		if hint := tool.Annotations.ReadOnlyHint; hint == nil || !*hint {
			t.Fatalf("smoke only admits read tools: %s", name)
		}
	}

	s := server.NewMCPServer("gitlab-mcp-plus", "smoke")
	(&toolset{gl: gitlab.NewClient(token, os.Getenv("GITLAB_URL"))}).registerTools(s)

	for i, c := range smokeCases {
		t.Run(c.tool, func(t *testing.T) {
			res := callThroughServer(t, s, i+1, c.tool, c.args)
			text := contentText(t, res, nil)
			if res.IsError {
				if !c.allowUnavailable || !strings.Contains(text, smokeNoDuoData) {
					t.Fatalf("the tool reported an error: %s", text)
				}
				t.Logf("tolerated: %s: %s", c.tool, text)
				return
			}
			// Sizes only: results carry names and emails that do not belong in logs.
			t.Logf("%d bytes", len(text))
			var withDays struct {
				Days []json.RawMessage `json:"days"`
			}
			if json.Unmarshal([]byte(text), &withDays) == nil && withDays.Days != nil {
				t.Logf("%d days", len(withDays.Days))
			}
		})
	}

	for i, c := range smokeSubgroupCases {
		t.Run(c.tool+"_subgroup", func(t *testing.T) {
			res := callThroughServer(t, s, len(smokeCases)+3+i, c.tool, c.args)
			t.Logf("error text: %s", errorText(t, res, nil))
		})
	}

	t.Run(smokeWorkflowCase.tool, func(t *testing.T) {
		res := callThroughServer(t, s, len(smokeCases)+5, smokeWorkflowCase.tool, smokeWorkflowCase.args)
		text := contentText(t, res, nil)
		switch {
		case !res.IsError:
			// Sizes only, like the other read cases.
			t.Logf("%d bytes", len(text))
		case text == smokeNoWorkflowExecution:
			t.Logf("no execution: %s", text)
		default:
			t.Fatalf("the tool reported an error: %s", text)
		}
	})

	t.Run("get_vulnerability", func(t *testing.T) {
		id := firstVulnerabilityID(t, s, len(smokeCases)+1)
		if id == "" {
			t.Skipf("group %s has no vulnerability to feed get_vulnerability", smokeProjectGroup)
		}
		res := callThroughServer(t, s, len(smokeCases)+2, "get_vulnerability", map[string]any{"id": id})
		text := resultText(t, res, nil)
		t.Logf("%d bytes", len(text))
	})

	t.Run("get_ai_governance_session", func(t *testing.T) {
		listed := callThroughServer(t, s, len(smokeCases)+10, "list_ai_governance_sessions", map[string]any{"group_path": smokeGroup, "first": 1})
		var page struct {
			Nodes []struct {
				ID string `json:"id"`
			} `json:"nodes"`
		}
		if err := json.Unmarshal([]byte(resultText(t, listed, nil)), &page); err != nil {
			t.Fatalf("decoding the list_ai_governance_sessions result: %v", err)
		}
		if len(page.Nodes) == 0 {
			t.Skipf("group %s has no AI governance session to feed get_ai_governance_session", smokeGroup)
		}
		res := callThroughServer(t, s, len(smokeCases)+11, "get_ai_governance_session", map[string]any{"group_path": smokeGroup, "id": page.Nodes[0].ID})
		// Sizes only: audit events carry user names and IP addresses.
		t.Logf("%d bytes", len(resultText(t, res, nil)))
	})
}

// firstVulnerabilityID lists one vulnerability of smokeProjectGroup and
// returns its ID, or "" when the group has none.
func firstVulnerabilityID(t *testing.T, s *server.MCPServer, id int) string {
	t.Helper()
	res := callThroughServer(t, s, id, "list_vulnerabilities", map[string]any{"group_path": smokeProjectGroup, "first": 1})
	var page struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res, nil)), &page); err != nil {
		t.Fatalf("decoding the list_vulnerabilities result: %v", err)
	}
	if len(page.Nodes) == 0 {
		return ""
	}
	return page.Nodes[0].ID
}

// callThroughServer sends a tools/call JSON-RPC message to the MCP server and
// returns the decoded tool result.
func callThroughServer(t *testing.T, s *server.MCPServer, id int, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	msg, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": args},
	})
	if err != nil {
		t.Fatalf("marshaling tools/call: %v", err)
	}

	raw, err := json.Marshal(s.HandleMessage(context.Background(), msg))
	if err != nil {
		t.Fatalf("marshaling the response: %v", err)
	}
	var resp struct {
		Result *mcp.CallToolResult `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("invalid tools/call response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("tools/call failed: %s", resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatalf("tools/call returned no result: %s", raw)
	}
	return resp.Result
}
