package tools

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestListDuoUserMetrics_DefaultsAndScope(t *testing.T) {
	const response = `{"data":{"group":{"aiUserMetrics":{"nodes":[{"totalEventCount":9,"user":{"username":"ana"}}],
	  "pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`
	app, fake := newFakeGitLab(t, response)
	res, err := app.handleListDuoUserMetrics(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	if text := resultText(t, res, err); !strings.Contains(text, `"username": "ana"`) {
		t.Errorf("result = %s", text)
	}
	call := fake.lastCall(t)
	if call.Variables["sort"] != "TOTAL_EVENTS_COUNT_DESC" || call.Variables["first"] != float64(20) {
		t.Errorf("defaults: %v", call.Variables)
	}
	for _, key := range []string{"startDate", "endDate"} {
		if _, present := call.Variables[key]; present {
			t.Errorf("%s must not be sent without a date", key)
		}
	}
	if !strings.Contains(call.Query, "group(fullPath: $fullPath)") {
		t.Errorf("wrong scope")
	}

	res, err = app.handleListDuoUserMetrics(context.Background(), callTool(map[string]any{}))
	if msg := errorText(t, res, err); msg != "either project_path or group_path is required" {
		t.Errorf("message = %q", msg)
	}
}

func TestListDuoUserMetrics_ForwardsOptionsAndReportsMissingScope(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{"project":null}}`)
	res, err := app.handleListDuoUserMetrics(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "start_date": "2026-10-01", "end_date": "2026-10-31",
		"sort": "chat_total_count_desc", "first": float64(500), "after": "cur",
	}))
	if msg := errorText(t, res, err); msg != "Project 'acme/app' not found" {
		t.Errorf("message = %q", msg)
	}
	vars := fake.lastCall(t).Variables
	want := map[string]any{"startDate": "2026-10-01", "endDate": "2026-10-31", "sort": "CHAT_TOTAL_COUNT_DESC", "first": float64(100), "after": "cur"}
	for key, value := range want {
		if vars[key] != value {
			t.Errorf("%s = %v, want %v", key, vars[key], value)
		}
	}
}

const groupIDResponse = `{"data":{"group":{"id":"gid://gitlab/Group/42"}}}`

const purchasesResponse = `{"data":{"addOnPurchases":[
  {"id":"gid://gitlab/GitlabSubscriptions::AddOnPurchase/5","name":"DUO_ENTERPRISE","purchasedQuantity":2000,"assignedQuantity":1350},
  {"id":"gid://gitlab/GitlabSubscriptions::AddOnPurchase/6","name":"DUO_CORE","purchasedQuantity":2000,"assignedQuantity":0}]}}`

func TestGetDuoSeatUsage_ComputesUnassigned(t *testing.T) {
	app, fake := newScriptedGitLab(t, []string{groupIDResponse, purchasesResponse}, nil)
	res, err := app.handleGetDuoSeatUsage(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	var out struct {
		AddOns []struct {
			Name                                                    string
			PurchasedQuantity, AssignedQuantity, UnassignedQuantity int
			AssignedPercent                                         float64
		}
	}
	if err := json.Unmarshal([]byte(resultText(t, res, err)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.AddOns) != 2 || out.AddOns[0].UnassignedQuantity != 650 || out.AddOns[0].AssignedPercent != 67.5 {
		t.Errorf("addOns = %+v", out.AddOns)
	}
	if got := fake.graphQLCalls()[1].Variables["namespaceId"]; got != "gid://gitlab/Group/42" {
		t.Errorf("namespaceId = %v", got)
	}
}

func TestGetDuoSeatUsage_SubgroupWithoutPurchases(t *testing.T) {
	app, _ := newScriptedGitLab(t, []string{groupIDResponse, `{"data":{"addOnPurchases":[]}}`}, nil)
	res, err := app.handleGetDuoSeatUsage(context.Background(), callTool(map[string]any{"group_path": "acme/sub"}))
	want := "no add-on purchases found for 'acme/sub'; seats are purchased at the top-level group"
	if msg := errorText(t, res, err); !strings.Contains(msg, want) {
		t.Errorf("message = %q", msg)
	}
}

func TestGetDuoSeatUsage_GroupNotFound(t *testing.T) {
	app, _ := newScriptedGitLab(t, []string{`{"data":{"group":null}}`}, nil)
	res, err := app.handleGetDuoSeatUsage(context.Background(), callTool(map[string]any{"group_path": "ghost"}))
	if msg := errorText(t, res, err); msg != "Group 'ghost' not found" {
		t.Errorf("message = %q", msg)
	}
}

func TestListDuoSeatUsers_PicksPurchaseByType(t *testing.T) {
	const users = `{"data":{"group":{"addOnEligibleUsers":{"nodes":[{"username":"ana","lastDuoActivityOn":null}],
	  "pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`
	app, fake := newScriptedGitLab(t, []string{groupIDResponse, purchasesResponse, users}, nil)
	res, err := app.handleListDuoSeatUsers(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	resultText(t, res, err)
	vars := fake.graphQLCalls()[2].Variables
	wantIDs := []any{"gid://gitlab/GitlabSubscriptions::AddOnPurchase/5"}
	if vars["addOnType"] != "DUO_ENTERPRISE" || !reflect.DeepEqual(vars["addOnPurchaseIds"], wantIDs) ||
		vars["assigned"] != "true" || vars["sort"] != "LAST_ACTIVITY_ON_ASC" {
		t.Errorf("variables = %v", vars)
	}

	app, _ = newScriptedGitLab(t, []string{groupIDResponse, purchasesResponse}, nil)
	res, err = app.handleListDuoSeatUsers(context.Background(), callTool(map[string]any{
		"group_path": "acme", "add_on_type": "DUO_AMAZON_Q",
	}))
	want := "no DUO_AMAZON_Q purchase found for 'acme' (available: DUO_ENTERPRISE, DUO_CORE)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q", msg)
	}
}

func TestListDuoSeatUsers_UnassignedFilterAndOptions(t *testing.T) {
	const users = `{"data":{"group":{"addOnEligibleUsers":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`
	app, fake := newScriptedGitLab(t, []string{groupIDResponse, purchasesResponse, users}, nil)
	res, err := app.handleListDuoSeatUsers(context.Background(), callTool(map[string]any{
		"group_path": "acme", "assigned": false, "search": "ana", "sort": "name_asc", "first": float64(5), "after": "c1",
	}))
	resultText(t, res, err)
	vars := fake.graphQLCalls()[2].Variables
	if vars["assigned"] != "false" || vars["search"] != "ana" || vars["sort"] != "NAME_ASC" ||
		vars["first"] != float64(5) || vars["after"] != "c1" || vars["fullPath"] != "acme" {
		t.Errorf("variables = %v", vars)
	}
}

func TestGetGitLabCreditsUsage(t *testing.T) {
	app, fake := newFakeGitLab(t, `{"data":{"subscriptionUsage":{"enabled":true,"creditsUsed":1742.55}}}`)
	res, err := app.handleGetGitLabCreditsUsage(context.Background(), callTool(map[string]any{
		"group_path": "acme", "top_users": float64(500),
	}))
	if text := resultText(t, res, err); !strings.Contains(text, "1742.55") {
		t.Errorf("result = %s", text)
	}
	vars := fake.lastCall(t).Variables
	if vars["namespacePath"] != "acme" || vars["topUsers"] != float64(100) || vars["userSort"] != "TOTAL_CREDITS_USED_DESC" {
		t.Errorf("variables = %v", vars)
	}

	for name, body := range map[string]string{
		"null":     `{"data":{"subscriptionUsage":null}}`,
		"disabled": `{"data":{"subscriptionUsage":{"enabled":false}}}`,
	} {
		app, _ := newFakeGitLab(t, body)
		res, err := app.handleGetGitLabCreditsUsage(context.Background(), callTool(map[string]any{"group_path": "acme/sub"}))
		if msg := errorText(t, res, err); !strings.Contains(msg, "not available for 'acme/sub'") {
			t.Errorf("%s: message = %q", name, msg)
		}
	}
}

func TestListDuoUserMetrics_NullMetricsIsNotEmptyList(t *testing.T) {
	app, _ := newFakeGitLab(t, `{"data":{"project":{"id":"gid://gitlab/Project/1","aiUserMetrics":null}}}`)
	res, err := app.handleListDuoUserMetrics(context.Background(), callTool(map[string]any{"project_path": "acme/app"}))
	want := "Project 'acme/app' has no Duo user metrics available (not licensed or not permitted)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

func TestListDuoSeatUsers_NullSeatDataIsNotEmptyList(t *testing.T) {
	const users = `{"data":{"group":{"id":"gid://gitlab/Group/42","addOnEligibleUsers":null}}}`
	app, _ := newScriptedGitLab(t, []string{groupIDResponse, purchasesResponse, users}, nil)
	res, err := app.handleListDuoSeatUsers(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	want := "Group 'acme' has no Duo seat data available (not licensed or not permitted)"
	if msg := errorText(t, res, err); msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

func TestListDuoSeatUsers_AssignedMustBeBoolean(t *testing.T) {
	app, fake := newScriptedGitLab(t, []string{groupIDResponse, purchasesResponse}, nil)
	res, err := app.handleListDuoSeatUsers(context.Background(), callTool(map[string]any{
		"group_path": "acme", "assigned": "false",
	}))
	if msg := errorText(t, res, err); msg != "assigned must be a boolean" {
		t.Errorf("message = %q", msg)
	}
	if n := len(fake.graphQLCalls()); n != 0 {
		t.Errorf("GraphQL calls = %d, validation must run first", n)
	}
}

func TestListDuoSeatUsers_SendsEveryMatchingPurchase(t *testing.T) {
	const purchases = `{"data":{"addOnPurchases":[
  {"id":"gid://gitlab/GitlabSubscriptions::AddOnPurchase/5","name":"DUO_ENTERPRISE"},
  {"id":"gid://gitlab/GitlabSubscriptions::AddOnPurchase/6","name":"DUO_CORE"},
  {"id":"gid://gitlab/GitlabSubscriptions::AddOnPurchase/7","name":"DUO_ENTERPRISE"}]}}`
	const users = `{"data":{"group":{"addOnEligibleUsers":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`
	app, fake := newScriptedGitLab(t, []string{groupIDResponse, purchases, users}, nil)
	res, err := app.handleListDuoSeatUsers(context.Background(), callTool(map[string]any{"group_path": "acme"}))
	resultText(t, res, err)
	want := []any{"gid://gitlab/GitlabSubscriptions::AddOnPurchase/5", "gid://gitlab/GitlabSubscriptions::AddOnPurchase/7"}
	if got := fake.graphQLCalls()[2].Variables["addOnPurchaseIds"]; !reflect.DeepEqual(got, want) {
		t.Errorf("addOnPurchaseIds = %v, want %v", got, want)
	}
}
