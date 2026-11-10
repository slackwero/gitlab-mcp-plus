package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	defaultDuoUserSort = "TOTAL_EVENTS_COUNT_DESC"
	defaultAddOnType   = "DUO_ENTERPRISE"
	defaultSeatSort    = "LAST_ACTIVITY_ON_ASC"

	defaultCreditsUserSort = "TOTAL_CREDITS_USED_DESC"
	defaultTopUsers        = 10
	maxTopUsers            = 100
)

const queryListDuoUserMetrics = `query($fullPath: ID!, $startDate: Date, $endDate: Date, $sort: AiUserMetricsSort, $first: Int, $after: String) {
  __SCOPE__(fullPath: $fullPath) {
    aiUserMetrics(startDate: $startDate, endDate: $endDate, sort: $sort, first: $first, after: $after) {
      nodes {
        user { username name state lastActivityOn }
        lastDuoActivityOn totalEventCount
        codeSuggestions { totalEventCount codeSuggestionShownInIdeEventCount codeSuggestionAcceptedInIdeEventCount }
        chat { totalEventCount requestDuoChatResponseEventCount }
        codeReview { totalEventCount }
        agentPlatform { totalEventCount agentPlatformSessionCreatedEventCount agentPlatformSessionFinishedEventCount }
        mcp { totalEventCount }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

const queryAddOnPurchases = `query($namespaceId: NamespaceID!) {
  addOnPurchases(namespaceId: $namespaceId) { id name purchasedQuantity assignedQuantity }
}`

const queryListAddOnSeatUsers = `query($fullPath: ID!, $addOnType: GitlabSubscriptionsAddOnType!,
      $addOnPurchaseIds: [GitlabSubscriptionsAddOnPurchaseID!]!, $assigned: String,
      $search: String, $sort: GitlabSubscriptionsUserSort, $first: Int, $after: String) {
  group(fullPath: $fullPath) {
    addOnEligibleUsers(addOnType: $addOnType, addOnPurchaseIds: $addOnPurchaseIds,
        filterByAssignedSeat: $assigned, search: $search, sort: $sort, first: $first, after: $after) {
      nodes { username name state lastActivityOn lastDuoActivityOn }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

const queryGetCreditsUsage = `query($namespacePath: ID!, $startDate: ISO8601Date, $endDate: ISO8601Date, $flowTypes: [String!],
      $userSort: GitlabSubscriptionUsageUserSort, $topUsers: Int) {
  subscriptionUsage(namespacePath: $namespacePath, startDate: $startDate, endDate: $endDate, flowTypes: $flowTypes) {
    enabled startDate endDate creditsUsed dailyAverage lastEventTransactionAt
    monthlyCommitment { totalCredits creditsUsed }
    monthlyWaiver { totalCredits creditsUsed }
    overage { isAllowed creditsUsed }
    budgetCaps { subscriptionCapEnabled subscriptionCap flatUserCapEnabled flatUserCap }
    products { id title creditsUsed flowTypes { id title } }
    dailyUsage { date creditsUsed }
    usersUsage {
      totalActiveUsers totalUsersUsingCredits totalUsersUsingMonthlyCommitment totalUsersUsingOverage
      users(first: $topUsers, sort: $userSort) {
        nodes { username name usage { totalCreditsUsed creditsUsed monthlyCommitmentCreditsUsed overageCreditsUsed } }
      }
    }
  }
}`

func (a *App) registerAIUsageTools(s toolAdder) {
	// ── list_duo_user_metrics ──
	s.AddTool(mcp.NewTool("list_duo_user_metrics",
		readOnlyTool(),
		mcp.WithDescription("List per-user GitLab Duo activity for a group or project: last Duo activity date and event counts for code suggestions, chat, code review, Agent Platform and MCP. Useful to find inactive seats and top adopters. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project'). Mutually exclusive with group_path")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'my-group'). Mutually exclusive with project_path")),
		mcp.WithString("start_date", mcp.Description("Start date (YYYY-MM-DD). GitLab uses the current month when omitted")),
		mcp.WithString("end_date", mcp.Description("End date (YYYY-MM-DD). GitLab uses the current month when omitted")),
		mcp.WithString("sort", mcp.Description("Sort order, a value of AiUserMetricsSort (default: TOTAL_EVENTS_COUNT_DESC). E.g. TOTAL_EVENTS_COUNT_ASC, CODE_SUGGESTIONS_TOTAL_COUNT_DESC, CHAT_TOTAL_COUNT_DESC, AGENT_PLATFORM_TOTAL_COUNT_DESC, MCP_TOTAL_COUNT_DESC")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListDuoUserMetrics)

	// ── get_duo_seat_usage ──
	s.AddTool(mcp.NewTool("get_duo_seat_usage",
		readOnlyTool(),
		mcp.WithDescription("GitLab Duo seat usage for a top-level group: purchased, assigned and unassigned seats per add-on (e.g. DUO_ENTERPRISE, DUO_CORE) and the assigned percentage."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full path of the top-level group (seats are purchased at the top-level group)")),
	), a.handleGetDuoSeatUsage)

	// ── list_duo_seat_users ──
	s.AddTool(mcp.NewTool("list_duo_seat_users",
		readOnlyTool(),
		mcp.WithDescription("List the users of a GitLab Duo add-on in a top-level group, filtered by seat assignment, with their last activity and last Duo activity dates. Use assigned=false to list users without a seat."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full path of the top-level group")),
		mcp.WithString("add_on_type", mcp.Description("Add-on type (default: DUO_ENTERPRISE)"), mcp.Enum("DUO_ENTERPRISE", "CODE_SUGGESTIONS", "DUO_AMAZON_Q", "DUO_CORE")),
		mcp.WithBoolean("assigned", mcp.Description("true (default) lists users with a seat, false lists eligible users without one")),
		mcp.WithString("search", mcp.Description("Search by name or username")),
		mcp.WithString("sort", mcp.Description("Sort order (default: LAST_ACTIVITY_ON_ASC)"), mcp.Enum("ID_ASC", "ID_DESC", "NAME_ASC", "NAME_DESC", "LAST_ACTIVITY_ON_ASC", "LAST_ACTIVITY_ON_DESC")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListDuoSeatUsers)

	// ── get_gitlab_credits_usage ──
	s.AddTool(mcp.NewTool("get_gitlab_credits_usage",
		readOnlyTool(),
		mcp.WithDescription("Get GitLab Credits consumption for a top-level group: credits used, daily usage, monthly commitment, overage, budget caps, usage per product and the top consuming users."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full path of the top-level group")),
		mcp.WithString("start_date", mcp.Description("Start date (YYYY-MM-DD). GitLab uses the current month when omitted")),
		mcp.WithString("end_date", mcp.Description("End date (YYYY-MM-DD). GitLab uses the current month when omitted")),
		mcp.WithArray("flow_types", mcp.Description("Restrict usage to these flow types (e.g. 'chat', 'code_review')"), mcp.WithStringItems()),
		mcp.WithNumber("top_users", mcp.Description("Number of top consuming users to return (max 100, default 10)")),
		mcp.WithString("user_sort", mcp.Description("Sort order of the users (default: TOTAL_CREDITS_USED_DESC)"), mcp.Enum("NAME_ASC", "NAME_DESC", "TOTAL_CREDITS_USED_ASC", "TOTAL_CREDITS_USED_DESC")),
	), a.handleGetGitLabCreditsUsage)
}

func (a *App) handleListDuoUserMetrics(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	sort := defaultDuoUserSort
	if v, _ := args["sort"].(string); strings.TrimSpace(v) != "" {
		sort = strings.ToUpper(strings.TrimSpace(v))
	}
	variables := map[string]interface{}{
		"fullPath": path,
		"sort":     sort,
		"first":    pageSize(args),
	}
	for param, variable := range map[string]string{"start_date": "startDate", "end_date": "endDate", "after": "after"} {
		if v, _ := args[param].(string); v != "" {
			variables[variable] = v
		}
	}

	data, err := a.graphql(ctx, scopedQuery(queryListDuoUserMetrics, scope), variables)
	if err != nil {
		return toolError("list_duo_user_metrics", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	metrics := scopeData["aiUserMetrics"]
	if metrics == nil {
		return errResult(fmt.Sprintf("%s '%s' has no Duo user metrics available (not licensed or not permitted)", capitalize(scope), path)), nil
	}
	return okResult(metrics), nil
}

// addOnPurchases returns the add-on purchases of a group. Seats are bought at
// the top-level group, so an empty list is reported as an error.
func (a *App) addOnPurchases(ctx context.Context, groupPath string) ([]any, error) {
	groupID, err := a.resolveGID(ctx, "group", groupPath)
	if err != nil {
		return nil, err
	}
	data, err := a.graphql(ctx, queryAddOnPurchases, map[string]interface{}{"namespaceId": groupID})
	if err != nil {
		return nil, fmt.Errorf("listing add-on purchases for '%s': %w", groupPath, err)
	}
	purchases, _ := data["addOnPurchases"].([]any)
	if len(purchases) == 0 {
		return nil, fmt.Errorf("no add-on purchases found for '%s'; seats are purchased at the top-level group", groupPath)
	}
	return purchases, nil
}

func (a *App) handleGetDuoSeatUsage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, _ := request.GetArguments()["group_path"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		return errResult("group_path is required"), nil
	}

	purchases, err := a.addOnPurchases(ctx, path)
	if err != nil {
		return errResult(err.Error()), nil
	}

	addOns := make([]map[string]any, 0, len(purchases))
	for _, p := range purchases {
		purchase, _ := p.(map[string]any)
		purchased, _ := purchase["purchasedQuantity"].(float64)
		assigned, _ := purchase["assignedQuantity"].(float64)
		percent := 0.0
		if purchased > 0 {
			percent = round2(assigned / purchased * 100)
		}
		addOns = append(addOns, map[string]any{
			"name":               purchase["name"],
			"purchasedQuantity":  purchased,
			"assignedQuantity":   assigned,
			"unassignedQuantity": purchased - assigned,
			"assignedPercent":    percent,
		})
	}
	return okResult(map[string]any{"group": path, "addOns": addOns}), nil
}

func (a *App) handleListDuoSeatUsers(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	path, _ := args["group_path"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		return errResult("group_path is required"), nil
	}
	addOnType := defaultAddOnType
	if v, _ := args["add_on_type"].(string); strings.TrimSpace(v) != "" {
		addOnType = strings.ToUpper(strings.TrimSpace(v))
	}
	sort := defaultSeatSort
	if v, _ := args["sort"].(string); strings.TrimSpace(v) != "" {
		sort = strings.ToUpper(strings.TrimSpace(v))
	}
	assigned := "true"
	if raw, present := args["assigned"]; present && raw != nil {
		v, ok := raw.(bool)
		if !ok {
			return errResult("assigned must be a boolean"), nil
		}
		assigned = strconv.FormatBool(v)
	}

	purchases, err := a.addOnPurchases(ctx, path)
	if err != nil {
		return errResult(err.Error()), nil
	}
	var purchaseIDs []string
	available := make([]string, 0, len(purchases))
	for _, p := range purchases {
		purchase, _ := p.(map[string]any)
		name, _ := purchase["name"].(string)
		available = append(available, name)
		if id, _ := purchase["id"].(string); name == addOnType && id != "" {
			purchaseIDs = append(purchaseIDs, id)
		}
	}
	if len(purchaseIDs) == 0 {
		return errResult(fmt.Sprintf("no %s purchase found for '%s' (available: %s)", addOnType, path, strings.Join(available, ", "))), nil
	}

	variables := map[string]interface{}{
		"fullPath":         path,
		"addOnType":        addOnType,
		"addOnPurchaseIds": purchaseIDs,
		"assigned":         assigned,
		"sort":             sort,
		"first":            pageSize(args),
	}
	for param, variable := range map[string]string{"search": "search", "after": "after"} {
		if v, _ := args[param].(string); v != "" {
			variables[variable] = v
		}
	}

	data, err := a.graphql(ctx, queryListAddOnSeatUsers, variables)
	if err != nil {
		return toolError("list_duo_seat_users", err)
	}
	seatUsers := mapGet(data, "group")["addOnEligibleUsers"]
	if seatUsers == nil {
		return errResult(fmt.Sprintf("Group '%s' has no Duo seat data available (not licensed or not permitted)", path)), nil
	}
	return okResult(seatUsers), nil
}

func (a *App) handleGetGitLabCreditsUsage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	path, _ := args["group_path"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		return errResult("group_path is required"), nil
	}

	topUsers := defaultTopUsers
	if n, _ := args["top_users"].(float64); n >= 1 {
		topUsers = int(min(n, maxTopUsers))
	}
	userSort := defaultCreditsUserSort
	if v, _ := args["user_sort"].(string); strings.TrimSpace(v) != "" {
		userSort = strings.ToUpper(strings.TrimSpace(v))
	}
	variables := map[string]interface{}{
		"namespacePath": path,
		"userSort":      userSort,
		"topUsers":      topUsers,
	}
	for param, variable := range map[string]string{"start_date": "startDate", "end_date": "endDate"} {
		if v, _ := args[param].(string); v != "" {
			variables[variable] = v
		}
	}
	if flowTypes := stringList(args["flow_types"]); len(flowTypes) > 0 {
		variables["flowTypes"] = flowTypes
	}

	data, err := a.graphql(ctx, queryGetCreditsUsage, variables)
	if err != nil {
		return toolError("get_gitlab_credits_usage", err)
	}
	usage := mapGet(data, "subscriptionUsage")
	if enabled, _ := usage["enabled"].(bool); !enabled {
		return errResult(fmt.Sprintf("GitLab Credits usage is not available for '%s'; it requires the top-level group and the Customer Portal credits API", path)), nil
	}
	return okResult(usage), nil
}
