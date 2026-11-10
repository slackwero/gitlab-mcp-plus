package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// vulnerabilityReportTypes mirrors GitLab's VulnerabilityReportType enum.
var vulnerabilityReportTypes = []string{
	"SAST", "DEPENDENCY_SCANNING", "CONTAINER_SCANNING", "DAST", "SECRET_DETECTION",
	"COVERAGE_FUZZING", "API_FUZZING", "CLUSTER_IMAGE_SCANNING",
	"CONTAINER_SCANNING_FOR_REGISTRY", "SARIF", "GENERIC",
}

// mcp-go publishes readOnlyHint=false and destructiveHint=true by default, so
// every tool declares its classification with one of these three options.

// readOnlyTool marks a tool that only queries GitLab.
func readOnlyTool() mcp.ToolOption { return safetyHints(true, false) }

// additiveTool marks a tool that creates resources without modifying existing ones.
func additiveTool() mcp.ToolOption { return safetyHints(false, false) }

// stateChangingTool marks a tool that modifies an existing resource.
func stateChangingTool() mcp.ToolOption { return safetyHints(false, true) }

func safetyHints(readOnly, destructive bool) mcp.ToolOption {
	return func(t *mcp.Tool) {
		t.Annotations.ReadOnlyHint = &readOnly
		t.Annotations.DestructiveHint = &destructive
	}
}

func (a *App) registerTools(s toolAdder) {
	// ── list_vulnerabilities ──
	s.AddTool(mcp.NewTool("list_vulnerabilities",
		readOnlyTool(),
		mcp.WithDescription("List vulnerabilities for a GitLab project or group with optional filters. Returns paginated results with severity, state, location, and scanner information. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup') to list vulnerabilities across all projects in the group")),
		mcp.WithArray("severity",
			mcp.Description("Filter by severity levels"),
			mcp.Items(map[string]any{"type": "string", "enum": []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}}),
		),
		mcp.WithArray("state",
			mcp.Description("Filter by vulnerability states"),
			mcp.Items(map[string]any{"type": "string", "enum": []string{"DETECTED", "CONFIRMED", "DISMISSED", "RESOLVED"}}),
		),
		mcp.WithArray("report_type",
			mcp.Description("Filter by report/scanner type"),
			mcp.Items(map[string]any{"type": "string", "enum": vulnerabilityReportTypes}),
		),
		mcp.WithArray("scanner",
			mcp.Description("Filter by scanner external IDs"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithBoolean("has_issues", mcp.Description("Filter by whether vulnerability has linked issues")),
		mcp.WithBoolean("has_resolution", mcp.Description("Filter by whether vulnerability has a resolution")),
		mcp.WithString("identifier_name", mcp.Description("Filter by identifier name, e.g. 'CVE-2026-1234'")),
		mcp.WithBoolean("has_merge_request", mcp.Description("Filter by whether the vulnerability has a linked merge request")),
		mcp.WithBoolean("has_ai_resolution", mcp.Description("Filter by whether an AI resolution is available")),
		mcp.WithBoolean("has_remediations", mcp.Description("Filter by whether the vulnerability has remediations")),
		mcp.WithArray("dismissal_reason",
			mcp.Description("Filter dismissed vulnerabilities by dismissal reason"),
			mcp.Items(map[string]any{"type": "string", "enum": []string{"ACCEPTABLE_RISK", "FALSE_POSITIVE", "MITIGATING_CONTROL", "USED_IN_TESTS", "NOT_APPLICABLE"}}),
		),
		mcp.WithString("sort",
			mcp.Description("Sort order (default: severity_desc)"),
			mcp.Enum("severity_desc", "severity_asc", "detected_desc", "detected_asc"),
		),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListVulnerabilities)

	// ── get_vulnerability ──
	s.AddTool(mcp.NewTool("get_vulnerability",
		readOnlyTool(),
		mcp.WithDescription("Get full details of a single vulnerability: identifiers, location, solution, CVSS, EPSS and KEV (cveEnrichment), linked issues and merge requests, severity overrides, AI resolution availability, notes and state history."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), a.handleGetVulnerability)

	// ── get_vulnerability_statistics ──
	s.AddTool(mcp.NewTool("get_vulnerability_statistics",
		readOnlyTool(),
		mcp.WithDescription("Get vulnerability severity distribution counts and statistics for a project or group. Shows totals by severity level. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup') to get aggregated statistics across all projects in the group")),
	), a.handleGetVulnerabilityStatistics)

	// ── vulnerability_confirm ──
	s.AddTool(mcp.NewTool("vulnerability_confirm",
		stateChangingTool(),
		mcp.WithDescription("Confirm a detected vulnerability, changing its state from DETECTED to CONFIRMED."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), a.handleVulnerabilityConfirm)

	// ── vulnerability_dismiss ──
	s.AddTool(mcp.NewTool("vulnerability_dismiss",
		stateChangingTool(),
		mcp.WithDescription("Dismiss a vulnerability with an optional comment and dismissal reason. Valid reasons: ACCEPTABLE_RISK, FALSE_POSITIVE, MITIGATING_CONTROL, USED_IN_TESTS, NOT_APPLICABLE."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
		mcp.WithString("comment", mcp.Description("Dismissal comment")),
		mcp.WithString("dismissal_reason",
			mcp.Description("Reason for dismissal"),
			mcp.Enum("ACCEPTABLE_RISK", "FALSE_POSITIVE", "MITIGATING_CONTROL", "USED_IN_TESTS", "NOT_APPLICABLE"),
		),
	), a.handleVulnerabilityDismiss)

	// ── vulnerability_resolve ──
	s.AddTool(mcp.NewTool("vulnerability_resolve",
		stateChangingTool(),
		mcp.WithDescription("Mark a vulnerability as resolved."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), a.handleVulnerabilityResolve)

	// ── vulnerability_revert_to_detected ──
	s.AddTool(mcp.NewTool("vulnerability_revert_to_detected",
		stateChangingTool(),
		mcp.WithDescription("Revert a vulnerability back to DETECTED state (from CONFIRMED, DISMISSED, or RESOLVED)."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), a.handleVulnerabilityRevertToDetected)

	// ── list_pipeline_security_findings ──
	s.AddTool(mcp.NewTool("list_pipeline_security_findings",
		readOnlyTool(),
		mcp.WithDescription("Get security findings from a specific pipeline. These are findings before they become vulnerabilities. Useful for inspecting scan results from a particular CI run."),
		mcp.WithString("project_path", mcp.Required(), mcp.Description("Full project path")),
		mcp.WithString("pipeline_iid", mcp.Required(), mcp.Description("Pipeline IID (internal ID within the project)")),
		mcp.WithArray("report_type",
			mcp.Description("Filter by report type: sast, dast, dependency_scanning, container_scanning, secret_detection, api_fuzzing, coverage_fuzzing, cluster_image_scanning (case-insensitive)"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithArray("severity",
			mcp.Description("Filter by severity: critical, high, medium, low, info, unknown (case-insensitive)"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListPipelineSecurityFindings)

	// ── list_vulnerability_scanners ──
	s.AddTool(mcp.NewTool("list_vulnerability_scanners",
		readOnlyTool(),
		mcp.WithDescription("List all security scanners that have produced findings for a project or group. Shows scanner name, type, and vendor. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup') to list scanners across all projects in the group")),
	), a.handleListVulnerabilityScanners)

	// ── list_security_policies ──
	s.AddTool(mcp.NewTool("list_security_policies",
		readOnlyTool(),
		mcp.WithDescription("List security policies of every type (approval, scan execution, pipeline execution, vulnerability management) for a project or group. Filter with policy_type; set include_yaml=true to get each policy's YAML. Provide either project_path or group_path. Results come from a single GitLab page; pageInfo.hasNextPage is true when more policies exist."),
		mcp.WithString("project_path", mcp.Description("Full project path")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup') to list security policies defined at the group level")),
		mcp.WithString("relationship",
			mcp.Description("Filter by policy relationship: DIRECT (project or group only), INHERITED (own + parent groups), INHERITED_ONLY (parent groups only), DESCENDANT (group_path only: policies of descendant groups and projects). Defaults to INHERITED to include all applicable policies."),
			mcp.Enum("DIRECT", "INHERITED", "INHERITED_ONLY", "DESCENDANT"),
		),
		mcp.WithString("policy_type",
			mcp.Description("Only return policies of this type. Omit to return every type."),
			mcp.Enum("APPROVAL_POLICY", "SCAN_EXECUTION_POLICY", "PIPELINE_EXECUTION_POLICY", "PIPELINE_EXECUTION_SCHEDULE_POLICY", "VULNERABILITY_MANAGEMENT_POLICY"),
		),
		mcp.WithBoolean("include_yaml", mcp.Description("Include each policy's YAML (default false)")),
	), a.handleListSecurityPolicies)

	// ── list_scan_execution_policies ──
	s.AddTool(mcp.NewTool("list_scan_execution_policies",
		readOnlyTool(),
		mcp.WithDescription("List scan execution policies for a project or group with full YAML configuration. Shows rules, actions, and scope of each policy. Equivalent to list_security_policies with policy_type=SCAN_EXECUTION_POLICY and include_yaml=true. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup') to list scan execution policies defined at the group level")),
		mcp.WithString("relationship",
			mcp.Description("Filter by policy relationship: DIRECT (project only), INHERITED (project + parent groups), INHERITED_ONLY (parent groups only). Defaults to INHERITED to include all applicable policies."),
			mcp.Enum("DIRECT", "INHERITED", "INHERITED_ONLY"),
		),
	), a.handleListScanExecutionPolicies)

	// ── list_compliance_frameworks ──
	s.AddTool(mcp.NewTool("list_compliance_frameworks",
		readOnlyTool(),
		mcp.WithDescription("List compliance frameworks for a project or group. Shows framework name, description, color, and pipeline configuration. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'my-group')")),
		mcp.WithNumber("first", mcp.Description("Number of results (default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListComplianceFrameworks)

	// ── get_duo_ai_metrics ──
	s.AddTool(mcp.NewTool("get_duo_ai_metrics",
		readOnlyTool(),
		mcp.WithDescription("Get GitLab Duo usage metrics for a group or project: code suggestions, chat, code review, MCP tool calls, troubleshooting and Agent Platform sessions, with optional trend periods."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project'). Mutually exclusive with group_path.")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup'). Mutually exclusive with project_path; one of the two is required.")),
		mcp.WithString("start_date", mcp.Description("Start date in ISO8601 format (e.g. '2024-01-01'). Defaults to 30 days ago.")),
		mcp.WithString("end_date", mcp.Description("End date in ISO8601 format (e.g. '2024-01-31'). Defaults to today.")),
		mcp.WithNumber("periods",
			mcp.Description("Number of equal periods to split the date range into for trend analysis (1-12). Use 1 for a single summary, >1 for a trend over time."),
			mcp.Min(1), mcp.Max(12),
		),
		mcp.WithArray("ide_names",
			mcp.Description("Restrict code suggestion metrics to these IDEs. Use the exact names returned in codeSuggestions.ideNames by an unfiltered call."),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithArray("languages",
			mcp.Description("Restrict code suggestion metrics to these languages. Use the exact names returned in codeSuggestions.languageBreakdown by an unfiltered call."),
			mcp.Items(map[string]any{"type": "string"}),
		),
	), a.handleGetDuoAIMetrics)

	// ── get_group ──
	s.AddTool(mcp.NewTool("get_group",
		readOnlyTool(),
		mcp.WithDescription("Get full details of a GitLab group: metadata, settings, statistics, and storage breakdown."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path e.g. 'group/subgroup'")),
	), a.handleGetGroup)

	// ── list_groups ──
	s.AddTool(mcp.NewTool("list_groups",
		readOnlyTool(),
		mcp.WithDescription("List GitLab groups with filters (search, parent, owned only, top level only)."),
		mcp.WithString("search", mcp.Description("Search by name or path")),
		mcp.WithString("parent_path", mcp.Description("Parent group path")),
		mcp.WithBoolean("owned_only", mcp.Description("Only groups owned by current user")),
		mcp.WithBoolean("top_level_only", mcp.Description("Only top-level groups (no parent)")),
		mcp.WithArray("ids",
			mcp.Description("Filter by group IDs (gid://gitlab/Group/N)"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("sort",
			mcp.Description("Sort order"),
			mcp.Enum("id_asc", "id_desc", "name_asc", "name_desc", "path_asc", "path_desc", "created_asc", "created_desc", "updated_asc", "updated_desc"),
		),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListGroups)

	// ── list_descendant_groups ──
	s.AddTool(mcp.NewTool("list_descendant_groups",
		readOnlyTool(),
		mcp.WithDescription("List descendant (subgroup) of a given group, optionally recursive."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path e.g. 'group/subgroup'")),
		mcp.WithString("search", mcp.Description("Search by name or path")),
		mcp.WithBoolean("include_parent_descendants", mcp.Description("Recursive into all descendants")),
		mcp.WithBoolean("owned_only", mcp.Description("Only groups owned by current user")),
		mcp.WithString("sort", mcp.Description("Sort order")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListDescendantGroups)

	// ── list_group_projects ──
	s.AddTool(mcp.NewTool("list_group_projects",
		readOnlyTool(),
		mcp.WithDescription("List projects in a group with filters: subgroups, archived state, vulnerabilities, merge-request enablement, etc."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path e.g. 'group/subgroup'")),
		mcp.WithString("search", mcp.Description("Search by name or path")),
		mcp.WithBoolean("include_subgroups", mcp.Description("Include projects from descendant subgroups")),
		mcp.WithString("archived",
			mcp.Description("Filter projects by archived state. ONLY = archived only; EXCLUDE = non-archived only; INCLUDE = no filter (default)."),
			mcp.Enum("INCLUDE", "EXCLUDE", "ONLY"),
		),
		mcp.WithBoolean("archived_only", mcp.Description("If true, only archived projects; if false, only non-archived. Alternative to the `archived` enum.")),
		mcp.WithBoolean("has_merge_requests_enabled", mcp.Description("Only projects with merge requests enabled")),
		mcp.WithBoolean("has_vulnerabilities", mcp.Description("Only projects with detected vulnerabilities")),
		mcp.WithString("sort", mcp.Description("NamespaceProjectSort enum, e.g. ACTIVITY_DESC, SIMILARITY, FULL_PATH_ASC, STORAGE_SIZE_DESC, STORAGE_SIZE_ASC, REPOSITORY_SIZE_DESC.")),
		mcp.WithArray("ids",
			mcp.Description("Filter by project IDs"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithBoolean("not_aimed_for_deletion", mcp.Description("Exclude projects scheduled for deletion")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListGroupProjects)

	// ── list_group_members ──
	s.AddTool(mcp.NewTool("list_group_members",
		readOnlyTool(),
		mcp.WithDescription("List members of a group with access level and relation filters."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path e.g. 'group/subgroup'")),
		mcp.WithString("search", mcp.Description("Search by name or username")),
		mcp.WithArray("access_levels",
			mcp.Description("Filter by access levels"),
			mcp.Items(map[string]any{"type": "string", "enum": []string{"GUEST", "PLANNER", "REPORTER", "DEVELOPER", "MAINTAINER", "OWNER"}}),
		),
		mcp.WithArray("relations",
			mcp.Description("Filter by member relation type"),
			mcp.Items(map[string]any{"type": "string", "enum": []string{"DIRECT", "INHERITED", "DESCENDANTS", "SHARED_FROM_GROUPS"}}),
		),
		mcp.WithString("sort",
			mcp.Description("Sort order"),
			mcp.Enum("ACCESS_LEVEL_ASC", "ACCESS_LEVEL_DESC", "USER_FULL_NAME_ASC", "USER_FULL_NAME_DESC", "CREATED_ASC", "CREATED_DESC", "UPDATED_ASC", "UPDATED_DESC"),
		),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListGroupMembers)

	// ── list_group_audit_events ──
	s.AddTool(mcp.NewTool("list_group_audit_events",
		readOnlyTool(),
		mcp.WithDescription("List audit events for a group with date and author filters. Uses the GitLab REST API (audit events are not exposed in GraphQL at group level)."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path e.g. 'group/subgroup'")),
		mcp.WithString("created_after", mcp.Description("ISO8601 datetime")),
		mcp.WithString("created_before", mcp.Description("ISO8601 datetime")),
		mcp.WithString("author_username", mcp.Description("Filter by author username. Resolved to a user ID and applied to the current page of results.")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Page number for pagination; use pageInfo.endCursor from the previous call")),
	), a.handleListGroupAuditEvents)

	// ── list_group_merge_requests ──
	s.AddTool(mcp.NewTool("list_group_merge_requests",
		readOnlyTool(),
		mcp.WithDescription("List merge requests across all projects in a group with rich filters."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path e.g. 'group/subgroup'")),
		mcp.WithString("state",
			mcp.Description("Merge request state"),
			mcp.Enum("opened", "closed", "locked", "merged", "all"),
		),
		mcp.WithArray("labels",
			mcp.Description("Filter by label names"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("milestone_title", mcp.Description("Filter by milestone title")),
		mcp.WithString("assignee_username", mcp.Description("Filter by assignee username")),
		mcp.WithString("author_username", mcp.Description("Filter by author username")),
		mcp.WithString("reviewer_username", mcp.Description("Filter by reviewer username")),
		mcp.WithString("search", mcp.Description("Search query")),
		mcp.WithString("created_after", mcp.Description("ISO8601 datetime")),
		mcp.WithString("created_before", mcp.Description("ISO8601 datetime")),
		mcp.WithString("merged_after", mcp.Description("ISO8601 datetime")),
		mcp.WithString("merged_before", mcp.Description("ISO8601 datetime")),
		mcp.WithArray("target_branches",
			mcp.Description("Filter by target branches"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithArray("source_branches",
			mcp.Description("Filter by source branches"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithBoolean("draft", mcp.Description("Filter by draft state")),
		mcp.WithString("sort", mcp.Description("e.g. CREATED_DESC, UPDATED_DESC, MERGED_AT_DESC")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), a.handleListGroupMergeRequests)

	// ── create_project ──
	s.AddTool(mcp.NewTool("create_project",
		additiveTool(),
		mcp.WithDescription("Create a new GitLab project in a given namespace (group or personal). Requires scope 'api' on the token."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Project name (human-readable)")),
		mcp.WithString("path", mcp.Description("URL path/slug for the project. If omitted, GitLab derives it from name.")),
		mcp.WithString("namespace_path", mcp.Description("Full path of the destination namespace (group or user). If omitted, uses the token user's personal namespace.")),
		mcp.WithString("description", mcp.Description("Project description")),
		mcp.WithString("visibility",
			mcp.Description("Project visibility (default: private)"),
			mcp.Enum("private", "internal", "public"),
		),
		mcp.WithBoolean("initialize_with_readme", mcp.Description("Initialize the repo with a README (default: false)")),
	), a.handleCreateProject)

	// ── create_group ──
	s.AddTool(mcp.NewTool("create_group",
		additiveTool(),
		mcp.WithDescription("Create a new GitLab group or subgroup. Requires scope 'api' on the token."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Group name (human-readable)")),
		mcp.WithString("path", mcp.Required(), mcp.Description("URL path/slug for the group (must match ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$)")),
		mcp.WithString("parent_path", mcp.Description("Full path of the parent group. If omitted, creates a top-level group.")),
		mcp.WithString("description", mcp.Description("Group description")),
		mcp.WithString("visibility",
			mcp.Description("Group visibility (default: private)"),
			mcp.Enum("private", "internal", "public"),
		),
	), a.handleCreateGroup)

	// ── fork_project ──
	s.AddTool(mcp.NewTool("fork_project",
		additiveTool(),
		mcp.WithDescription("Fork an existing GitLab project to another namespace. Requires scope 'api' on the token."),
		mcp.WithString("project_path", mcp.Required(), mcp.Description("Full path of the source project (e.g. 'group/subgroup/project')")),
		mcp.WithString("namespace_path", mcp.Description("Full path of the destination namespace. If omitted, uses the token user's personal namespace.")),
		mcp.WithString("name", mcp.Description("Name for the forked project (default: same as source)")),
		mcp.WithString("path", mcp.Description("Path/slug for the forked project (default: same as source)")),
		mcp.WithString("description", mcp.Description("Description for the forked project")),
		mcp.WithString("visibility",
			mcp.Description("Visibility for the fork (default: inherits from destination namespace)"),
			mcp.Enum("private", "internal", "public"),
		),
	), a.handleForkProject)

	a.registerBranchTools(s)
	a.registerVulnerabilityActionTools(s)
	a.registerAIUsageTools(s)
	a.registerAIGovernanceTools(s)
	a.registerSecurityPostureTools(s)
}

// ── Handlers ──────────────────────────────────────────────────────────────

func (a *App) handleListVulnerabilities(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	variables := map[string]interface{}{
		"fullPath": path,
		"first":    pageSize(args),
	}

	if v, ok := args["severity"].([]interface{}); ok && len(v) > 0 {
		variables["severity"] = v
	}
	if v, ok := args["state"].([]interface{}); ok && len(v) > 0 {
		variables["state"] = v
	}
	if v, ok := args["report_type"].([]interface{}); ok && len(v) > 0 {
		variables["reportType"] = v
	}
	if v, ok := args["scanner"].([]interface{}); ok && len(v) > 0 {
		variables["scanner"] = v
	}
	if _, exists := args["has_issues"]; exists {
		if v, ok := args["has_issues"].(bool); ok {
			variables["hasIssues"] = v
		}
	}
	if _, exists := args["has_resolution"]; exists {
		if v, ok := args["has_resolution"].(bool); ok {
			variables["hasResolution"] = v
		}
	}
	if v, ok := args["identifier_name"].(string); ok && v != "" {
		variables["identifierName"] = v
	}
	for param, variable := range map[string]string{
		"has_merge_request": "hasMergeRequest",
		"has_ai_resolution": "hasAiResolution",
		"has_remediations":  "hasRemediations",
	} {
		if v, ok := args[param].(bool); ok {
			variables[variable] = v
		}
	}
	if v := stringList(args["dismissal_reason"]); len(v) > 0 {
		variables["dismissalReason"] = v
	}
	// VulnerabilitySort is a lowercase enum, unlike the rest.
	if v, ok := args["sort"].(string); ok && v != "" {
		variables["sort"] = strings.ToLower(v)
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, scopedQuery(queryListVulnerabilities, scope), variables)
	if err != nil {
		return toolError("list_vulnerabilities", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}

	counts := mapGet(scopeData, "vulnerabilitySeveritiesCount")
	total := 0
	for _, s := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		total += intGet(counts, s)
	}

	vulns := mapGet(scopeData, "vulnerabilities")
	vulns["totalCount"] = total
	vulns["severityCounts"] = counts
	return okResult(vulns), nil
}

func (a *App) handleGetVulnerability(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := a.graphql(ctx, queryGetVulnerability, map[string]interface{}{
		"id": normalizeVulnID(id),
	})
	if err != nil {
		return toolError("get_vulnerability", err)
	}

	if data["vulnerability"] == nil {
		return errResult(fmt.Sprintf("Vulnerability '%s' not found", id)), nil
	}
	return okResult(data["vulnerability"]), nil
}

func (a *App) handleGetVulnerabilityStatistics(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	var query string
	if scope == "group" {
		query = queryGetVulnerabilityStatisticsGroup
	} else {
		query = queryGetVulnerabilityStatistics
	}

	data, err := a.graphql(ctx, query, map[string]interface{}{"fullPath": path})
	if err != nil {
		return toolError("get_vulnerability_statistics", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}

	result := map[string]interface{}{
		"severityCounts": scopeData["vulnerabilitySeveritiesCount"],
	}
	if scope == "project" {
		result["statistics"] = scopeData["vulnerabilityStatistic"]
	}
	return okResult(result), nil
}

func (a *App) handleVulnerabilityConfirm(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := a.graphql(ctx, mutationVulnerabilityConfirm, map[string]interface{}{
		"id": normalizeVulnID(id),
	})
	if err != nil {
		return toolError("vulnerability_confirm", err)
	}

	result := mapGet(data, "vulnerabilityConfirm")
	if errs := getErrorStrings(result); len(errs) > 0 {
		return errResult(fmt.Sprintf("Failed to confirm: %s", strings.Join(errs, ", "))), nil
	}
	return okResult(result["vulnerability"]), nil
}

func (a *App) handleVulnerabilityDismiss(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	variables := map[string]interface{}{
		"id": normalizeVulnID(id),
	}
	if v, ok := args["comment"].(string); ok && v != "" {
		variables["comment"] = v
	}
	if v, ok := args["dismissal_reason"].(string); ok && v != "" {
		variables["dismissalReason"] = v
	}

	data, err := a.graphql(ctx, mutationVulnerabilityDismiss, variables)
	if err != nil {
		return toolError("vulnerability_dismiss", err)
	}

	result := mapGet(data, "vulnerabilityDismiss")
	if errs := getErrorStrings(result); len(errs) > 0 {
		return errResult(fmt.Sprintf("Failed to dismiss: %s", strings.Join(errs, ", "))), nil
	}
	return okResult(result["vulnerability"]), nil
}

func (a *App) handleVulnerabilityResolve(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := a.graphql(ctx, mutationVulnerabilityResolve, map[string]interface{}{
		"id": normalizeVulnID(id),
	})
	if err != nil {
		return toolError("vulnerability_resolve", err)
	}

	result := mapGet(data, "vulnerabilityResolve")
	if errs := getErrorStrings(result); len(errs) > 0 {
		return errResult(fmt.Sprintf("Failed to resolve: %s", strings.Join(errs, ", "))), nil
	}
	return okResult(result["vulnerability"]), nil
}

func (a *App) handleVulnerabilityRevertToDetected(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := a.graphql(ctx, mutationVulnerabilityRevertToDetected, map[string]interface{}{
		"id": normalizeVulnID(id),
	})
	if err != nil {
		return toolError("vulnerability_revert_to_detected", err)
	}

	result := mapGet(data, "vulnerabilityRevertToDetected")
	if errs := getErrorStrings(result); len(errs) > 0 {
		return errResult(fmt.Sprintf("Failed to revert: %s", strings.Join(errs, ", "))), nil
	}
	return okResult(result["vulnerability"]), nil
}

func (a *App) handleListPipelineSecurityFindings(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	projectPath, _ := args["project_path"].(string)
	pipelineIID, _ := args["pipeline_iid"].(string)

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	variables := map[string]interface{}{
		"fullPath":    projectPath,
		"pipelineIid": pipelineIID,
		"first":       first,
	}
	// securityReportFindings takes both filters as lowercase text.
	if v := lowerStrings(args["report_type"]); len(v) > 0 {
		variables["reportType"] = v
	}
	if v := lowerStrings(args["severity"]); len(v) > 0 {
		variables["severity"] = v
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, queryListPipelineSecurityFindings, variables)
	if err != nil {
		return toolError("list_pipeline_security_findings", err)
	}

	project := mapGet(data, "project")
	if len(project) == 0 {
		return errResult(fmt.Sprintf("Project '%s' not found", projectPath)), nil
	}
	if project["pipeline"] == nil {
		return errResult(fmt.Sprintf("Pipeline '%s' not found", pipelineIID)), nil
	}
	pipeline := mapGet(project, "pipeline")
	return okResult(pipeline["securityReportFindings"]), nil
}

func (a *App) handleListVulnerabilityScanners(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	var query string
	if scope == "group" {
		query = queryListVulnerabilityScannersGroup
	} else {
		query = queryListVulnerabilityScanners
	}

	data, err := a.graphql(ctx, query, map[string]interface{}{"fullPath": path})
	if err != nil {
		return toolError("list_vulnerability_scanners", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	return okResult(scopeData["vulnerabilityScanners"]), nil
}

func (a *App) handleListSecurityPolicies(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}
	withYaml, err := optionalBool(args, "include_yaml")
	if err != nil {
		return errResult(err.Error()), nil
	}

	relationship := "INHERITED"
	if v, ok := args["relationship"].(string); ok && strings.TrimSpace(v) != "" {
		relationship = strings.ToUpper(strings.TrimSpace(v))
	}
	if relationship == "DESCENDANT" && scope != "group" {
		return errResult("relationship DESCENDANT is only valid with group_path"), nil
	}

	variables := map[string]interface{}{
		"fullPath":     path,
		"relationship": relationship,
		"withYaml":     withYaml,
	}
	if v, ok := args["policy_type"].(string); ok && strings.TrimSpace(v) != "" {
		variables["type"] = strings.ToUpper(strings.TrimSpace(v))
	}

	data, err := a.graphql(ctx, scopedQuery(queryListSecurityPolicies, scope), variables)
	if err != nil {
		return toolError("list_security_policies", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	if scopeData["securityPolicies"] == nil {
		return errResult(fmt.Sprintf("%s '%s' has no security policy data available (not licensed or not permitted)", capitalize(scope), path)), nil
	}
	return okResult(scopeData["securityPolicies"]), nil
}

func (a *App) handleListScanExecutionPolicies(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	var query string
	if scope == "group" {
		query = queryListScanExecutionPoliciesGroup
	} else {
		query = queryListScanExecutionPolicies
	}

	relationship := "INHERITED"
	if v, ok := args["relationship"].(string); ok && strings.TrimSpace(v) != "" {
		relationship = strings.ToUpper(strings.TrimSpace(v))
	}

	data, err := a.graphql(ctx, query, map[string]interface{}{
		"fullPath":     path,
		"relationship": relationship,
	})
	if err != nil {
		return toolError("list_scan_execution_policies", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	return okResult(scopeData["scanExecutionPolicies"]), nil
}

func (a *App) handleListComplianceFrameworks(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	var query string
	if scope == "group" {
		query = queryListComplianceFrameworksGroup
	} else {
		query = queryListComplianceFrameworks
	}

	variables := map[string]interface{}{
		"fullPath": path,
		"first":    first,
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, query, variables)
	if err != nil {
		return toolError("list_compliance_frameworks", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	return okResult(scopeData["complianceFrameworks"]), nil
}

func (a *App) handleGetDuoAIMetrics(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, err := parseDuoMetricsArgs(request.GetArguments())
	if err != nil {
		return errResult(err.Error()), nil
	}

	if args.periods == 1 {
		dashboard, err := a.fetchDuoMetrics(ctx, args, args.startDate, args.endDate, "")
		if err != nil {
			return duoMetricsError(err)
		}
		dashboard[args.scope] = args.path
		dashboard["dateRange"] = map[string]interface{}{
			"start": args.startDate,
			"end":   args.endDate,
		}
		return okResult(dashboard), nil
	}

	startDt, _ := time.Parse("2006-01-02", args.startDate)
	endDt, _ := time.Parse("2006-01-02", args.endDate)
	ranges := splitDateRange(startDt, endDt, args.periods)

	var trendDashboards []interface{}
	for _, r := range ranges {
		pStartStr := r.start.Format("2006-01-02")
		pEndStr := r.end.Format("2006-01-02")
		dashboard, err := a.fetchDuoMetrics(ctx, args, pStartStr, pEndStr, pStartStr+"/"+pEndStr)
		if err != nil {
			return duoMetricsError(err)
		}
		trendDashboards = append(trendDashboards, dashboard)
	}

	return okResult(map[string]interface{}{
		args.scope: args.path,
		"dateRange": map[string]interface{}{
			"start": args.startDate,
			"end":   args.endDate,
		},
		"periods": args.periods,
		"trends":  trendDashboards,
	}), nil
}

// ── Group tools handlers ──────────────────────────────────────────────────

func (a *App) handleGetGroup(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	data, err := a.graphql(ctx, queryGetGroup, map[string]interface{}{
		"fullPath": groupPath,
	})
	if err != nil {
		return toolError("get_group", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group), nil
}

func (a *App) handleListGroups(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	variables := map[string]interface{}{
		"first": first,
	}
	if v, ok := args["search"].(string); ok && v != "" {
		variables["search"] = v
	}
	if v, ok := args["parent_path"].(string); ok && v != "" {
		variables["parentPath"] = v
	}
	if v, ok := args["owned_only"].(bool); ok {
		variables["ownedOnly"] = v
	}
	if v, ok := args["top_level_only"].(bool); ok {
		variables["topLevelOnly"] = v
	}
	if v, ok := args["ids"].([]interface{}); ok && len(v) > 0 {
		variables["ids"] = v
	}
	if v, ok := args["sort"].(string); ok && v != "" {
		variables["sort"] = v
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, queryListGroups, variables)
	if err != nil {
		return toolError("list_groups", err)
	}
	return okResult(data["groups"]), nil
}

func (a *App) handleListDescendantGroups(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	variables := map[string]interface{}{
		"fullPath": groupPath,
		"first":    first,
	}
	if v, ok := args["search"].(string); ok && v != "" {
		variables["search"] = v
	}
	if v, ok := args["include_parent_descendants"].(bool); ok {
		variables["includeParentDescendants"] = v
	}
	if v, ok := args["owned_only"].(bool); ok {
		variables["owned"] = v
	}
	if v, ok := args["sort"].(string); ok && v != "" {
		variables["sort"] = v
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, queryListDescendantGroups, variables)
	if err != nil {
		return toolError("list_descendant_groups", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["descendantGroups"]), nil
}

func (a *App) handleListGroupProjects(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	variables := map[string]interface{}{
		"fullPath": groupPath,
		"first":    first,
	}
	if v, ok := args["search"].(string); ok && v != "" {
		variables["search"] = v
	}
	if v, ok := args["include_subgroups"].(bool); ok {
		variables["includeSubgroups"] = v
	}
	// Group.projects includes archived projects by default: keeping only the
	// active ones requires includeArchived=false (archivedOnly=false excludes
	// nothing). archived_only takes precedence over archived.
	archived, _ := args["archived"].(string)
	if v, ok := args["archived_only"].(bool); ok {
		archived = "EXCLUDE"
		if v {
			archived = "ONLY"
		}
	}
	switch archived {
	case "ONLY":
		variables["archivedOnly"] = true
	case "EXCLUDE":
		variables["includeArchived"] = false
	}
	if v, ok := args["has_merge_requests_enabled"].(bool); ok {
		variables["withMergeRequestsEnabled"] = v
	}
	if v, ok := args["has_vulnerabilities"].(bool); ok {
		variables["hasVulnerabilities"] = v
	}
	if v, ok := args["sort"].(string); ok && v != "" {
		variables["sort"] = v
	}
	if v, ok := args["ids"].([]interface{}); ok && len(v) > 0 {
		variables["ids"] = v
	}
	if v, ok := args["not_aimed_for_deletion"].(bool); ok {
		variables["notAimedForDeletion"] = v
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, queryListGroupProjects, variables)
	if err != nil {
		return toolError("list_group_projects", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["projects"]), nil
}

func (a *App) handleListGroupMembers(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	variables := map[string]interface{}{
		"fullPath": groupPath,
		"first":    first,
	}
	if v, ok := args["search"].(string); ok && v != "" {
		variables["search"] = v
	}
	if v, ok := args["access_levels"].([]interface{}); ok && len(v) > 0 {
		variables["accessLevels"] = v
	}
	if v, ok := args["relations"].([]interface{}); ok && len(v) > 0 {
		variables["relations"] = v
	}
	if v, ok := args["sort"].(string); ok && v != "" {
		variables["sort"] = v
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, queryListGroupMembers, variables)
	if err != nil {
		return toolError("list_group_members", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["groupMembers"]), nil
}

func (a *App) handleListGroupAuditEvents(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	q := url.Values{}
	q.Set("per_page", strconv.Itoa(first))
	if v, ok := args["after"].(string); ok && v != "" {
		q.Set("page", v)
	}
	if v, ok := args["created_after"].(string); ok && v != "" {
		q.Set("created_after", v)
	}
	if v, ok := args["created_before"].(string); ok && v != "" {
		q.Set("created_before", v)
	}

	events, nextPage, err := a.restList(ctx, "/groups/"+url.PathEscape(groupPath)+"/audit_events?"+q.Encode())
	if err != nil {
		return toolError("list_group_audit_events", err)
	}

	// The audit events REST API does not filter by author: the username is
	// resolved to an ID and the current page is filtered client-side.
	if username, ok := args["author_username"].(string); ok && username != "" {
		users, _, err := a.restList(ctx, "/users?username="+url.QueryEscape(username))
		if err != nil {
			return toolError("list_group_audit_events", err)
		}
		if len(users) == 0 {
			return errResult(fmt.Sprintf("User '%s' not found", username)), nil
		}
		user, _ := users[0].(map[string]any)
		authorID := intGet(user, "id")

		filtered := make([]any, 0, len(events))
		for _, e := range events {
			if ev, ok := e.(map[string]any); ok && intGet(ev, "author_id") == authorID {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	return okResult(map[string]any{
		"nodes": events,
		"pageInfo": map[string]any{
			"hasNextPage": nextPage != "",
			"endCursor":   nextPage,
		},
	}), nil
}

func (a *App) handleListGroupMergeRequests(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	first := 20
	if v, ok := args["first"].(float64); ok {
		first = int(v)
	}
	if first > 100 {
		first = 100
	}

	variables := map[string]interface{}{
		"fullPath": groupPath,
		"first":    first,
	}
	if v, ok := args["state"].(string); ok && v != "" {
		variables["state"] = v
	}
	if v, ok := args["labels"].([]interface{}); ok && len(v) > 0 {
		variables["labels"] = v
	}
	if v, ok := args["milestone_title"].(string); ok && v != "" {
		variables["milestoneTitle"] = v
	}
	if v, ok := args["assignee_username"].(string); ok && v != "" {
		variables["assigneeUsername"] = v
	}
	if v, ok := args["author_username"].(string); ok && v != "" {
		variables["authorUsername"] = v
	}
	if v, ok := args["reviewer_username"].(string); ok && v != "" {
		variables["reviewerUsername"] = v
	}
	if v, ok := args["search"].(string); ok && v != "" {
		variables["search"] = v
	}
	if v, ok := args["created_after"].(string); ok && v != "" {
		variables["createdAfter"] = v
	}
	if v, ok := args["created_before"].(string); ok && v != "" {
		variables["createdBefore"] = v
	}
	if v, ok := args["merged_after"].(string); ok && v != "" {
		variables["mergedAfter"] = v
	}
	if v, ok := args["merged_before"].(string); ok && v != "" {
		variables["mergedBefore"] = v
	}
	if v, ok := args["target_branches"].([]interface{}); ok && len(v) > 0 {
		variables["targetBranches"] = v
	}
	if v, ok := args["source_branches"].([]interface{}); ok && len(v) > 0 {
		variables["sourceBranches"] = v
	}
	if v, ok := args["draft"].(bool); ok {
		variables["draft"] = v
	}
	if v, ok := args["sort"].(string); ok && v != "" {
		variables["sort"] = v
	}
	if v, ok := args["after"].(string); ok && v != "" {
		variables["after"] = v
	}

	data, err := a.graphql(ctx, queryListGroupMergeRequests, variables)
	if err != nil {
		return toolError("list_group_merge_requests", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["mergeRequests"]), nil
}

// ── Duo AI Metrics helpers ───────────────────────────────────────────────

type duoMetricsArgs struct {
	scope     string // "group" or "project"
	path      string
	startDate string
	endDate   string
	periods   int
	ideNames  []string
	languages []string
}

func parseDuoMetricsArgs(args map[string]any) (duoMetricsArgs, error) {
	scope, path, err := resolveScope(args)
	if err != nil {
		return duoMetricsArgs{}, err
	}
	d := duoMetricsArgs{scope: scope, path: path, periods: 1}

	now := time.Now()
	d.endDate = now.Format("2006-01-02")
	d.startDate = now.AddDate(0, 0, -30).Format("2006-01-02")

	if v, ok := args["end_date"].(string); ok && v != "" {
		d.endDate = v
	}
	if v, ok := args["start_date"].(string); ok && v != "" {
		d.startDate = v
	}

	if v, ok := args["periods"].(float64); ok {
		d.periods = int(v)
	}
	if d.periods < 1 {
		d.periods = 1
	}
	if d.periods > 12 {
		d.periods = 12
	}

	d.ideNames = stringList(args["ide_names"])
	d.languages = stringList(args["languages"])

	if _, err := time.Parse("2006-01-02", d.endDate); err != nil {
		return d, fmt.Errorf("Invalid end_date format: %v", err)
	}
	if _, err := time.Parse("2006-01-02", d.startDate); err != nil {
		return d, fmt.Errorf("Invalid start_date format: %v", err)
	}

	return d, nil
}

type dateRange struct {
	start time.Time
	end   time.Time
}

func splitDateRange(start, end time.Time, periods int) []dateRange {
	totalDays := end.Sub(start).Hours() / 24
	periodDays := totalDays / float64(periods)

	ranges := make([]dateRange, periods)
	for i := 0; i < periods; i++ {
		pStart := start.AddDate(0, 0, int(math.Round(float64(i)*periodDays)))
		pEnd := start.AddDate(0, 0, int(math.Round(float64(i+1)*periodDays))).AddDate(0, 0, -1)
		if pEnd.After(end) {
			pEnd = end
		}
		ranges[i] = dateRange{start: pStart, end: pEnd}
	}
	return ranges
}

// resultError is a logical failure (missing scope, data not available) that a
// handler reports as the tool result as is, without the tool name prefix.
type resultError string

func (e resultError) Error() string { return string(e) }

// duoMetricsError reports a resultError as is and any other error, a transport
// or GraphQL failure, through toolError.
func duoMetricsError(err error) (*mcp.CallToolResult, error) {
	var logical resultError
	if errors.As(err, &logical) {
		return errResult(logical.Error()), nil
	}
	return toolError("get_duo_ai_metrics", err)
}

func (a *App) fetchDuoMetrics(ctx context.Context, args duoMetricsArgs, startDate, endDate, periodLabel string) (map[string]any, error) {
	variables := map[string]interface{}{
		"fullPath":  args.path,
		"startDate": startDate,
		"endDate":   endDate,
	}
	// The code suggestions filters are sent only when they carry values.
	if len(args.ideNames) > 0 {
		variables["ideNames"] = args.ideNames
	}
	if len(args.languages) > 0 {
		variables["languages"] = args.languages
	}

	data, err := a.graphql(ctx, scopedQuery(queryGetAIMetrics, args.scope), variables)
	if err != nil {
		return nil, err
	}

	root := mapGet(data, args.scope)
	if len(root) == 0 {
		return nil, resultError(fmt.Sprintf("%s '%s' not found", capitalize(args.scope), args.path))
	}
	if root["aiMetrics"] == nil {
		return nil, resultError(fmt.Sprintf("%s '%s' has no Duo metrics available (not licensed or not permitted)", capitalize(args.scope), args.path))
	}
	return buildAIDashboard(mapGet(root, "aiMetrics"), periodLabel), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────

func toolError(op string, err error) (*mcp.CallToolResult, error) {
	return errResult(fmt.Sprintf("%s: %v", op, err)), nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// stringList extracts the non-empty text elements of a list argument.
func stringList(arg any) []string {
	items, _ := arg.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// lowerStrings is stringList with every element lowercased.
func lowerStrings(arg any) []string {
	out := stringList(arg)
	for i, s := range out {
		out[i] = strings.ToLower(s)
	}
	return out
}

func getErrorStrings(result map[string]interface{}) []string {
	errs, ok := result["errors"].([]interface{})
	if !ok || len(errs) == 0 {
		return nil
	}
	var msgs []string
	for _, e := range errs {
		if s, ok := e.(string); ok && s != "" {
			msgs = append(msgs, s)
		}
	}
	return msgs
}

func (a *App) handleCreateProject(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	name, _ := args["name"].(string)
	if strings.TrimSpace(name) == "" {
		return errResult("name is required"), nil
	}

	path, _ := args["path"].(string)
	namespacePath, _ := args["namespace_path"].(string)
	description, _ := args["description"].(string)
	visibility, _ := args["visibility"].(string)
	initReadme, _ := args["initialize_with_readme"].(bool)

	visibilityEnum, err := normalizeVisibility(visibility)
	if err != nil {
		return errResult(err.Error()), nil
	}

	body := map[string]interface{}{
		"name": name,
	}
	if path != "" {
		body["path"] = path
	}
	if description != "" {
		body["description"] = description
	}
	if visibilityEnum != "" {
		body["visibility"] = visibilityEnum
	}
	if initReadme {
		body["initialize_with_readme"] = true
	}

	if namespacePath != "" {
		encoded := url.PathEscape(namespacePath)
		nsResp, err := a.rest(ctx, "GET", "/namespaces/"+encoded, nil)
		if err != nil {
			return errResult(fmt.Sprintf("namespace '%s' not found: %s", namespacePath, err.Error())), nil
		}
		nsIDFloat, ok := nsResp["id"].(float64)
		if !ok {
			return errResult(fmt.Sprintf("could not resolve namespace_id for '%s'", namespacePath)), nil
		}
		body["namespace_id"] = int(nsIDFloat)
	}

	resp, err := a.rest(ctx, "POST", "/projects", body)
	if err != nil {
		return toolError("create_project", err)
	}
	return okResult(resp), nil
}

func normalizeVisibility(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	switch strings.ToLower(v) {
	case "private":
		return "private", nil
	case "internal":
		return "internal", nil
	case "public":
		return "public", nil
	default:
		return "", fmt.Errorf("visibility must be private, internal or public")
	}
}

func slugify(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '_' || r == '.' || r == '-':
			b.WriteRune(r)
			prevDash = false
		case r == ' ':
			if !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func (a *App) fetchCurrentUsername(ctx context.Context) (string, error) {
	data, err := a.graphql(ctx, queryCurrentUser, nil)
	if err != nil {
		return "", err
	}
	user := mapGet(data, "currentUser")
	username, _ := user["username"].(string)
	if username == "" {
		return "", fmt.Errorf("could not resolve current user from token")
	}
	return username, nil
}

var groupPathRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)

func (a *App) handleCreateGroup(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	name, _ := args["name"].(string)
	path, _ := args["path"].(string)
	parentPath, _ := args["parent_path"].(string)
	description, _ := args["description"].(string)
	visibility, _ := args["visibility"].(string)

	if strings.TrimSpace(name) == "" {
		return errResult("name is required"), nil
	}
	if strings.TrimSpace(path) == "" {
		return errResult("path is required"), nil
	}
	if !groupPathRe.MatchString(path) {
		return errResult("path must match ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$"), nil
	}

	visibilityEnum, err := normalizeVisibility(visibility)
	if err != nil {
		return errResult(err.Error()), nil
	}

	body := map[string]interface{}{
		"name": name,
		"path": path,
	}
	if description != "" {
		body["description"] = description
	}
	if visibilityEnum != "" {
		body["visibility"] = visibilityEnum
	}

	if parentPath != "" {
		encoded := url.PathEscape(parentPath)
		groupResp, err := a.rest(ctx, "GET", "/groups/"+encoded, nil)
		if err != nil {
			return errResult(fmt.Sprintf("parent group '%s' not found: %s", parentPath, err.Error())), nil
		}
		parentIDFloat, ok := groupResp["id"].(float64)
		if !ok {
			return errResult(fmt.Sprintf("could not resolve parent_id for '%s'", parentPath)), nil
		}
		body["parent_id"] = int(parentIDFloat)
	}

	resp, err := a.rest(ctx, "POST", "/groups", body)
	if err != nil {
		return toolError("create_group", err)
	}
	return okResult(resp), nil
}

func (a *App) handleForkProject(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	projectPath, _ := args["project_path"].(string)
	namespacePath, _ := args["namespace_path"].(string)
	name, _ := args["name"].(string)
	path, _ := args["path"].(string)
	description, _ := args["description"].(string)
	visibility, _ := args["visibility"].(string)

	if strings.TrimSpace(projectPath) == "" {
		return errResult("project_path is required"), nil
	}

	visibilityEnum, err := normalizeVisibility(visibility)
	if err != nil {
		return errResult(err.Error()), nil
	}

	if namespacePath == "" {
		username, err := a.fetchCurrentUsername(ctx)
		if err != nil {
			return toolError("fork_project", err)
		}
		namespacePath = username
	}

	body := map[string]interface{}{
		"namespace_path": namespacePath,
	}
	if name != "" {
		body["name"] = name
	}
	if path != "" {
		body["path"] = path
	}
	if description != "" {
		body["description"] = description
	}
	if visibilityEnum != "" {
		body["visibility"] = visibilityEnum
	}

	encoded := url.PathEscape(projectPath)
	resp, err := a.rest(ctx, "POST", "/projects/"+encoded+"/fork", body)
	if err != nil {
		return toolError("fork_project", err)
	}
	return okResult(resp), nil
}
