package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const queryListDependencies = `query($fullPath: ID!, $sort: DependencySort, $packageManagers: [PackageManager!],
      $componentNames: [String!], $first: Int, $after: String) {
  __SCOPE__(fullPath: $fullPath) {
    dependencies(sort: $sort, packageManagers: $packageManagers, componentNames: $componentNames,
        first: $first, after: $after) {
      nodes {
        id name packager vulnerabilityCount reachability
        componentVersion { version }
        licenses { name spdxIdentifier }
        location { path blobPath topLevel }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

const queryListComplianceViolations = `query($fullPath: ID!, $filters: ProjectComplianceViolationFilterInput, $first: Int, $after: String) {
  group(fullPath: $fullPath) {
    projectComplianceViolations(filters: $filters, first: $first, after: $after) {
      nodes {
        id status createdAt webUrl
        project { fullPath }
        complianceControl { name controlType complianceRequirement { name framework { name } } }
        auditEvent { eventName createdAt targetType targetDetails author { username } }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

const queryGetAnalyzerCoverage = `query($fullPath: ID!) {
  group(fullPath: $fullPath) {
    analyzerStatuses { analyzerType success failure notConfigured stale totalProjectsCount updatedAt }
  }
}`

const queryGetVulnerabilityTrend = `query($fullPath: ID!, $startDate: ISO8601Date!, $endDate: ISO8601Date!, $first: Int, $after: String) {
  __SCOPE__(fullPath: $fullPath) {
    vulnerabilitiesCountByDay(startDate: $startDate, endDate: $endDate, first: $first, after: $after) {
      nodes { date total critical high medium low info unknown }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

// defaultTrendDays is the range get_vulnerability_trend covers when no
// start_date is given.
const defaultTrendDays = 30

const dateLayout = "2006-01-02"

// Trend paging: GitLab retains 365 days, so five pages of 100 cover any range.
const (
	trendPageSize = 100
	trendMaxPages = 5
)

const trendTimeoutMessage = "get_vulnerability_trend: GitLab timed out. Use a shorter date range or a subgroup"

// isGitLabTimeout reports whether err means GitLab or the HTTP client gave up
// waiting: GitLab's own "Request timed out" message, the client deadline, or a
// 502/504 from the gateway in front of GitLab. Other network errors are not.
func isGitLabTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, marker := range [...]string{"Request timed out", "Client.Timeout exceeded", "GitLab API 502", "GitLab API 504"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func (ts *toolset) registerSecurityPostureTools(s toolAdder) {
	// ── list_dependencies ──
	s.AddTool(mcp.NewTool("list_dependencies",
		readOnlyTool(),
		mcp.WithDescription("List the software dependencies (SBOM) of a project or group with version, package manager, licenses, reachability and vulnerability count. Use component_names to find where a package is used. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project'). Mutually exclusive with group_path")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'my-group'). Mutually exclusive with project_path")),
		mcp.WithArray("component_names", mcp.Description("Exact names of the packages to find (e.g. 'lodash')"), mcp.WithStringItems()),
		mcp.WithArray("package_managers", mcp.Description("Package managers to include, values of the PackageManager enum (e.g. NPM, YARN, PNPM, MAVEN, GRADLE, PIP, POETRY, GO, COMPOSER, NUGET, BUNDLER, CARGO)"), mcp.WithStringItems()),
		mcp.WithString("sort", mcp.Description("Sort order (GitLab's default applies when omitted)"), mcp.Enum("NAME_ASC", "NAME_DESC", "PACKAGER_ASC", "PACKAGER_DESC", "SEVERITY_ASC", "SEVERITY_DESC", "LICENSE_ASC", "LICENSE_DESC")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), ts.handleListDependencies)

	// ── list_compliance_violations ──
	s.AddTool(mcp.NewTool("list_compliance_violations",
		readOnlyTool(),
		mcp.WithDescription("List compliance violations detected in the projects of a group: the violated control and requirement, the framework, the project, the audit event that triggered it and its status."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path (e.g. 'my-group')")),
		mcp.WithArray("status", mcp.Description("Violation statuses to include"), mcp.WithStringEnumItems([]string{"DETECTED", "IN_REVIEW", "RESOLVED", "DISMISSED"})),
		mcp.WithString("created_after", mcp.Description("Only violations created on or after this date (YYYY-MM-DD)")),
		mcp.WithString("created_before", mcp.Description("Only violations created on or before this date (YYYY-MM-DD)")),
		mcp.WithString("project_path", mcp.Description("Only violations of this project (full path, e.g. 'group/subgroup/project')")),
		mcp.WithNumber("first", mcp.Description("Number of results (max 100, default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), ts.handleListComplianceViolations)

	// ── get_security_scanner_coverage ──
	s.AddTool(mcp.NewTool("get_security_scanner_coverage",
		readOnlyTool(),
		mcp.WithDescription("Get security scanner coverage for a group and its subgroups: for each analyzer (SAST, dependency scanning, secret detection, container scanning, ...) how many projects ran it successfully, failed, are stale or do not have it configured, plus coveragePercent (successful projects over total projects)."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path (e.g. 'my-group')")),
	), ts.handleGetSecurityScannerCoverage)

	// ── get_vulnerability_trend ──
	s.AddTool(mcp.NewTool("get_vulnerability_trend",
		readOnlyTool(),
		mcp.WithDescription("Get the daily count of open vulnerabilities by severity for a project or group over a date range (GitLab retains 365 days; results are paged internally). On very large groups use a short range or a subgroup: GitLab times out on long ranges."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project'). Mutually exclusive with group_path")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'my-group'). Mutually exclusive with project_path")),
		mcp.WithString("start_date", mcp.Description("First day of the range (YYYY-MM-DD, default: 30 days before end_date)")),
		mcp.WithString("end_date", mcp.Description("Last day of the range (YYYY-MM-DD, default: today)")),
	), ts.handleGetVulnerabilityTrend)
}

func (ts *toolset) handleListDependencies(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	variables := map[string]interface{}{
		"fullPath": path,
		"first":    pageSize(args),
	}
	if names := stringList(args["component_names"]); len(names) > 0 {
		variables["componentNames"] = names
	}
	if managers := stringList(args["package_managers"]); len(managers) > 0 {
		for i, m := range managers {
			managers[i] = strings.ToUpper(strings.TrimSpace(m))
		}
		variables["packageManagers"] = managers
	}
	if v, _ := args["sort"].(string); strings.TrimSpace(v) != "" {
		variables["sort"] = strings.ToUpper(strings.TrimSpace(v))
	}
	if v, _ := args["after"].(string); v != "" {
		variables["after"] = v
	}

	data, err := ts.gl.GraphQL(ctx, scopedQuery(queryListDependencies, scope), variables)
	if err != nil {
		return toolError("list_dependencies", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	dependencies := scopeData["dependencies"]
	if dependencies == nil {
		return errResult(fmt.Sprintf("%s '%s' has no dependency data available (not licensed or not permitted)", capitalize(scope), path)), nil
	}
	return okResult(dependencies), nil
}

func (ts *toolset) handleListComplianceViolations(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	groupPath = strings.TrimSpace(groupPath)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	filters := map[string]interface{}{}
	if statuses := stringList(args["status"]); len(statuses) > 0 {
		for i, st := range statuses {
			statuses[i] = strings.ToUpper(strings.TrimSpace(st))
		}
		filters["status"] = statuses
	}
	for _, d := range [...]struct{ param, key string }{{"created_after", "createdAfter"}, {"created_before", "createdBefore"}} {
		param, key := d.param, d.key
		raw, _ := args[param].(string)
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, err := time.Parse(dateLayout, raw); err != nil {
			return errResult(param + " must be YYYY-MM-DD"), nil
		}
		filters[key] = raw
	}
	if projectPath, _ := args["project_path"].(string); strings.TrimSpace(projectPath) != "" {
		id, err := ts.resolveGID(ctx, "project", strings.TrimSpace(projectPath))
		if err != nil {
			return errResult(err.Error()), nil
		}
		filters["projectId"] = id
	}

	variables := map[string]interface{}{
		"fullPath": groupPath,
		"filters":  filters,
		"first":    pageSize(args),
	}
	if v, _ := args["after"].(string); v != "" {
		variables["after"] = v
	}

	data, err := ts.gl.GraphQL(ctx, queryListComplianceViolations, variables)
	if err != nil {
		return toolError("list_compliance_violations", err)
	}
	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	violations := group["projectComplianceViolations"]
	if violations == nil {
		return errResult(fmt.Sprintf("Group '%s' has no compliance violation data available (not licensed or not permitted)", groupPath)), nil
	}
	return okResult(violations), nil
}

func (ts *toolset) handleGetSecurityScannerCoverage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	groupPath, _ := request.GetArguments()["group_path"].(string)
	groupPath = strings.TrimSpace(groupPath)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	data, err := ts.gl.GraphQL(ctx, queryGetAnalyzerCoverage, map[string]interface{}{"fullPath": groupPath})
	if err != nil {
		return toolError("get_security_scanner_coverage", err)
	}
	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	statuses, ok := group["analyzerStatuses"].([]interface{})
	if !ok {
		return errResult(fmt.Sprintf("Group '%s' has no scanner coverage data available (not licensed or not permitted)", groupPath)), nil
	}

	for _, item := range statuses {
		analyzer, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		success, _ := analyzer["success"].(float64)
		total, _ := analyzer["totalProjectsCount"].(float64)
		percent := 0.0
		if total > 0 {
			percent = round2(success / total * 100)
		}
		analyzer["coveragePercent"] = percent
	}
	return okResult(map[string]interface{}{"group": groupPath, "analyzers": statuses}), nil
}

func (ts *toolset) handleGetVulnerabilityTrend(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	scope, path, err := resolveScope(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	now := time.Now().UTC()
	end := now
	if raw, _ := args["end_date"].(string); strings.TrimSpace(raw) != "" {
		end, err = time.Parse(dateLayout, strings.TrimSpace(raw))
		if err != nil {
			return errResult("end_date must be YYYY-MM-DD"), nil
		}
	}
	start := end.AddDate(0, 0, -defaultTrendDays)
	if raw, _ := args["start_date"].(string); strings.TrimSpace(raw) != "" {
		start, err = time.Parse(dateLayout, strings.TrimSpace(raw))
		if err != nil {
			return errResult("start_date must be YYYY-MM-DD"), nil
		}
	}
	if start.After(end) {
		return errResult("start_date must be on or before end_date"), nil
	}

	query := scopedQuery(queryGetVulnerabilityTrend, scope)
	variables := map[string]interface{}{
		"fullPath":  path,
		"startDate": start.Format(dateLayout),
		"endDate":   end.Format(dateLayout),
		"first":     trendPageSize,
	}
	days := []interface{}{}
	for page := 1; ; page++ {
		data, err := ts.gl.GraphQL(ctx, query, variables)
		if err != nil {
			if isGitLabTimeout(err) {
				return errResult(trendTimeoutMessage), nil
			}
			return toolError("get_vulnerability_trend", err)
		}

		scopeData := mapGet(data, scope)
		if len(scopeData) == 0 {
			return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
		}
		counts := mapGet(scopeData, "vulnerabilitiesCountByDay")
		if len(counts) == 0 {
			return errResult(fmt.Sprintf("%s '%s' has no vulnerability history available (not licensed or not permitted)", capitalize(scope), path)), nil
		}
		nodes, _ := counts["nodes"].([]interface{})
		days = append(days, nodes...)

		pageInfo := mapGet(counts, "pageInfo")
		cursor, _ := pageInfo["endCursor"].(string)
		if more, _ := pageInfo["hasNextPage"].(bool); !more || cursor == "" {
			break
		}
		if page == trendMaxPages {
			return errResult(fmt.Sprintf("get_vulnerability_trend: more than %d days returned; use a shorter range", trendMaxPages*trendPageSize)), nil
		}
		variables["after"] = cursor
	}
	return okResult(map[string]interface{}{
		"dateRange": map[string]string{"start": start.Format(dateLayout), "end": end.Format(dateLayout)},
		"days":      days,
	}), nil
}
