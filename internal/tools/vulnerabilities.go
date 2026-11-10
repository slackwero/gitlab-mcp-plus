package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	queryListVulnerabilities = `
    query($fullPath: ID!, $severity: [VulnerabilitySeverity!], $state: [VulnerabilityState!],
          $reportType: [VulnerabilityReportType!], $scanner: [String!], $hasIssues: Boolean,
          $hasResolution: Boolean, $identifierName: String, $hasMergeRequest: Boolean,
          $hasAiResolution: Boolean, $hasRemediations: Boolean,
          $dismissalReason: [VulnerabilityDismissalReason!],
          $sort: VulnerabilitySort, $first: Int, $after: String) {
      __SCOPE__(fullPath: $fullPath) {
        vulnerabilitySeveritiesCount(severity: $severity, state: $state, reportType: $reportType,
            scanner: $scanner, hasIssues: $hasIssues, hasResolution: $hasResolution,
            identifierName: $identifierName, hasMergeRequest: $hasMergeRequest,
            hasAiResolution: $hasAiResolution, hasRemediations: $hasRemediations,
            dismissalReason: $dismissalReason) {
          critical high medium low info unknown
        }
        vulnerabilities(severity: $severity, state: $state, reportType: $reportType,
            scanner: $scanner, hasIssues: $hasIssues, hasResolution: $hasResolution,
            identifierName: $identifierName, hasMergeRequest: $hasMergeRequest,
            hasAiResolution: $hasAiResolution, hasRemediations: $hasRemediations,
            dismissalReason: $dismissalReason,
            sort: $sort, first: $first, after: $after) {
          nodes {
            id uuid title severity state reportType detectedAt resolvedAt dismissedAt
            description webUrl dismissalReason falsePositive hasRemediations aiResolutionAvailable
            cveEnrichment { epssScore isKnownExploit }
            primaryIdentifier { name externalType externalId url }
            location {
              ... on VulnerabilityLocationSast { file startLine endLine }
              ... on VulnerabilityLocationDependencyScanning { file dependency { package { name } version } }
              ... on VulnerabilityLocationContainerScanning { image operatingSystem }
              ... on VulnerabilityLocationSecretDetection { file startLine endLine }
              ... on VulnerabilityLocationDast { hostname path }
            }
            scanner { name externalId vendor }
            project { fullPath }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryGetVulnerability = `
    query($id: VulnerabilityID!) {
      vulnerability(id: $id) {
        id uuid title severity state reportType
        detectedAt confirmedAt resolvedAt dismissedAt updatedAt dueDate
        description solution webUrl
        dismissalReason stateComment falsePositive hasRemediations
        presentOnDefaultBranch resolvedOnDefaultBranch
        aiResolutionAvailable aiResolutionEnabled
        cvss { vendor version baseScore overallScore severity vector }
        cveEnrichment { cve epssScore isKnownExploit }
        primaryIdentifier { name externalType externalId url }
        identifiers { name externalType externalId url }
        links { name url }
        location {
          ... on VulnerabilityLocationSast { file startLine endLine blobPath }
          ... on VulnerabilityLocationDependencyScanning { file dependency { package { name } version } blobPath }
          ... on VulnerabilityLocationContainerScanning { image operatingSystem }
          ... on VulnerabilityLocationSecretDetection { file startLine endLine blobPath }
          ... on VulnerabilityLocationDast { hostname path requestMethod }
        }
        scanner { name externalId vendor }
        project { fullPath name webUrl }
        findingTokenStatus { status lastVerifiedAt }
        issueLinks { nodes { linkType issue { iid title webUrl state } } }
        mergeRequests(first: 10) { nodes { iid title state webUrl } pageInfo { hasNextPage } }
        severityOverrides(first: 10) { nodes { originalSeverity newSeverity createdAt author { username } } pageInfo { hasNextPage } }
        notes { nodes { body author { name username } createdAt } }
        stateTransitions { nodes { toState fromState author { name username } createdAt comment } }
      }
    }`

	queryGetVulnerabilityStatistics = `
    query($fullPath: ID!) {
      project(fullPath: $fullPath) {
        vulnerabilitySeveritiesCount {
          critical high medium low info unknown
        }
        vulnerabilityStatistic {
          total
          critical high medium low info unknown
        }
      }
    }`

	queryListPipelineSecurityFindings = `
    query($fullPath: ID!, $pipelineIid: ID!, $reportType: [String!], $severity: [String!],
          $first: Int, $after: String) {
      project(fullPath: $fullPath) {
        pipeline(iid: $pipelineIid) {
          securityReportFindings(reportType: $reportType, severity: $severity,
                                 first: $first, after: $after) {
            nodes {
              uuid title severity reportType
              scanner { name externalId }
              identifiers { name externalType externalId url }
              description solution state
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }`

	queryListVulnerabilityScanners = `
    query($fullPath: ID!) {
      project(fullPath: $fullPath) {
        vulnerabilityScanners {
          nodes {
            id name externalId reportType
            vendor
          }
        }
      }
    }`

	queryGetVulnerabilityStatisticsGroup = `
    query($fullPath: ID!) {
      group(fullPath: $fullPath) {
        vulnerabilitySeveritiesCount {
          critical high medium low info unknown
        }
      }
    }`

	queryListVulnerabilityScannersGroup = `
    query($fullPath: ID!) {
      group(fullPath: $fullPath) {
        vulnerabilityScanners {
          nodes {
            id name externalId reportType
            vendor
          }
        }
      }
    }`

	mutationVulnerabilityConfirm = `
    mutation($id: VulnerabilityID!) {
      vulnerabilityConfirm(input: { id: $id }) {
        vulnerability { id title state severity }
        errors
      }
    }`

	mutationVulnerabilityDismiss = `
    mutation($id: VulnerabilityID!, $comment: String, $dismissalReason: VulnerabilityDismissalReason) {
      vulnerabilityDismiss(input: { id: $id, comment: $comment, dismissalReason: $dismissalReason }) {
        vulnerability { id title state severity }
        errors
      }
    }`

	mutationVulnerabilityResolve = `
    mutation($id: VulnerabilityID!) {
      vulnerabilityResolve(input: { id: $id }) {
        vulnerability { id title state severity }
        errors
      }
    }`

	mutationVulnerabilityRevertToDetected = `
    mutation($id: VulnerabilityID!) {
      vulnerabilityRevertToDetected(input: { id: $id }) {
        vulnerability { id title state severity }
        errors
      }
    }`
)

// vulnerabilityReportTypes mirrors GitLab's VulnerabilityReportType enum.
var vulnerabilityReportTypes = []string{
	"SAST", "DEPENDENCY_SCANNING", "CONTAINER_SCANNING", "DAST", "SECRET_DETECTION",
	"COVERAGE_FUZZING", "API_FUZZING", "CLUSTER_IMAGE_SCANNING",
	"CONTAINER_SCANNING_FOR_REGISTRY", "SARIF", "GENERIC",
}

// registerVulnerabilityTools registers the tools that read vulnerabilities and change the state of one.
func (ts *toolset) registerVulnerabilityTools(s toolAdder) {
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
	), ts.handleListVulnerabilities)

	// ── get_vulnerability ──
	s.AddTool(mcp.NewTool("get_vulnerability",
		readOnlyTool(),
		mcp.WithDescription("Get full details of a single vulnerability: identifiers, location, solution, CVSS, EPSS and KEV (cveEnrichment), linked issues and merge requests, severity overrides, AI resolution availability, notes and state history."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), ts.handleGetVulnerability)

	// ── get_vulnerability_statistics ──
	s.AddTool(mcp.NewTool("get_vulnerability_statistics",
		readOnlyTool(),
		mcp.WithDescription("Get vulnerability severity distribution counts and statistics for a project or group. Shows totals by severity level. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup') to get aggregated statistics across all projects in the group")),
	), ts.handleGetVulnerabilityStatistics)

	// ── vulnerability_confirm ──
	s.AddTool(mcp.NewTool("vulnerability_confirm",
		stateChangingTool(),
		mcp.WithDescription("Confirm a detected vulnerability, changing its state from DETECTED to CONFIRMED."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), ts.handleVulnerabilityConfirm)

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
	), ts.handleVulnerabilityDismiss)

	// ── vulnerability_resolve ──
	s.AddTool(mcp.NewTool("vulnerability_resolve",
		stateChangingTool(),
		mcp.WithDescription("Mark a vulnerability as resolved."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), ts.handleVulnerabilityResolve)

	// ── vulnerability_revert_to_detected ──
	s.AddTool(mcp.NewTool("vulnerability_revert_to_detected",
		stateChangingTool(),
		mcp.WithDescription("Revert a vulnerability back to DETECTED state (from CONFIRMED, DISMISSED, or RESOLVED)."),
		mcp.WithString("id", mcp.Required(), mcp.Description("Vulnerability global ID (e.g. 'gid://gitlab/Vulnerability/12345' or just '12345')")),
	), ts.handleVulnerabilityRevertToDetected)

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
	), ts.handleListPipelineSecurityFindings)

	// ── list_vulnerability_scanners ──
	s.AddTool(mcp.NewTool("list_vulnerability_scanners",
		readOnlyTool(),
		mcp.WithDescription("List all security scanners that have produced findings for a project or group. Shows scanner name, type, and vendor. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'group/subgroup') to list scanners across all projects in the group")),
	), ts.handleListVulnerabilityScanners)
}

func (ts *toolset) handleListVulnerabilities(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, scopedQuery(queryListVulnerabilities, scope), variables)
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

func (ts *toolset) handleGetVulnerability(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := ts.gl.GraphQL(ctx, queryGetVulnerability, map[string]interface{}{
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

func (ts *toolset) handleGetVulnerabilityStatistics(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, query, map[string]interface{}{"fullPath": path})
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

func (ts *toolset) handleVulnerabilityConfirm(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := ts.gl.GraphQL(ctx, mutationVulnerabilityConfirm, map[string]interface{}{
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

func (ts *toolset) handleVulnerabilityDismiss(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, mutationVulnerabilityDismiss, variables)
	if err != nil {
		return toolError("vulnerability_dismiss", err)
	}

	result := mapGet(data, "vulnerabilityDismiss")
	if errs := getErrorStrings(result); len(errs) > 0 {
		return errResult(fmt.Sprintf("Failed to dismiss: %s", strings.Join(errs, ", "))), nil
	}
	return okResult(result["vulnerability"]), nil
}

func (ts *toolset) handleVulnerabilityResolve(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := ts.gl.GraphQL(ctx, mutationVulnerabilityResolve, map[string]interface{}{
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

func (ts *toolset) handleVulnerabilityRevertToDetected(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	id, _ := args["id"].(string)

	data, err := ts.gl.GraphQL(ctx, mutationVulnerabilityRevertToDetected, map[string]interface{}{
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

func (ts *toolset) handleListPipelineSecurityFindings(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, queryListPipelineSecurityFindings, variables)
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

func (ts *toolset) handleListVulnerabilityScanners(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, query, map[string]interface{}{"fullPath": path})
	if err != nil {
		return toolError("list_vulnerability_scanners", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	return okResult(scopeData["vulnerabilityScanners"]), nil
}

func normalizeVulnID(id string) string {
	if strings.HasPrefix(id, "gid://") {
		return id
	}
	return "gid://gitlab/Vulnerability/" + id
}
