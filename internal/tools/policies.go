package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	queryListSecurityPolicies = `
    query($fullPath: ID!, $relationship: SecurityPolicyRelationType, $type: PolicyType, $withYaml: Boolean!) {
      __SCOPE__(fullPath: $fullPath) {
        securityPolicies(relationship: $relationship, type: $type) {
          nodes {
            name description type enabled updatedAt editPath
            yaml @include(if: $withYaml)
            policyScope { complianceFrameworks { nodes { id name } } }
          }
          pageInfo { hasNextPage }
        }
      }
    }`

	queryListScanExecutionPolicies = `
    query($fullPath: ID!, $relationship: SecurityPolicyRelationType) {
      project(fullPath: $fullPath) {
        scanExecutionPolicies(relationship: $relationship) {
          nodes {
            name description enabled updatedAt
            yaml
          }
        }
      }
    }`

	queryListScanExecutionPoliciesGroup = `
    query($fullPath: ID!, $relationship: SecurityPolicyRelationType) {
      group(fullPath: $fullPath) {
        scanExecutionPolicies(relationship: $relationship) {
          nodes {
            name description enabled updatedAt
            yaml
          }
        }
      }
    }`

	queryListComplianceFrameworksGroup = `
    query($fullPath: ID!, $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        complianceFrameworks(first: $first, after: $after) {
          nodes {
            id name description color default
            pipelineConfigurationFullPath
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListComplianceFrameworks = `
    query($fullPath: ID!, $first: Int, $after: String) {
      project(fullPath: $fullPath) {
        complianceFrameworks(first: $first, after: $after) {
          nodes {
            id name description color default
            pipelineConfigurationFullPath
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`
)

// registerPolicyTools registers the security policy and compliance framework tools.
func (ts *toolset) registerPolicyTools(s toolAdder) {
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
	), ts.handleListSecurityPolicies)

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
	), ts.handleListScanExecutionPolicies)

	// ── list_compliance_frameworks ──
	s.AddTool(mcp.NewTool("list_compliance_frameworks",
		readOnlyTool(),
		mcp.WithDescription("List compliance frameworks for a project or group. Shows framework name, description, color, and pipeline configuration. Provide either project_path or group_path."),
		mcp.WithString("project_path", mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("group_path", mcp.Description("Full group path (e.g. 'my-group')")),
		mcp.WithNumber("first", mcp.Description("Number of results (default 20)")),
		mcp.WithString("after", mcp.Description("Pagination cursor")),
	), ts.handleListComplianceFrameworks)
}

func (ts *toolset) handleListSecurityPolicies(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, scopedQuery(queryListSecurityPolicies, scope), variables)
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

func (ts *toolset) handleListScanExecutionPolicies(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, query, map[string]interface{}{
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

func (ts *toolset) handleListComplianceFrameworks(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, query, variables)
	if err != nil {
		return toolError("list_compliance_frameworks", err)
	}

	scopeData := mapGet(data, scope)
	if len(scopeData) == 0 {
		return errResult(fmt.Sprintf("%s '%s' not found", capitalize(scope), path)), nil
	}
	return okResult(scopeData["complianceFrameworks"]), nil
}
