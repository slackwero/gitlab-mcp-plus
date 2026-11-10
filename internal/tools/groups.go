package tools

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	queryGetGroup = `
    query($fullPath: ID!) {
      group(fullPath: $fullPath) {
        id name fullPath path description visibility webUrl avatarUrl createdAt
        parent { id fullPath }
        emailsEnabled mentionsDisabled requireTwoFactorAuthentication twoFactorGracePeriod
        projectCreationLevel subgroupCreationLevel
        lockMathRenderingLimitsEnabled mathRenderingLimitsEnabled
        lfsEnabled requestAccessEnabled shareWithGroupLock
        rootStorageStatistics {
          storageSize repositorySize lfsObjectsSize buildArtifactsSize packagesSize
          wikiSize snippetsSize pipelineArtifactsSize uploadsSize
          containerRegistrySize dependencyProxySize
        }
        stats { releaseStats { releasesCount releasesPercentage } }
      }
    }`

	queryListGroups = `
    query($search: String, $parentPath: ID, $ownedOnly: Boolean, $topLevelOnly: Boolean,
          $ids: [ID!], $sort: String, $first: Int, $after: String) {
      groups(search: $search, parentPath: $parentPath, ownedOnly: $ownedOnly,
             topLevelOnly: $topLevelOnly, ids: $ids, sort: $sort, first: $first, after: $after) {
        nodes {
          id name fullPath path description visibility webUrl avatarUrl
          parent { id fullPath }
        }
        pageInfo { hasNextPage endCursor }
      }
    }`

	queryListDescendantGroups = `
    query($fullPath: ID!, $search: String, $includeParentDescendants: Boolean,
          $owned: Boolean, $sort: GroupSort, $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        descendantGroups(search: $search, includeParentDescendants: $includeParentDescendants,
                         owned: $owned, sort: $sort, first: $first, after: $after) {
          nodes {
            id name fullPath path description visibility webUrl
            parent { id fullPath }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListGroupProjects = `
    query($fullPath: ID!, $search: String, $includeSubgroups: Boolean,
          $includeArchived: Boolean, $archivedOnly: Boolean, $withMergeRequestsEnabled: Boolean,
          $hasVulnerabilities: Boolean, $sort: NamespaceProjectSort, $ids: [ID!],
          $notAimedForDeletion: Boolean,
          $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        projects(search: $search, includeSubgroups: $includeSubgroups,
                 includeArchived: $includeArchived, archivedOnly: $archivedOnly,
                 withMergeRequestsEnabled: $withMergeRequestsEnabled,
                 hasVulnerabilities: $hasVulnerabilities, sort: $sort, ids: $ids,
                 notAimedForDeletion: $notAimedForDeletion,
                 first: $first, after: $after) {
          nodes {
            id name fullPath path description visibility webUrl archived
            createdAt lastActivityAt starCount forksCount openIssuesCount topics
            namespace { id fullPath }
            complianceFrameworks { nodes { id name color default } }
            statistics {
              repositorySize storageSize lfsObjectsSize buildArtifactsSize
              packagesSize containerRegistrySize
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListGroupMembers = `
    query($fullPath: ID!, $search: String, $accessLevels: [AccessLevelEnum!],
          $relations: [GroupMemberRelation!], $sort: MemberSort,
          $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        groupMembers(search: $search, accessLevels: $accessLevels, relations: $relations,
                     sort: $sort, first: $first, after: $after) {
          nodes {
            id createdAt updatedAt expiresAt
            accessLevel { integerValue stringValue }
            user { id username name publicEmail webUrl state lastActivityOn }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListGroupMergeRequests = `
    query($fullPath: ID!, $state: MergeRequestState, $labels: [String!],
          $milestoneTitle: String, $assigneeUsername: String, $authorUsername: String,
          $reviewerUsername: String, $search: String,
          $createdAfter: Time, $createdBefore: Time, $mergedAfter: Time, $mergedBefore: Time,
          $targetBranches: [String!], $sourceBranches: [String!], $draft: Boolean,
          $sort: MergeRequestSort, $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        mergeRequests(state: $state, labels: $labels, milestoneTitle: $milestoneTitle,
                      assigneeUsername: $assigneeUsername, authorUsername: $authorUsername,
                      reviewerUsername: $reviewerUsername, search: $search,
                      createdAfter: $createdAfter, createdBefore: $createdBefore,
                      mergedAfter: $mergedAfter, mergedBefore: $mergedBefore,
                      targetBranches: $targetBranches, sourceBranches: $sourceBranches,
                      draft: $draft, sort: $sort, first: $first, after: $after) {
          nodes {
            id iid title state draft createdAt updatedAt mergedAt webUrl
            sourceBranch targetBranch mergeStatus approvalsRequired approvalsLeft
            author { username name }
            assignees { nodes { username name } }
            reviewers { nodes { username name } }
            labels { nodes { title color } }
            milestone { title state }
            project { id fullPath }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryCurrentUser = `
    query { currentUser { username } }`
)

var groupPathRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)

// registerGroupTools registers the group inventory, audit and project and group creation tools.
func (ts *toolset) registerGroupTools(s toolAdder) {
	// ── get_group ──
	s.AddTool(mcp.NewTool("get_group",
		readOnlyTool(),
		mcp.WithDescription("Get full details of a GitLab group: metadata, settings, statistics, and storage breakdown."),
		mcp.WithString("group_path", mcp.Required(), mcp.Description("Full group path e.g. 'group/subgroup'")),
	), ts.handleGetGroup)

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
	), ts.handleListGroups)

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
	), ts.handleListDescendantGroups)

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
	), ts.handleListGroupProjects)

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
	), ts.handleListGroupMembers)

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
	), ts.handleListGroupAuditEvents)

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
	), ts.handleListGroupMergeRequests)

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
	), ts.handleCreateProject)

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
	), ts.handleCreateGroup)

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
	), ts.handleForkProject)
}

func (ts *toolset) handleGetGroup(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	groupPath, _ := args["group_path"].(string)
	if groupPath == "" {
		return errResult("group_path is required"), nil
	}

	data, err := ts.gl.GraphQL(ctx, queryGetGroup, map[string]interface{}{
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

func (ts *toolset) handleListGroups(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, queryListGroups, variables)
	if err != nil {
		return toolError("list_groups", err)
	}
	return okResult(data["groups"]), nil
}

func (ts *toolset) handleListDescendantGroups(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, queryListDescendantGroups, variables)
	if err != nil {
		return toolError("list_descendant_groups", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["descendantGroups"]), nil
}

func (ts *toolset) handleListGroupProjects(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, queryListGroupProjects, variables)
	if err != nil {
		return toolError("list_group_projects", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["projects"]), nil
}

func (ts *toolset) handleListGroupMembers(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, queryListGroupMembers, variables)
	if err != nil {
		return toolError("list_group_members", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["groupMembers"]), nil
}

func (ts *toolset) handleListGroupAuditEvents(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	events, nextPage, err := ts.gl.RESTList(ctx, "/groups/"+url.PathEscape(groupPath)+"/audit_events?"+q.Encode())
	if err != nil {
		return toolError("list_group_audit_events", err)
	}

	// The audit events REST API does not filter by author: the username is
	// resolved to an ID and the current page is filtered client-side.
	if username, ok := args["author_username"].(string); ok && username != "" {
		users, _, err := ts.gl.RESTList(ctx, "/users?username="+url.QueryEscape(username))
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

func (ts *toolset) handleListGroupMergeRequests(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	data, err := ts.gl.GraphQL(ctx, queryListGroupMergeRequests, variables)
	if err != nil {
		return toolError("list_group_merge_requests", err)
	}

	group := mapGet(data, "group")
	if len(group) == 0 {
		return errResult(fmt.Sprintf("Group '%s' not found", groupPath)), nil
	}
	return okResult(group["mergeRequests"]), nil
}

func (ts *toolset) handleCreateProject(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		nsResp, err := ts.gl.REST(ctx, "GET", "/namespaces/"+encoded, nil)
		if err != nil {
			return errResult(fmt.Sprintf("namespace '%s' not found: %s", namespacePath, err.Error())), nil
		}
		nsIDFloat, ok := nsResp["id"].(float64)
		if !ok {
			return errResult(fmt.Sprintf("could not resolve namespace_id for '%s'", namespacePath)), nil
		}
		body["namespace_id"] = int(nsIDFloat)
	}

	resp, err := ts.gl.REST(ctx, "POST", "/projects", body)
	if err != nil {
		return toolError("create_project", err)
	}
	return okResult(resp), nil
}

func (ts *toolset) handleCreateGroup(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		groupResp, err := ts.gl.REST(ctx, "GET", "/groups/"+encoded, nil)
		if err != nil {
			return errResult(fmt.Sprintf("parent group '%s' not found: %s", parentPath, err.Error())), nil
		}
		parentIDFloat, ok := groupResp["id"].(float64)
		if !ok {
			return errResult(fmt.Sprintf("could not resolve parent_id for '%s'", parentPath)), nil
		}
		body["parent_id"] = int(parentIDFloat)
	}

	resp, err := ts.gl.REST(ctx, "POST", "/groups", body)
	if err != nil {
		return toolError("create_group", err)
	}
	return okResult(resp), nil
}

func (ts *toolset) handleForkProject(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		username, err := ts.fetchCurrentUsername(ctx)
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
	resp, err := ts.gl.REST(ctx, "POST", "/projects/"+encoded+"/fork", body)
	if err != nil {
		return toolError("fork_project", err)
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

func (ts *toolset) fetchCurrentUsername(ctx context.Context) (string, error) {
	data, err := ts.gl.GraphQL(ctx, queryCurrentUser, nil)
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
