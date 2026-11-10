package main

import (
	"context"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

func (a *App) registerBranchTools(s toolAdder) {
	// ── delete_branch ──
	s.AddTool(mcp.NewTool("delete_branch",
		stateChangingTool(),
		mcp.WithDescription("Delete a branch from a project. Refuses the default branch and protected branches, and refuses unmerged branches unless allow_unmerged is true. Returns the last commit SHA so the branch can be restored."),
		mcp.WithString("project_path", mcp.Required(), mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("branch", mcp.Required(), mcp.Description("Name of the branch to delete")),
		mcp.WithBoolean("allow_unmerged", mcp.Description("Delete the branch even if it is not merged into the default branch (default: false)")),
	), a.handleDeleteBranch)
}

func (a *App) handleDeleteBranch(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	projectPath, _ := args["project_path"].(string)
	branch, _ := args["branch"].(string)
	allowUnmerged, _ := args["allow_unmerged"].(bool)

	if strings.TrimSpace(projectPath) == "" {
		return errResult("project_path is required"), nil
	}
	if strings.TrimSpace(branch) == "" {
		return errResult("branch is required"), nil
	}

	endpoint := "/projects/" + url.PathEscape(projectPath) + "/repository/branches/" + url.PathEscape(branch)

	info, err := a.rest(ctx, "GET", endpoint, nil)
	if err != nil {
		if strings.Contains(err.Error(), "GitLab REST 404") {
			return errResult("Branch '" + branch + "' not found in project '" + projectPath + "'"), nil
		}
		return toolError("delete_branch", err)
	}

	// A guard whose flag is missing or not a boolean must refuse, never pass.
	merged, mergedOK := info["merged"].(bool)
	isDefault, defaultOK := info["default"].(bool)
	protected, protectedOK := info["protected"].(bool)
	if !mergedOK || !defaultOK || !protectedOK {
		return errResult("Unexpected GitLab response for branch '" + branch + "': missing or non-boolean \"default\", \"protected\" or \"merged\""), nil
	}
	// The last commit id is what lets the caller restore the branch.
	if commitID, _ := mapGet(info, "commit")["id"].(string); commitID == "" {
		return errResult("Unexpected GitLab response for branch '" + branch + "': missing \"commit.id\", needed to restore the branch"), nil
	}
	if isDefault {
		return errResult("Refusing to delete '" + branch + "': it is the default branch"), nil
	}
	if protected {
		return errResult("Refusing to delete '" + branch + "': it is a protected branch"), nil
	}
	if !merged && !allowUnmerged {
		return errResult("Refusing to delete '" + branch + "': it is not merged into the default branch. Pass allow_unmerged=true to delete it anyway"), nil
	}

	if _, err := a.rest(ctx, "DELETE", endpoint, nil); err != nil {
		return toolError("delete_branch", err)
	}
	return okResult(map[string]any{
		"deleted":    true,
		"project":    projectPath,
		"branch":     branch,
		"wasMerged":  merged,
		"lastCommit": info["commit"],
	}), nil
}
