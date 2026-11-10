package main

import (
	"slices"
	"strings"
	"testing"
)

func claudeConfig(scope string) InstallConfig {
	return InstallConfig{
		Name:        "gitlab-mcp-plus",
		BinaryPath:  "/opt/my tools/gitlab-mcp-plus",
		GitLabToken: testTokenA,
		GitLabURL:   "https://gitlab.example.com",
		Scope:       scope,
		Tools:       []string{"list_vulnerabilities", "get_vulnerability"},
	}
}

func TestClaudeAddArgs_ProjectScopeReferencesTheToken(t *testing.T) {
	args := (&claudeClient{}).addArgs(claudeConfig("project"))
	if slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, testTokenA) }) {
		t.Errorf("the project registration carries the token: %v", args)
	}
	for _, want := range []string{"GITLAB_TOKEN=${GITLAB_TOKEN}", "GITLAB_MCP_TOOLS=list_vulnerabilities,get_vulnerability"} {
		if !slices.Contains(args, want) {
			t.Errorf("args lack %q: %v", want, args)
		}
	}
}

func TestClaudeAddArgs_UserScopeCarriesTheTokenAndOptions(t *testing.T) {
	cfg := claudeConfig("user")
	cfg.ReadOnly = true
	args := (&claudeClient{}).addArgs(cfg)
	for _, want := range []string{"GITLAB_TOKEN=" + testTokenA, "GITLAB_MCP_READ_ONLY=true", "GITLAB_URL=https://gitlab.example.com"} {
		if !slices.Contains(args, want) {
			t.Errorf("args lack %q: %v", want, args)
		}
	}
	if args[len(args)-2] != "--" || args[len(args)-1] != cfg.BinaryPath {
		t.Errorf("args must end with -- and the binary path: %v", args)
	}
}

func TestClaudePrintConfig_NeverPrintsTheToken(t *testing.T) {
	for _, scope := range []string{"user", "project"} {
		out, err := (&claudeClient{}).PrintConfig(claudeConfig(scope))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, testTokenA) {
			t.Errorf("%s: the command prints the token:\n%s", scope, out)
		}
		if !strings.Contains(out, `'/opt/my tools/gitlab-mcp-plus'`) {
			t.Errorf("%s: the binary path is not shell-quoted:\n%s", scope, out)
		}
	}

	user, _ := (&claudeClient{}).PrintConfig(claudeConfig("user"))
	if !strings.Contains(user, `GITLAB_TOKEN="$GITLAB_TOKEN"`) {
		t.Errorf("user scope must take the token from the shell at paste time:\n%s", user)
	}
	project, _ := (&claudeClient{}).PrintConfig(claudeConfig("project"))
	if !strings.Contains(project, `'GITLAB_TOKEN=${GITLAB_TOKEN}'`) {
		t.Errorf("project scope must store a reference, unexpanded by the shell:\n%s", project)
	}
}
