// Package tools defines the MCP tools of gitlab-mcp-plus and builds the server that exposes them.
package tools

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/slackwero/gitlab-mcp-plus/internal/gitlab"
)

// Environment variables that restrict the tools the server exposes. A tool that
// is not registered cannot be called, whatever the model is told to do, so
// these hold even when the client approves tool calls automatically.
const (
	EnvReadOnly = "GITLAB_MCP_READ_ONLY"
	EnvTools    = "GITLAB_MCP_TOOLS"
)

// toolset holds what the tool handlers share: the GitLab client.
type toolset struct {
	gl *gitlab.Client
}

// NewServer builds the MCP server, reporting version, with the tools the
// policy permits. A panic in a handler becomes an error for that call instead
// of ending the session.
func NewServer(gl *gitlab.Client, policy Policy, version string) *server.MCPServer {
	s := server.NewMCPServer("gitlab-mcp-plus", version, server.WithRecovery())
	(&toolset{gl: gl}).registerTools(filteredAdder{next: s, policy: policy})
	return s
}

// registerTools registers every tool of the server.
func (ts *toolset) registerTools(s toolAdder) {
	ts.registerVulnerabilityTools(s)
	ts.registerVulnerabilityActionTools(s)
	ts.registerPolicyTools(s)
	ts.registerSecurityPostureTools(s)
	ts.registerDuoMetricsTools(s)
	ts.registerAIUsageTools(s)
	ts.registerAIGovernanceTools(s)
	ts.registerGroupTools(s)
	ts.registerBranchTools(s)
}

// Policy decides which tools are registered. The zero value registers every
// tool.
type Policy struct {
	readOnly bool
	allowed  map[string]bool // nil: no allowlist
}

// PolicyFromEnv reads the policy from GITLAB_MCP_READ_ONLY and GITLAB_MCP_TOOLS.
func PolicyFromEnv() (Policy, error) {
	return ParsePolicy(os.Getenv(EnvReadOnly), os.Getenv(EnvTools))
}

// ParsePolicy builds a policy from the values of GITLAB_MCP_READ_ONLY and
// GITLAB_MCP_TOOLS. Anything ambiguous is an error rather than a guess: a
// misspelled tool name, or a write tool listed while read-only is set, would
// otherwise turn the restriction the user asked for into a different one.
func ParsePolicy(readOnly, allowlist string) (Policy, error) {
	var p Policy
	if s := strings.TrimSpace(readOnly); s != "" {
		v, err := strconv.ParseBool(s)
		if err != nil {
			return Policy{}, fmt.Errorf("%s must be true or false, got %q", EnvReadOnly, readOnly)
		}
		p.readOnly = v
	}
	if strings.TrimSpace(allowlist) == "" {
		return p, nil
	}

	catalog := toolCatalog()
	p.allowed = map[string]bool{}
	for _, name := range strings.Split(allowlist, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		tool, ok := catalog[name]
		if !ok {
			return Policy{}, fmt.Errorf("unknown tool %q in %s", name, EnvTools)
		}
		if p.readOnly && !isReadOnly(tool) {
			return Policy{}, fmt.Errorf("%q changes data and %s is set: remove it from %s", name, EnvReadOnly, EnvTools)
		}
		p.allowed[name] = true
	}
	if len(p.allowed) == 0 {
		return Policy{}, fmt.Errorf("%s lists no tool names", EnvTools)
	}
	return p, nil
}

func (p Policy) permits(tool mcp.Tool) bool {
	if p.readOnly && !isReadOnly(tool) {
		return false
	}
	return p.allowed == nil || p.allowed[tool.Name]
}

// toolAdder is the part of *server.MCPServer that tool registration uses.
type toolAdder interface {
	AddTool(tool mcp.Tool, handler server.ToolHandlerFunc)
}

// filteredAdder registers only the tools its policy permits.
type filteredAdder struct {
	next   toolAdder
	policy Policy
}

func (f filteredAdder) AddTool(tool mcp.Tool, handler server.ToolHandlerFunc) {
	if f.policy.permits(tool) {
		f.next.AddTool(tool, handler)
	}
}

func isReadOnly(tool mcp.Tool) bool {
	return tool.Annotations.ReadOnlyHint != nil && *tool.Annotations.ReadOnlyHint
}

// toolCollector records tool definitions without serving them.
type toolCollector map[string]mcp.Tool

func (c toolCollector) AddTool(tool mcp.Tool, _ server.ToolHandlerFunc) { c[tool.Name] = tool }

// toolCatalog returns every tool the server defines, by name. Registration only
// stores the handlers, so a toolset without a client is enough to read the
// definitions.
func toolCatalog() map[string]mcp.Tool {
	c := toolCollector{}
	(&toolset{}).registerTools(c)
	return c
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
