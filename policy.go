package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Environment variables that restrict the tools the server exposes. A tool that
// is not registered cannot be called, whatever the model is told to do, so
// these hold even when the client approves tool calls automatically.
const (
	envReadOnly = "GITLAB_MCP_READ_ONLY"
	envTools    = "GITLAB_MCP_TOOLS"
)

// toolAdder is the part of *server.MCPServer that tool registration uses.
type toolAdder interface {
	AddTool(tool mcp.Tool, handler server.ToolHandlerFunc)
}

// toolPolicy decides which tools are registered. The zero value registers
// every tool.
type toolPolicy struct {
	readOnly bool
	allowed  map[string]bool // nil: no allowlist
}

func toolPolicyFromEnv() (toolPolicy, error) {
	return parseToolPolicy(os.Getenv(envReadOnly), os.Getenv(envTools))
}

// parseToolPolicy builds a policy from the values of GITLAB_MCP_READ_ONLY and
// GITLAB_MCP_TOOLS. Anything ambiguous is an error rather than a guess: a
// misspelled tool name, or a write tool listed while read-only is set, would
// otherwise turn the restriction the user asked for into a different one.
func parseToolPolicy(readOnly, tools string) (toolPolicy, error) {
	var p toolPolicy
	if s := strings.TrimSpace(readOnly); s != "" {
		v, err := strconv.ParseBool(s)
		if err != nil {
			return toolPolicy{}, fmt.Errorf("%s must be true or false, got %q", envReadOnly, readOnly)
		}
		p.readOnly = v
	}
	if strings.TrimSpace(tools) == "" {
		return p, nil
	}

	catalog := toolCatalog()
	p.allowed = map[string]bool{}
	for _, name := range strings.Split(tools, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		tool, ok := catalog[name]
		if !ok {
			return toolPolicy{}, fmt.Errorf("unknown tool %q in %s", name, envTools)
		}
		if p.readOnly && !isReadOnly(tool) {
			return toolPolicy{}, fmt.Errorf("%q changes data and %s is set: remove it from %s", name, envReadOnly, envTools)
		}
		p.allowed[name] = true
	}
	if len(p.allowed) == 0 {
		return toolPolicy{}, fmt.Errorf("%s lists no tool names", envTools)
	}
	return p, nil
}

func (p toolPolicy) permits(tool mcp.Tool) bool {
	if p.readOnly && !isReadOnly(tool) {
		return false
	}
	return p.allowed == nil || p.allowed[tool.Name]
}

// filteredAdder registers only the tools its policy permits.
type filteredAdder struct {
	next   toolAdder
	policy toolPolicy
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
// stores the handlers, so an empty App is enough to read the definitions.
func toolCatalog() map[string]mcp.Tool {
	c := toolCollector{}
	(&App{}).registerTools(c)
	return c
}

// newServer builds the MCP server with the tools the policy permits. A panic in
// a handler becomes an error for that call instead of ending the session.
func newServer(app *App, policy toolPolicy) *server.MCPServer {
	s := server.NewMCPServer("gitlab-mcp-plus", Version, server.WithRecovery())
	app.registerTools(filteredAdder{next: s, policy: policy})
	return s
}
