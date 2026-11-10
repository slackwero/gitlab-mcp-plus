package setup

import (
	"fmt"
	"strings"

	"github.com/slackwero/gitlab-mcp-plus/internal/tools"
)

// installConfig groups the parameters needed to install the MCP server in any
// client.
type installConfig struct {
	Name        string
	BinaryPath  string
	GitLabToken string
	GitLabURL   string
	Scope       string
	Force       bool

	ReadOnly bool     // registers GITLAB_MCP_READ_ONLY=true
	Tools    []string // registers GITLAB_MCP_TOOLS when not empty
}

// serverEnv returns the environment the client passes to the server, with
// token as the value of GITLAB_TOKEN: the token itself, or a reference the
// client expands from the user's environment when it starts the server.
func (cfg installConfig) serverEnv(token string) map[string]string {
	env := map[string]string{
		"GITLAB_TOKEN": token,
		"GITLAB_URL":   cfg.GitLabURL,
	}
	if cfg.ReadOnly {
		env[tools.EnvReadOnly] = "true"
	}
	if len(cfg.Tools) > 0 {
		env[tools.EnvTools] = strings.Join(cfg.Tools, ",")
	}
	return env
}

// mcpClient abstracts the differences between the supported MCP clients
// (claude uses its own CLI; cursor edits a JSON file).
type mcpClient interface {
	Name() string
	SupportedScopes() []string
	Available() error
	IsInstalled(name string, scope string) (bool, error)
	Install(cfg installConfig) error
	Uninstall(name string, scope string) error
	PrintConfig(cfg installConfig) (string, error)
}

var clients = map[string]mcpClient{
	"claude": &claudeClient{},
	"cursor": &cursorClient{},
}

func resolveClient(name string) (mcpClient, error) {
	c, ok := clients[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unsupported client: %q (supported: claude, cursor)", name)
	}
	return c, nil
}

func validateScope(c mcpClient, scope string) error {
	for _, s := range c.SupportedScopes() {
		if s == scope {
			return nil
		}
	}
	return fmt.Errorf("scope %q is not supported by %s (valid: %s)",
		scope, c.Name(), strings.Join(c.SupportedScopes(), ", "))
}
