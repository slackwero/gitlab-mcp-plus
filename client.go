package main

import (
	"fmt"
	"strings"
)

// InstallConfig groups the parameters needed to install the MCP server in any
// client.
type InstallConfig struct {
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
func (cfg InstallConfig) serverEnv(token string) map[string]string {
	env := map[string]string{
		"GITLAB_TOKEN": token,
		"GITLAB_URL":   cfg.GitLabURL,
	}
	if cfg.ReadOnly {
		env[envReadOnly] = "true"
	}
	if len(cfg.Tools) > 0 {
		env[envTools] = strings.Join(cfg.Tools, ",")
	}
	return env
}

// MCPClient abstracts the differences between the supported MCP clients
// (claude uses its own CLI; cursor edits a JSON file).
type MCPClient interface {
	Name() string
	SupportedScopes() []string
	Available() error
	IsInstalled(name string, scope string) (bool, error)
	Install(cfg InstallConfig) error
	Uninstall(name string, scope string) error
	PrintConfig(cfg InstallConfig) (string, error)
}

var clients = map[string]MCPClient{
	"claude": &claudeClient{},
	"cursor": &cursorClient{},
}

func resolveClient(name string) (MCPClient, error) {
	c, ok := clients[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unsupported client: %q (supported: claude, cursor)", name)
	}
	return c, nil
}

func validateScope(c MCPClient, scope string) error {
	for _, s := range c.SupportedScopes() {
		if s == scope {
			return nil
		}
	}
	return fmt.Errorf("scope %q is not supported by %s (valid: %s)",
		scope, c.Name(), strings.Join(c.SupportedScopes(), ", "))
}
