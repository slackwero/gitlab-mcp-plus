package setup

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strings"
)

// claudeTokenReference is what a project registration stores instead of the
// token. The project scope writes .mcp.json, a file meant to be committed, and
// Claude Code expands ${VAR} in it from the environment of whoever opens the
// project.
const claudeTokenReference = "${GITLAB_TOKEN}"

type claudeClient struct{}

func (c *claudeClient) Name() string { return "claude" }

func (c *claudeClient) SupportedScopes() []string {
	return []string{"user", "project", "local"}
}

func (c *claudeClient) Available() error {
	if _, err := exec.LookPath("claude"); err != nil {
		return errors.New("'claude' CLI not found in PATH. Install Claude Code or use --print-config claude to configure it manually")
	}
	return nil
}

func (c *claudeClient) IsInstalled(name string, _ string) (bool, error) {
	if err := c.Available(); err != nil {
		return false, err
	}
	cmd := exec.Command("claude", "mcp", "get", name)
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		// non-zero exit code → not installed (claude mcp get returns non-zero when it does not exist)
		return false, nil
	}
	return true, nil
}

// tokenValue is the GITLAB_TOKEN value stored in the registration.
func (c *claudeClient) tokenValue(cfg installConfig) string {
	if cfg.Scope == "project" {
		return claudeTokenReference
	}
	return cfg.GitLabToken
}

// addArgs builds the arguments of `claude mcp add`. Outside the project scope
// the token is one of them, visible in the process list while the command
// runs: the claude CLI takes environment values only as arguments.
func (c *claudeClient) addArgs(cfg installConfig) []string {
	args := []string{"mcp", "add", "--scope", cfg.Scope, cfg.Name}
	env := cfg.serverEnv(c.tokenValue(cfg))
	for _, key := range slices.Sorted(maps.Keys(env)) {
		args = append(args, "--env", key+"="+env[key])
	}
	return append(args, "--", cfg.BinaryPath)
}

func (c *claudeClient) Install(cfg installConfig) error {
	if err := c.Available(); err != nil {
		return err
	}
	cmd := exec.Command("claude", c.addArgs(cfg)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("claude mcp add failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (c *claudeClient) Uninstall(name string, scope string) error {
	if err := c.Available(); err != nil {
		return err
	}
	args := []string{"mcp", "remove"}
	if scope != "" {
		args = append(args, "--scope", scope)
	}
	args = append(args, name)
	cmd := exec.Command("claude", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("claude mcp remove failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// PrintConfig prints the `claude mcp add` command without the token. For the
// user and local scopes it reads "$GITLAB_TOKEN" from the shell where it is
// pasted, so the token stays out of the shell history; for the project scope it
// stores the unexpanded reference.
func (c *claudeClient) PrintConfig(cfg installConfig) (string, error) {
	tokenArg := `GITLAB_TOKEN="$GITLAB_TOKEN"`
	note := "Export GITLAB_TOKEN in your shell, then run the following command (it reads the token from the variable):"
	if cfg.Scope == "project" {
		tokenArg = shellQuote("GITLAB_TOKEN=" + claudeTokenReference)
		note = "Run the following command. The token is not stored in .mcp.json: Claude Code reads it from the GITLAB_TOKEN variable of each user."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "claude mcp add --scope %s %s", shellQuote(cfg.Scope), shellQuote(cfg.Name))
	env := cfg.serverEnv("")
	for _, key := range slices.Sorted(maps.Keys(env)) {
		arg := shellQuote(key + "=" + env[key])
		if key == "GITLAB_TOKEN" {
			arg = tokenArg
		}
		fmt.Fprintf(&b, " \\\n  --env %s", arg)
	}
	fmt.Fprintf(&b, " \\\n  -- %s", shellQuote(cfg.BinaryPath))
	return note + "\n\n" + b.String(), nil
}

// shellQuote returns s ready to paste into a POSIX shell: as is when it holds
// only characters the shell does not interpret, otherwise single-quoted.
func shellQuote(s string) string {
	safe := s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=,@%+", r))
	}) == -1
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
