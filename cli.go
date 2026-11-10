package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

const usageHelp = `gitlab-mcp-plus — MCP server that extends the official GitLab MCP with security, compliance and GitLab Duo operations

Usage:
  gitlab-mcp-plus                                    Start the MCP server (stdio)
  gitlab-mcp-plus --version                          Print the version and exit
  gitlab-mcp-plus --help                             Show this help

  gitlab-mcp-plus --install      <claude|cursor>     Install the MCP server in the client
  gitlab-mcp-plus --uninstall    <claude|cursor>     Remove the registration from the client
  gitlab-mcp-plus --check        <claude|cursor>     Diagnose an installation
  gitlab-mcp-plus --print-config <claude|cursor>     Print the manual configuration

Flags:
  --version                Print the version and exit
  --help, -h               Show this help

  --install <client>       Install the MCP server in claude or cursor
  --uninstall <client>     Uninstall the MCP server from the client
  --check <client>         Check the registration, client availability, binary and token
  --print-config <client>  Print the command or JSON to configure it manually

  --name <string>          MCP server name (default: gitlab-mcp-plus)
  --scope <user|project>   Scope to register in (default: user; claude also accepts 'local')
  --gitlab-token <string>  Overrides $GITLAB_TOKEN
  --gitlab-url <string>    Overrides $GITLAB_URL (default: https://gitlab.com)
  --force, -f              Overwrite an existing registration
  --yes, -y                Skip interactive confirmations
  --no-validate            Do not validate the GitLab token against the API before installing
  --read-only              Register the server with only its read tools
  --tools <a,b,...>        Register the server with only these tools

Environment variables:
  GITLAB_TOKEN             Token with the 'api' scope ('read_api' for read-only use); required to serve
  GITLAB_URL               GitLab instance URL, https only (default: https://gitlab.com)
  GITLAB_MCP_READ_ONLY     true: do not expose the tools that change data
  GITLAB_MCP_TOOLS         Comma-separated allowlist of the tools to expose

Examples:
  # Serve the MCP (normal use from Claude Code / Cursor)
  GITLAB_TOKEN=glpat-xxx gitlab-mcp-plus

  # Automatic installation in Claude Code
  GITLAB_TOKEN=glpat-xxx gitlab-mcp-plus --install claude

  # Installation in Cursor with project scope (the file references $GITLAB_TOKEN)
  gitlab-mcp-plus --install cursor --scope project

  # Reinstall without prompting
  gitlab-mcp-plus --install claude --force --yes

  # Expose only the read tools
  gitlab-mcp-plus --install claude --read-only

  # Diagnose an existing installation
  gitlab-mcp-plus --check claude

  # Get the snippet for manual configuration
  gitlab-mcp-plus --print-config cursor
`

func printHelp() {
	fmt.Fprint(os.Stdout, usageHelp)
}

func printVersion() {
	fmt.Printf("gitlab-mcp-plus %s (commit %s, built %s, %s/%s)\n",
		Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH)
}

// maskToken returns a masked version of the token, keeping the first 4 and
// last 4 characters to make visual verification easier.
func maskToken(t string) string {
	if t == "" {
		return ""
	}
	if len(t) <= 8 {
		return strings.Repeat("*", len(t))
	}
	return t[:4] + strings.Repeat("*", 8) + t[len(t)-4:]
}

// promptToken reads a token from stdin without echo. Requires a TTY.
func promptToken() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no TTY available to read the token; set GITLAB_TOKEN or use --gitlab-token")
	}
	fmt.Fprint(os.Stderr, "GitLab Personal Access Token (scope api): ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// promptYesNo asks the user for confirmation. Without a TTY it returns defaultYes.
func promptYesNo(question string, defaultYes bool) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return defaultYes, nil
	}
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(os.Stderr, "%s %s ", question, suffix)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return defaultYes, nil
	}
	return line == "y" || line == "yes", nil
}
