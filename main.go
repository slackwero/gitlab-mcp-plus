// Command gitlab-mcp-plus is an MCP server that extends the official GitLab MCP
// server with security, compliance and GitLab Duo tools. Run with no arguments
// it serves over stdio; --install and the other flags register it in MCP
// clients.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/mark3labs/mcp-go/server"

	"github.com/slackwero/gitlab-mcp-plus/internal/gitlab"
	"github.com/slackwero/gitlab-mcp-plus/internal/setup"
	"github.com/slackwero/gitlab-mcp-plus/internal/tools"
)

// Variables injected at build time via -ldflags. A binary built locally with
// `go build` keeps their default values.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
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

func main() {
	var (
		showVersion     bool
		showHelp        bool
		installFlag     string
		uninstallFlag   string
		checkFlag       string
		printConfigFlag string
		serverNameFlag  string
		scopeFlag       string
		gitlabTokenFlag string
		gitlabURLFlag   string
		forceFlag       bool
		yesFlag         bool
		noValidateFlag  bool
		readOnlyFlag    bool
		toolsFlag       string
	)

	flag.BoolVar(&showVersion, "version", false, "Print the version and exit")
	flag.BoolVar(&showHelp, "help", false, "Show the help and exit")
	flag.BoolVar(&showHelp, "h", false, "Show the help and exit (alias)")

	flag.StringVar(&installFlag, "install", "", "Install the MCP server in a client: claude|cursor")
	flag.StringVar(&uninstallFlag, "uninstall", "", "Uninstall the MCP server from a client: claude|cursor")
	flag.StringVar(&checkFlag, "check", "", "Check the installation in a client: claude|cursor")
	flag.StringVar(&printConfigFlag, "print-config", "", "Print the manual configuration for a client: claude|cursor")

	flag.StringVar(&serverNameFlag, "name", "gitlab-mcp-plus", "Name to register the MCP server under")
	flag.StringVar(&scopeFlag, "scope", "user", "Scope to register in: user|project (claude also accepts 'local')")
	flag.StringVar(&gitlabTokenFlag, "gitlab-token", "", "GitLab token (overrides $GITLAB_TOKEN)")
	flag.StringVar(&gitlabURLFlag, "gitlab-url", "", "GitLab URL (overrides $GITLAB_URL)")
	flag.BoolVar(&forceFlag, "force", false, "Overwrite if it already exists")
	flag.BoolVar(&forceFlag, "f", false, "Overwrite if it already exists (alias)")
	flag.BoolVar(&yesFlag, "yes", false, "Skip interactive confirmations")
	flag.BoolVar(&yesFlag, "y", false, "Skip interactive confirmations (alias)")
	flag.BoolVar(&noValidateFlag, "no-validate", false, "Do not validate the GitLab token against the API")
	flag.BoolVar(&readOnlyFlag, "read-only", false, "Register the server with only its read tools ("+tools.EnvReadOnly+"=true)")
	flag.StringVar(&toolsFlag, "tools", "", "Register the server with only these comma-separated tools ("+tools.EnvTools+")")

	flag.Usage = printHelp
	flag.Parse()

	if showHelp {
		printHelp()
		return
	}
	if showVersion {
		printVersion()
		return
	}

	if gitlabTokenFlag != "" {
		fmt.Fprintln(os.Stderr, "warning: --gitlab-token leaves the token in your shell history and in the process list; "+
			"prefer exporting GITLAB_TOKEN or the hidden prompt")
	}

	opts := setup.Options{
		Name:       serverNameFlag,
		Scope:      scopeFlag,
		Token:      gitlabTokenFlag,
		URL:        gitlabURLFlag,
		Force:      forceFlag,
		Yes:        yesFlag,
		NoValidate: noValidateFlag,
		ReadOnly:   readOnlyFlag,
		Tools:      toolsFlag,
	}

	switch {
	case installFlag != "":
		exitOn(setup.Install(installFlag, opts))
	case uninstallFlag != "":
		exitOn(setup.Uninstall(uninstallFlag, opts))
	case checkFlag != "":
		exitOn(setup.Check(checkFlag, opts))
	case printConfigFlag != "":
		exitOn(setup.PrintConfig(printConfigFlag, opts))
	default:
		runServer()
	}
}

func runServer() {
	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "gitlab-mcp-plus: GITLAB_TOKEN environment variable is required")
		os.Exit(1)
	}

	gitlabURL, err := gitlab.NormalizeURL(os.Getenv("GITLAB_URL"))
	if err != nil {
		exitServer(fmt.Errorf("GITLAB_URL: %w", err))
	}
	policy, err := tools.PolicyFromEnv()
	if err != nil {
		exitServer(err)
	}

	s := tools.NewServer(gitlab.NewClient(token, gitlabURL), policy, Version)
	if err := server.ServeStdio(s); err != nil {
		exitServer(err)
	}
}

// exitServer reports a startup or transport failure on stderr, which MCP
// clients show in their server logs, and exits.
func exitServer(err error) {
	fmt.Fprintf(os.Stderr, "gitlab-mcp-plus: %v\n", err)
	os.Exit(1)
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Fprint(os.Stdout, usageHelp)
}

func printVersion() {
	fmt.Printf("gitlab-mcp-plus %s (commit %s, built %s, %s/%s)\n",
		Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH)
}
