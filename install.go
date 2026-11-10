package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// adminOpts groups the flags shared by all administrative subcommands
// (install / uninstall / check / print-config).
type adminOpts struct {
	Name       string
	Scope      string
	Token      string
	URL        string
	Force      bool
	Yes        bool
	NoValidate bool
	ReadOnly   bool
	Tools      string // comma-separated allowlist
}

// resolveTokenAndURL applies the precedence: flag > env > prompt (when
// allowPrompt is set and a TTY is available) > error. For the URL: flag > env >
// default https://gitlab.com, validated before the token is asked for.
func resolveTokenAndURL(opts adminOpts, allowPrompt bool) (string, string, error) {
	url, err := resolveURL(opts)
	if err != nil {
		return "", "", err
	}

	token := opts.Token
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	if token == "" && allowPrompt {
		t, err := promptToken()
		if err != nil {
			return "", "", err
		}
		token = t
	}
	if token == "" {
		return "", "", errors.New("GITLAB_TOKEN is not set. Use --gitlab-token or export the environment variable")
	}
	return token, url, nil
}

// resolveURL returns the validated GitLab URL: flag > env > https://gitlab.com.
func resolveURL(opts adminOpts) (string, error) {
	return normalizeGitLabURL(cmp.Or(opts.URL, os.Getenv("GITLAB_URL")))
}

// toolOptions validates --read-only and --tools exactly as the server will
// read them, so a typo fails now instead of when the client starts the server,
// and returns the allowlist.
func toolOptions(opts adminOpts) ([]string, error) {
	readOnly := ""
	if opts.ReadOnly {
		readOnly = "true"
	}
	if _, err := parseToolPolicy(readOnly, opts.Tools); err != nil {
		return nil, fmt.Errorf("--read-only/--tools: %w", err)
	}
	var tools []string
	for _, name := range strings.Split(opts.Tools, ",") {
		if name = strings.TrimSpace(name); name != "" {
			tools = append(tools, name)
		}
	}
	return tools, nil
}

// describeTools summarizes the tool restrictions of a registration.
func describeTools(readOnly bool, tools []string) string {
	switch {
	case len(tools) > 0 && readOnly:
		return "read-only, only " + strings.Join(tools, ", ")
	case len(tools) > 0:
		return "only " + strings.Join(tools, ", ")
	case readOnly:
		return "read-only (write tools are not registered)"
	}
	return "all"
}

// resolveBinaryPath returns the absolute path of the running binary, resolving
// symlinks so the registration always points to the real binary.
func resolveBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		return real, nil
	}
	return exe, nil
}

func runInstall(clientName string, opts adminOpts) error {
	client, err := resolveClient(clientName)
	if err != nil {
		return err
	}
	if err := validateScope(client, opts.Scope); err != nil {
		return err
	}

	tools, err := toolOptions(opts)
	if err != nil {
		return err
	}
	token, url, err := resolveTokenAndURL(opts, true)
	if err != nil {
		return err
	}

	binaryPath, err := resolveBinaryPath()
	if err != nil {
		return fmt.Errorf("could not resolve the binary path: %w", err)
	}

	if !opts.NoValidate {
		username, err := validateGitLabToken(context.Background(), nil, url, token)
		if err != nil {
			return fmt.Errorf("token validation failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "✓ Valid token (user: %s)\n", username)
	}

	if err := client.Available(); err != nil {
		return err
	}

	existed, err := client.IsInstalled(opts.Name, opts.Scope)
	if err != nil {
		return err
	}
	if existed && !opts.Force {
		if opts.Yes {
			return fmt.Errorf("'%s' already exists in %s (--scope %s); use --force to overwrite",
				opts.Name, client.Name(), opts.Scope)
		}
		ok, err := promptYesNo(
			fmt.Sprintf("'%s' already exists in %s. Overwrite?", opts.Name, client.Name()), false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("installation aborted by the user")
		}
		opts.Force = true
	}

	// Summary shown before running.
	fmt.Fprintln(os.Stderr, "\nInstallation summary:")
	fmt.Fprintf(os.Stderr, "  Client:   %s\n", client.Name())
	fmt.Fprintf(os.Stderr, "  Name:     %s\n", opts.Name)
	fmt.Fprintf(os.Stderr, "  Scope:    %s\n", opts.Scope)
	fmt.Fprintf(os.Stderr, "  Binary:   %s\n", binaryPath)
	if opts.Scope == "project" {
		fmt.Fprintln(os.Stderr, "  Token:    not stored; read from the GITLAB_TOKEN variable of each user")
	} else {
		fmt.Fprintf(os.Stderr, "  Token:    %s\n", maskToken(token))
	}
	fmt.Fprintf(os.Stderr, "  GitLab:   %s\n", url)
	fmt.Fprintf(os.Stderr, "  Tools:    %s\n\n", describeTools(opts.ReadOnly, tools))

	if !opts.Yes {
		ok, err := promptYesNo("Proceed with the installation?", true)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("installation aborted by the user")
		}
	}

	cfg := InstallConfig{
		Name:        opts.Name,
		BinaryPath:  binaryPath,
		GitLabToken: token,
		GitLabURL:   url,
		Scope:       opts.Scope,
		Force:       opts.Force,
		ReadOnly:    opts.ReadOnly,
		Tools:       tools,
	}

	if existed && opts.Force {
		if err := client.Uninstall(opts.Name, opts.Scope); err != nil {
			return fmt.Errorf("could not remove the previous registration: %w", err)
		}
	}

	if err := client.Install(cfg); err != nil {
		return err
	}

	installed, err := client.IsInstalled(opts.Name, opts.Scope)
	if err != nil || !installed {
		return fmt.Errorf("the installation ran but the follow-up verification failed")
	}

	fmt.Fprintf(os.Stderr, "\n✓ '%s' installed successfully in %s.\n", opts.Name, client.Name())
	if opts.Scope == "project" {
		fmt.Fprintf(os.Stderr, "  The project configuration does not contain the token: everyone who opens this\n"+
			"  project must have GITLAB_TOKEN exported in the environment %s starts from.\n", client.Name())
	}
	fmt.Fprintln(os.Stderr, "  Restart the client so it loads the new MCP server.")
	return nil
}

func runUninstall(clientName string, opts adminOpts) error {
	client, err := resolveClient(clientName)
	if err != nil {
		return err
	}
	if err := validateScope(client, opts.Scope); err != nil {
		return err
	}
	if err := client.Available(); err != nil {
		return err
	}
	installed, err := client.IsInstalled(opts.Name, opts.Scope)
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("'%s' is not registered in %s (--scope %s)",
			opts.Name, client.Name(), opts.Scope)
	}
	if !opts.Yes {
		ok, err := promptYesNo(
			fmt.Sprintf("Confirm uninstalling '%s' from %s?", opts.Name, client.Name()), false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("uninstall aborted")
		}
	}
	if err := client.Uninstall(opts.Name, opts.Scope); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ '%s' uninstalled from %s.\n", opts.Name, client.Name())
	return nil
}

func runCheck(clientName string, opts adminOpts) error {
	client, err := resolveClient(clientName)
	if err != nil {
		return err
	}
	if err := validateScope(client, opts.Scope); err != nil {
		return err
	}

	fmt.Println("Installation diagnostics")
	fmt.Printf("  Client:         %s\n", client.Name())
	fmt.Printf("  Scope:          %s\n", opts.Scope)
	fmt.Printf("  MCP name:       %s\n", opts.Name)

	if err := client.Available(); err != nil {
		fmt.Printf("  Availability:   ✗ %v\n", err)
	} else {
		fmt.Println("  Availability:   ✓")
	}

	if binaryPath, err := resolveBinaryPath(); err == nil {
		fmt.Printf("  Binary:         %s\n", binaryPath)
	}

	installed, err := client.IsInstalled(opts.Name, opts.Scope)
	switch {
	case err != nil:
		fmt.Printf("  Registration:   ✗ %v\n", err)
	case installed:
		fmt.Println("  Registration:   ✓ installed")
	default:
		fmt.Println("  Registration:   ✗ not installed")
	}

	if !opts.NoValidate {
		token, url, err := resolveTokenAndURL(opts, false)
		if err != nil {
			fmt.Printf("  GitLab token:   ⚠ %v\n", err)
		} else {
			username, err := validateGitLabToken(context.Background(), nil, url, token)
			if err != nil {
				fmt.Printf("  GitLab token:   ✗ %v\n", err)
			} else {
				fmt.Printf("  GitLab token:   ✓ (user: %s, url: %s)\n", username, url)
			}
		}
	}
	return nil
}

func runPrintConfig(clientName string, opts adminOpts) error {
	client, err := resolveClient(clientName)
	if err != nil {
		return err
	}
	if err := validateScope(client, opts.Scope); err != nil {
		return err
	}

	// The snippet never carries the token, so none is needed here.
	url, err := resolveURL(opts)
	if err != nil {
		return err
	}
	tools, err := toolOptions(opts)
	if err != nil {
		return err
	}
	binaryPath, err := resolveBinaryPath()
	if err != nil {
		return err
	}

	cfg := InstallConfig{
		Name:       opts.Name,
		BinaryPath: binaryPath,
		GitLabURL:  url,
		Scope:      opts.Scope,
		ReadOnly:   opts.ReadOnly,
		Tools:      tools,
	}
	out, err := client.PrintConfig(cfg)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
