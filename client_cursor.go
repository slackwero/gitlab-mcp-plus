package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
)

const (
	// cursorTokenReference is what a project registration stores instead of
	// the token: <project>/.cursor/mcp.json may be committed, and Cursor
	// expands ${env:NAME} from the environment of whoever opens the project.
	cursorTokenReference = "${env:GITLAB_TOKEN}"
	// cursorTokenPlaceholder stands for the token in printed snippets, which
	// never carry the real value.
	cursorTokenPlaceholder = "<GITLAB_TOKEN>"
)

type cursorClient struct{}

func (c *cursorClient) Name() string { return "cursor" }

func (c *cursorClient) SupportedScopes() []string {
	return []string{"user", "project"}
}

// configPath returns the path of Cursor's MCP configuration file for the
// given scope:
//   - user    -> ~/.cursor/mcp.json
//   - project -> ./.cursor/mcp.json
func (c *cursorClient) configPath(scope string) (string, error) {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".cursor", "mcp.json"), nil
	default:
		return "", fmt.Errorf("invalid scope for cursor: %q (valid: user, project)", scope)
	}
}

// Available always returns nil: Cursor needs no CLI and the file is created
// when missing.
func (c *cursorClient) Available() error { return nil }

// readConfig reads the configuration at path and reports whether the file
// exists. It refuses a symbolic link: following one would let a link planted
// in a project redirect the write, and the token, to any file of the user.
func (c *cursorClient) readConfig(path string) (map[string]any, bool, error) {
	config := map[string]any{"mcpServers": map[string]any{}}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return config, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("refusing to use %s: it is a symbolic link. Edit the file it points to by hand (see --print-config cursor)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, false, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}
	if config["mcpServers"] == nil {
		config["mcpServers"] = map[string]any{}
	}
	return config, true, nil
}

func (c *cursorClient) servers(config map[string]any) map[string]any {
	s, _ := config["mcpServers"].(map[string]any)
	if s == nil {
		s = map[string]any{}
		config["mcpServers"] = s
	}
	return s
}

func (c *cursorClient) IsInstalled(name string, scope string) (bool, error) {
	path, err := c.configPath(scope)
	if err != nil {
		return false, err
	}
	cfg, _, err := c.readConfig(path)
	if err != nil {
		return false, err
	}
	_, exists := c.servers(cfg)[name]
	return exists, nil
}

func (c *cursorClient) writeConfig(path string, config map[string]any) error {
	out, err := indentJSON(config)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out)
}

// writeFileAtomic replaces path with data through a temporary file created in
// the same directory (exclusively, with 0600) and renamed over path. Nothing is
// written through a symbolic link, the result is private whatever the
// permissions of the file it replaces, and a failure never leaves it half
// written.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// withoutServer returns a copy of config without the server name.
func withoutServer(config map[string]any, name string) map[string]any {
	out := maps.Clone(config)
	if servers, ok := config["mcpServers"].(map[string]any); ok {
		kept := maps.Clone(servers)
		delete(kept, name)
		out["mcpServers"] = kept
	}
	return out
}

// entry is the mcpServers entry of the server, with token as GITLAB_TOKEN.
func (c *cursorClient) entry(cfg InstallConfig, token string) map[string]any {
	return map[string]any{
		"command": cfg.BinaryPath,
		"args":    []string{},
		"env":     cfg.serverEnv(token),
	}
}

func (c *cursorClient) Install(cfg InstallConfig) error {
	path, err := c.configPath(cfg.Scope)
	if err != nil {
		return err
	}
	config, existed, err := c.readConfig(path)
	if err != nil {
		return err
	}
	servers := c.servers(config)
	if _, exists := servers[cfg.Name]; exists && !cfg.Force {
		return fmt.Errorf("'%s' already exists in %s; use --force to overwrite", cfg.Name, path)
	}

	// The backup is the previous file without this server's entry, so it
	// never keeps a token that this install replaces or a later uninstall
	// removes.
	if existed {
		backup, err := indentJSON(withoutServer(config, cfg.Name))
		if err != nil {
			return err
		}
		if err := writeFileAtomic(path+".bak", backup); err != nil {
			return fmt.Errorf("writing the backup of %s: %w", path, err)
		}
	}

	token := cfg.GitLabToken
	if cfg.Scope == "project" {
		token = cursorTokenReference
	}
	servers[cfg.Name] = c.entry(cfg, token)
	return c.writeConfig(path, config)
}

func (c *cursorClient) Uninstall(name string, scope string) error {
	path, err := c.configPath(scope)
	if err != nil {
		return err
	}
	config, _, err := c.readConfig(path)
	if err != nil {
		return err
	}
	servers := c.servers(config)
	if _, exists := servers[name]; !exists {
		return fmt.Errorf("'%s' is not registered in %s", name, path)
	}
	delete(servers, name)
	return c.writeConfig(path, config)
}

// PrintConfig prints the JSON entry without the token: a placeholder for the
// user scope, the ${env:GITLAB_TOKEN} reference for the project scope.
func (c *cursorClient) PrintConfig(cfg InstallConfig) (string, error) {
	path, err := c.configPath(cfg.Scope)
	if err != nil {
		return "", err
	}
	token, note := cursorTokenPlaceholder, "and replace "+cursorTokenPlaceholder+" with your token"
	if cfg.Scope == "project" {
		token, note = cursorTokenReference, "(Cursor reads the token from the GITLAB_TOKEN variable of each user)"
	}
	snippet := map[string]any{"mcpServers": map[string]any{cfg.Name: c.entry(cfg, token)}}
	out, err := indentJSON(snippet)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Add (or merge with the existing content) the following JSON to %s %s:\n\n%s", path, note, out), nil
}

// indentJSON renders v as indented JSON ending in a newline. Unlike
// json.MarshalIndent it leaves <, > and & unescaped, so a placeholder such as
// <GITLAB_TOKEN> stays readable for whoever copies the snippet.
func indentJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
