package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testTokenA = "glpat-first-token-aaaa"
	testTokenB = "glpat-second-token-bbbb"
)

func cursorConfig(token, scope string) installConfig {
	return installConfig{
		Name:        "gitlab-mcp-plus",
		BinaryPath:  "/usr/local/bin/gitlab-mcp-plus",
		GitLabToken: token,
		GitLabURL:   "https://gitlab.com",
		Scope:       scope,
		Force:       true,
	}
}

// cursorHome points HOME to a fresh directory and returns ~/.cursor.
func cursorHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return filepath.Join(home, ".cursor")
}

// filesContaining returns the files under dir whose content includes s.
func filesContaining(t *testing.T, dir, s string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), s) {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestCursorPrintConfig_NeverPrintsTheToken(t *testing.T) {
	cursorHome(t)
	out, err := (&cursorClient{}).PrintConfig(cursorConfig(testTokenA, "user"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, testTokenA) {
		t.Errorf("the snippet prints the token:\n%s", out)
	}
	if !strings.Contains(out, `"GITLAB_TOKEN": "<GITLAB_TOKEN>"`) {
		t.Errorf("the snippet lacks a readable placeholder:\n%s", out)
	}
}

func TestCursorInstall_WritesPrivateFileAndKeepsOtherServers(t *testing.T) {
	dir := cursorHome(t)
	path := filepath.Join(dir, "mcp.json")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"other":{"command":"other-mcp"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := (&cursorClient{}).Install(cursorConfig(testTokenA, "user")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mcp.json permissions = %o, want 600", perm)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"other-mcp"`) || !strings.Contains(string(data), testTokenA) {
		t.Errorf("mcp.json = %s", data)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) > 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestCursorInstall_BackupNeverKeepsTheToken(t *testing.T) {
	dir := cursorHome(t)
	client := &cursorClient{}
	if err := client.Install(cursorConfig(testTokenA, "user")); err != nil {
		t.Fatal(err)
	}
	if err := client.Install(cursorConfig(testTokenB, "user")); err != nil {
		t.Fatal(err)
	}
	if found := filesContaining(t, dir, testTokenA); len(found) > 0 {
		t.Errorf("the replaced token survives in %v", found)
	}

	if err := client.Uninstall("gitlab-mcp-plus", "user"); err != nil {
		t.Fatal(err)
	}
	if found := filesContaining(t, dir, testTokenB); len(found) > 0 {
		t.Errorf("the token survives the uninstall in %v", found)
	}
	if info, err := os.Stat(filepath.Join(dir, "mcp.json.bak")); err == nil && info.Mode().Perm() != 0o600 {
		t.Errorf("mcp.json.bak permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestCursorInstall_RefusesASymlinkedConfig(t *testing.T) {
	dir := cursorHome(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "mcp.json")); err != nil {
		t.Fatal(err)
	}

	err := (&cursorClient{}).Install(cursorConfig(testTokenA, "user"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("err = %v, want a refusal to follow the symbolic link", err)
	}
	if data, _ := os.ReadFile(target); string(data) != `{}` {
		t.Errorf("the link target was modified: %s", data)
	}
}

func TestCursorInstall_ProjectScopeReferencesTheToken(t *testing.T) {
	cursorHome(t)
	project := t.TempDir()
	t.Chdir(project)

	cfg := cursorConfig(testTokenA, "project")
	cfg.ReadOnly = true
	if err := (&cursorClient{}).Install(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(project, ".cursor", "mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), testTokenA) {
		t.Errorf("the project file contains the token: %s", data)
	}
	for _, want := range []string{`"GITLAB_TOKEN": "${env:GITLAB_TOKEN}"`, `"GITLAB_MCP_READ_ONLY": "true"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the project file lacks %s: %s", want, data)
		}
	}
}
