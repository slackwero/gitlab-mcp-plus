package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestParseToolPolicy_Rejects(t *testing.T) {
	cases := []struct {
		name, readOnly, tools, wantErr string
	}{
		{"read-only flag that is not a boolean", "yes please", "", "GITLAB_MCP_READ_ONLY must be true or false"},
		{"allowlist with no names", "", " , ", "GITLAB_MCP_TOOLS lists no tool names"},
		{"unknown tool", "", "list_vulnerabilities,list_vulnerabilitys", `unknown tool "list_vulnerabilitys" in GITLAB_MCP_TOOLS`},
		{"write tool while read-only", "true", "list_vulnerabilities,delete_branch", `"delete_branch" changes data`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseToolPolicy(c.readOnly, c.tools)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, c.wantErr)
			}
		})
	}
}

func serverToolNames(t *testing.T, readOnly, tools string) []string {
	t.Helper()
	policy, err := parseToolPolicy(readOnly, tools)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(NewApp("test-token", "https://gitlab.invalid"), policy)
	names := make([]string, 0)
	for name := range s.ListTools() {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func TestNewServer_DefaultPolicyRegistersEveryTool(t *testing.T) {
	if got, want := len(serverToolNames(t, "", "")), len(toolCatalog()); got != want {
		t.Errorf("registered %d tools, want all %d", got, want)
	}
}

func TestNewServer_ReadOnlyRegistersOnlyReadTools(t *testing.T) {
	names := serverToolNames(t, "true", "")
	catalog := toolCatalog()
	readTools := 0
	for _, tool := range catalog {
		if isReadOnly(tool) {
			readTools++
		}
	}
	if len(names) != readTools {
		t.Errorf("registered %d tools, want the %d read tools", len(names), readTools)
	}
	for _, name := range names {
		if !isReadOnly(catalog[name]) {
			t.Errorf("read-only mode registered the write tool %q", name)
		}
	}
}

func TestNewServer_AllowlistRegistersOnlyListedTools(t *testing.T) {
	got := serverToolNames(t, "false", " get_vulnerability , list_vulnerabilities,")
	want := []string{"get_vulnerability", "list_vulnerabilities"}
	if !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}
}

func TestNewServer_RecoversFromHandlerPanics(t *testing.T) {
	s := newServer(NewApp("test-token", "https://gitlab.invalid"), toolPolicy{})
	s.AddTool(mcp.NewTool("boom"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		panic("handler bug")
	})
	call, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "boom", "arguments": map[string]any{}},
	})
	resp := s.HandleMessage(context.Background(), call) // must not panic
	raw, _ := json.Marshal(resp)
	if !strings.Contains(string(raw), "panic recovered") {
		t.Errorf("response = %s, want the recovered panic reported", raw)
	}
}
