package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const branchRoute = "/projects/acme%2Fapp/repository/branches/feature%2Flogin"

func branchJSON(merged, protected, isDefault bool) string {
	return fmt.Sprintf(`{"name":"feature/login","merged":%t,"protected":%t,"default":%t,
	  "commit":{"id":"abc123def","short_id":"abc123d","title":"Add login"}}`, merged, protected, isDefault)
}

func TestDeleteBranch_Guards(t *testing.T) {
	tests := []struct {
		name          string
		branch        string // GET response
		allowUnmerged bool
		wantDeleted   bool
		wantErr       string // message fragment when the branch is not deleted
	}{
		{"merged is deleted", branchJSON(true, false, false), false, true, ""},
		{"unmerged is rejected", branchJSON(false, false, false), false, false, "not merged"},
		{"unmerged with allow_unmerged is deleted", branchJSON(false, false, false), true, true, ""},
		{"default is rejected even with allow_unmerged", branchJSON(true, false, true), true, false, "default branch"},
		{"protected is rejected even with allow_unmerged", branchJSON(true, true, false), true, false, "protected branch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, fake := newScriptedGitLab(t, nil, map[string]fakeResponse{
				"GET " + branchRoute:    {body: tt.branch},
				"DELETE " + branchRoute: {status: 204},
			})
			res, err := app.handleDeleteBranch(context.Background(), callTool(map[string]any{
				"project_path": "acme/app", "branch": "feature/login", "allow_unmerged": tt.allowUnmerged,
			}))

			deletes := 0
			for _, c := range fake.restCalls() {
				if c.Method == "DELETE" {
					deletes++
				}
			}
			if tt.wantDeleted {
				text := resultText(t, res, err)
				if deletes != 1 || !strings.Contains(text, `"lastCommit"`) || !strings.Contains(text, "abc123def") {
					t.Errorf("deletes = %d, result = %s", deletes, text)
				}
				return
			}
			if msg := errorText(t, res, err); !strings.Contains(msg, tt.wantErr) {
				t.Errorf("message = %q, want it to contain %q", msg, tt.wantErr)
			}
			if deletes != 0 {
				t.Errorf("DELETE was sent in a case that must be rejected")
			}
		})
	}
}

func TestDeleteBranch_UnknownBranch(t *testing.T) {
	app, fake := newScriptedGitLab(t, nil, nil) // every route answers 404
	res, err := app.handleDeleteBranch(context.Background(), callTool(map[string]any{
		"project_path": "acme/app", "branch": "feature/login",
	}))
	if msg := errorText(t, res, err); msg != "Branch 'feature/login' not found in project 'acme/app'" {
		t.Errorf("message = %q", msg)
	}
	// A name containing "/" must travel escaped (Review Focus 1).
	if calls := fake.restCalls(); len(calls) != 1 || calls[0].Path != branchRoute {
		t.Errorf("calls = %+v", calls)
	}
}

func TestDeleteBranch_IncompleteResponseFailsClosed(t *testing.T) {
	tests := []struct{ name, body string }{
		{"missing default and protected", `{"name":"feature/login","merged":true,"commit":{"id":"abc123def"}}`},
		{"non-boolean protected", `{"name":"feature/login","merged":true,"default":false,"protected":"yes","commit":{"id":"abc123def"}}`},
		{"missing merged", `{"name":"feature/login","default":false,"protected":false,"commit":{"id":"abc123def"}}`},
		{"empty body", ``},
		// Without the commit id the deleted branch could not be restored.
		{"missing commit", `{"name":"feature/login","merged":true,"default":false,"protected":false}`},
		{"null commit", `{"name":"feature/login","merged":true,"default":false,"protected":false,"commit":null}`},
		{"empty commit id", `{"name":"feature/login","merged":true,"default":false,"protected":false,"commit":{"id":""}}`},
		{"non-string commit id", `{"name":"feature/login","merged":true,"default":false,"protected":false,"commit":{"id":123}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, fake := newScriptedGitLab(t, nil, map[string]fakeResponse{
				"GET " + branchRoute:    {body: tt.body},
				"DELETE " + branchRoute: {status: 204},
			})
			res, err := app.handleDeleteBranch(context.Background(), callTool(map[string]any{
				"project_path": "acme/app", "branch": "feature/login", "allow_unmerged": true,
			}))
			if msg := errorText(t, res, err); !strings.Contains(msg, "Unexpected GitLab response") {
				t.Errorf("message = %q", msg)
			}
			for _, c := range fake.restCalls() {
				if c.Method == "DELETE" {
					t.Errorf("DELETE was sent for an incomplete branch response")
				}
			}
		})
	}
}
