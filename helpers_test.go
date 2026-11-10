package main

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestGID(t *testing.T) {
	if got := gid("Vulnerability", "123"); got != "gid://gitlab/Vulnerability/123" {
		t.Errorf("gid = %q", got)
	}
	if got := gid("Issue", "gid://gitlab/Issue/9"); got != "gid://gitlab/Issue/9" {
		t.Errorf("a full gid must not change, got %q", got)
	}
}

func TestGIDList_Limits(t *testing.T) {
	if _, err := gidList("ids", "Vulnerability", []any{}, 100); err == nil || err.Error() != "ids is required" {
		t.Errorf("empty list: err = %v", err)
	}
	many := make([]any, 101)
	for i := range many {
		many[i] = strconv.Itoa(i + 1)
	}
	_, err := gidList("ids", "Vulnerability", many, 100)
	if err == nil || err.Error() != "ids accepts at most 100 entries (got 101)" {
		t.Errorf("101 entries: err = %v", err)
	}
	got, err := gidList("ids", "Vulnerability", []any{" 7", "gid://gitlab/Vulnerability/8 "}, 100)
	want := []string{"gid://gitlab/Vulnerability/7", "gid://gitlab/Vulnerability/8"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, err %v", got, err)
	}
	// Numbers are not IDs: a list of them is invalid, not empty.
	if _, err := gidList("ids", "Vulnerability", []any{float64(7), float64(8)}, 100); err == nil ||
		err.Error() != "ids must contain only non-empty strings (entry 1 is not)" {
		t.Errorf("numeric list: err = %v", err)
	}
}

func TestLimitedStrings(t *testing.T) {
	many := make([]any, 1001)
	for i := range many {
		many[i] = "u-" + strconv.Itoa(i)
	}
	if _, err := limitedStrings("finding_uuids", many, 1000); err == nil ||
		err.Error() != "finding_uuids accepts at most 1000 entries (got 1001)" {
		t.Errorf("1001 entries: err = %v", err)
	}
	if got, err := limitedStrings("finding_uuids", nil, 1000); err != nil || len(got) != 0 {
		t.Errorf("absent or null: got %v, err %v", got, err)
	}
	// The cap counts every received entry, not only the valid ones.
	many[1000] = ""
	if _, err := limitedStrings("finding_uuids", many, 1000); err == nil ||
		err.Error() != "finding_uuids accepts at most 1000 entries (got 1001)" {
		t.Errorf("1001 entries with an invalid one: err = %v", err)
	}
}

func TestLimitedStrings_RejectsTheWholeListOnAnyInvalidEntry(t *testing.T) {
	// A write tool must act on exactly the entries it was given: one bad
	// entry rejects the list instead of being dropped.
	tests := []struct {
		name    string
		arg     any
		wantErr string
	}{
		{"string instead of array", "u-1", "finding_uuids must be an array of strings"},
		{"object instead of array", map[string]any{"0": "u-1"}, "finding_uuids must be an array of strings"},
		{"number entry", []any{"u-1", float64(5)}, "finding_uuids must contain only non-empty strings (entry 2 is not)"},
		{"empty entry", []any{"", "u-2"}, "finding_uuids must contain only non-empty strings (entry 1 is not)"},
		{"blank entry", []any{"u-1", " \t\n"}, "finding_uuids must contain only non-empty strings (entry 2 is not)"},
		{"null entry", []any{"u-1", "u-2", nil}, "finding_uuids must contain only non-empty strings (entry 3 is not)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := limitedStrings("finding_uuids", tt.arg, 1000)
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("got %v, err = %v, want %q", got, err, tt.wantErr)
			}
		})
	}

	got, err := limitedStrings("finding_uuids", []any{"u-1", "u-2"}, 1000)
	if want := []string{"u-1", "u-2"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("valid list: got %v, err %v", got, err)
	}
}

func TestLimitedStrings_SendsEntriesTrimmed(t *testing.T) {
	got, err := limitedStrings("finding_uuids", []any{" u-1", "u-2\n", "\tu 3 "}, 1000)
	if want := []string{"u-1", "u-2", "u 3"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, err %v, want %q", got, err, want)
	}
}

func TestPageSize(t *testing.T) {
	cases := map[string]struct {
		args map[string]any
		want int
	}{
		"absent":   {map[string]any{}, 20},
		"zero":     {map[string]any{"first": float64(0)}, 20},
		"in range": {map[string]any{"first": float64(50)}, 50},
		"over cap": {map[string]any{"first": float64(500)}, 100},
	}
	for name, c := range cases {
		if got := pageSize(c.args); got != c.want {
			t.Errorf("%s: pageSize = %d, want %d", name, got, c.want)
		}
	}
}

func TestResolveGID(t *testing.T) {
	app, fake := newScriptedGitLab(t, []string{`{"data":{"group":{"id":"gid://gitlab/Group/42"}}}`}, nil)
	id, err := app.resolveGID(context.Background(), "group", "acme")
	if err != nil || id != "gid://gitlab/Group/42" {
		t.Fatalf("id = %q, err = %v", id, err)
	}
	if q := fake.graphQLCalls()[0].Query; !strings.Contains(q, "group(fullPath: $fullPath)") {
		t.Errorf("query does not use the group root: %s", q)
	}

	app, _ = newScriptedGitLab(t, []string{`{"data":{"project":null}}`}, nil)
	if _, err := app.resolveGID(context.Background(), "project", "acme/app"); err == nil || err.Error() != "Project 'acme/app' not found" {
		t.Errorf("null root: err = %v", err)
	}
}

func TestPayloadError(t *testing.T) {
	// A mutation payload with an empty errors list is a success; any message
	// in it must reach the client.
	if res := payloadError("dismiss", map[string]any{"errors": []any{}}); res != nil {
		t.Errorf("empty errors must yield nil, got %+v", res)
	}
	res := payloadError("dismiss", map[string]any{"errors": []any{"not allowed", "already dismissed"}})
	if msg := errorText(t, res, nil); msg != "Failed to dismiss: not allowed, already dismissed" {
		t.Errorf("message = %q", msg)
	}
}

func TestScriptedGitLab_ServesRESTRoutesAndRecordsCalls(t *testing.T) {
	app, fake := newScriptedGitLab(t, nil, map[string]fakeResponse{
		"GET /projects/acme%2Fapp": {body: `{"id":7}`},
	})
	got, err := app.rest(context.Background(), "GET", "/projects/acme%2Fapp", nil)
	if err != nil || got["id"] != float64(7) {
		t.Fatalf("got %v, err %v", got, err)
	}
	if _, err := app.rest(context.Background(), "DELETE", "/projects/other", nil); err == nil || !strings.Contains(err.Error(), "GitLab REST 404") {
		t.Errorf("unscripted route must answer 404, err = %v", err)
	}
	calls := fake.restCalls()
	if len(calls) != 2 || calls[0].Method != "GET" || calls[0].Path != "/projects/acme%2Fapp" || calls[1].Method != "DELETE" {
		t.Errorf("recorded calls: %+v", calls)
	}
}

func TestScriptedGitLab_ServesGraphQLInOrderAndRepeatsTheLast(t *testing.T) {
	app, fake := newScriptedGitLab(t, []string{`{"data":{"n":1}}`, `{"data":{"n":2}}`}, nil)
	var got []any
	for i := range 3 {
		data, err := app.graphql(context.Background(), "query { n }", map[string]any{"i": i})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		got = append(got, data["n"])
	}
	if want := []any{float64(1), float64(2), float64(2)}; !reflect.DeepEqual(got, want) {
		t.Errorf("responses = %v, want %v", got, want)
	}
	calls := fake.graphQLCalls()
	if len(calls) != 3 || calls[2].Variables["i"] != float64(2) {
		t.Errorf("recorded calls: %+v", calls)
	}
}
