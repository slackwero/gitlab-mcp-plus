package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/slackwero/gitlab-mcp-plus/internal/gitlab"
)

const (
	fakeGraphQLPath = "/api/graphql"
	fakeRESTPrefix  = "/api/v4"
)

// fakeNotFound is what the fake GitLab answers to a REST route it has no script for.
var fakeNotFound = fakeResponse{status: http.StatusNotFound, body: `{"message":"404 Not Found"}`}

// registeredTools starts the real MCP server and asks it for tools/list, so
// tests see exactly what a client sees.
func registeredTools(t *testing.T) map[string]mcp.Tool {
	t.Helper()
	s := server.NewMCPServer("gitlab-mcp-plus", "test")
	(&toolset{gl: gitlab.NewClient("test-token", "http://gitlab.invalid")}).registerTools(s)

	msg := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	raw, err := json.Marshal(s.HandleMessage(context.Background(), msg))
	if err != nil {
		t.Fatalf("marshaling tools/list: %v", err)
	}
	var resp struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("invalid tools/list response: %v", err)
	}
	tools := make(map[string]mcp.Tool, len(resp.Result.Tools))
	for _, tool := range resp.Result.Tools {
		tools[tool.Name] = tool
	}
	return tools
}

func TestScriptedGitLab_ServesRESTRoutesAndRecordsCalls(t *testing.T) {
	app, fake := newScriptedGitLab(t, nil, map[string]fakeResponse{
		"GET /projects/acme%2Fapp": {body: `{"id":7}`},
	})
	got, err := app.gl.REST(context.Background(), "GET", "/projects/acme%2Fapp", nil)
	if err != nil || got["id"] != float64(7) {
		t.Fatalf("got %v, err %v", got, err)
	}
	if _, err := app.gl.REST(context.Background(), "DELETE", "/projects/other", nil); err == nil || !strings.Contains(err.Error(), "GitLab REST 404") {
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
		data, err := app.gl.GraphQL(context.Background(), "query { n }", map[string]any{"i": i})
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

// graphQLCall is a GraphQL request as the fake GitLab received it.
type graphQLCall struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// restCall is a REST request as the fake GitLab received it. Path is the
// escaped path without the /api/v4 prefix, so "%2F" in a project path stays
// visible.
type restCall struct {
	Method, Path string
	Query        url.Values
	Body         map[string]any
}

// fakeResponse is a scripted answer; status 0 means 200.
type fakeResponse struct {
	status int
	body   string
}

// fakeGitLab answers GraphQL requests from a script, in order, and REST
// requests from a route table. It records every request so tests can check
// what each tool sent.
type fakeGitLab struct {
	graphQLResponses []string
	restRoutes       map[string]fakeResponse

	mu         sync.Mutex
	graphQLLog []graphQLCall
	restLog    []restCall
}

// newScriptedGitLab starts a fake GitLab. The i-th GraphQL request receives
// graphQL[i] and the last response repeats once the script runs out. A REST
// request is answered by routes["METHOD /path"], or with a 404 when the route
// is not scripted.
func newScriptedGitLab(t *testing.T, graphQL []string, routes map[string]fakeResponse) (*toolset, *fakeGitLab) {
	t.Helper()
	fake := &fakeGitLab{graphQLResponses: graphQL, restRoutes: routes}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.serve(t, w, r)
	}))
	t.Cleanup(srv.Close)
	return (&toolset{gl: gitlab.NewClient("test-token", srv.URL)}), fake
}

// newFakeGitLab answers every GraphQL request with the same response.
func newFakeGitLab(t *testing.T, response string) (*toolset, *fakeGitLab) {
	t.Helper()
	return newScriptedGitLab(t, []string{response}, nil)
}

func (f *fakeGitLab) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("reading the body: %v", err)
	}

	var resp fakeResponse
	path := r.URL.EscapedPath()
	switch {
	case r.Method == http.MethodPost && path == fakeGraphQLPath:
		resp = f.serveGraphQL(t, raw)
	case strings.HasPrefix(path, fakeRESTPrefix+"/"):
		resp = f.serveREST(t, r, strings.TrimPrefix(path, fakeRESTPrefix), raw)
	default:
		t.Errorf("unexpected request to the fake GitLab: %s %s", r.Method, r.URL)
		resp = fakeNotFound
	}

	status := resp.status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, resp.body)
}

func (f *fakeGitLab) serveGraphQL(t *testing.T, raw []byte) fakeResponse {
	var call graphQLCall
	if err := json.Unmarshal(raw, &call); err != nil {
		t.Errorf("invalid GraphQL body: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.graphQLLog = append(f.graphQLLog, call)
	if len(f.graphQLResponses) == 0 {
		t.Errorf("unexpected GraphQL request, the test scripted none: %s", call.Query)
		return fakeResponse{status: http.StatusInternalServerError, body: `{"message":"no scripted GraphQL response"}`}
	}
	i := min(len(f.graphQLLog), len(f.graphQLResponses)) - 1
	return fakeResponse{body: f.graphQLResponses[i]}
}

func (f *fakeGitLab) serveREST(t *testing.T, r *http.Request, path string, raw []byte) fakeResponse {
	call := restCall{Method: r.Method, Path: path, Query: r.URL.Query()}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &call.Body); err != nil {
			t.Errorf("invalid REST body: %v", err)
		}
	}

	f.mu.Lock()
	f.restLog = append(f.restLog, call)
	f.mu.Unlock()

	if resp, ok := f.restRoutes[r.Method+" "+path]; ok {
		return resp
	}
	return fakeNotFound
}

// graphQLCalls returns the GraphQL requests received so far, in order.
func (f *fakeGitLab) graphQLCalls() []graphQLCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.graphQLLog)
}

// restCalls returns the REST requests received so far, in order.
func (f *fakeGitLab) restCalls() []restCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.restLog)
}

func (f *fakeGitLab) lastCall(t *testing.T) graphQLCall {
	t.Helper()
	calls := f.graphQLCalls()
	if len(calls) == 0 {
		t.Fatal("the tool sent no GraphQL request")
	}
	return calls[len(calls)-1]
}

func callTool(args map[string]any) mcp.CallToolRequest {
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return req
}

// resultText returns the result text and fails if the tool reported an error.
func resultText(t *testing.T, res *mcp.CallToolResult, err error) string {
	t.Helper()
	text := contentText(t, res, err)
	if res.IsError {
		t.Fatalf("the tool reported an error: %s", text)
	}
	return text
}

// errorText returns the error message and fails if the tool did not report an
// error.
func errorText(t *testing.T, res *mcp.CallToolResult, err error) string {
	t.Helper()
	text := contentText(t, res, err)
	if !res.IsError {
		t.Fatalf("the tool did not report an error, result: %s", text)
	}
	return text
}

// contentText returns the text of the first content block of a tool result.
func contentText(t *testing.T, res *mcp.CallToolResult, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("the handler returned an error: %v", err)
	}
	if res == nil {
		t.Fatal("the handler returned no result")
	}
	if len(res.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type: %T", res.Content[0])
	}
	return text.Text
}

// fieldArgs returns the text of the arguments the GraphQL document passes to a
// field, that is, whatever sits between "field(" and its closing parenthesis.
func fieldArgs(t *testing.T, query, field string) string {
	t.Helper()
	start := strings.Index(query, field+"(")
	if start < 0 {
		return ""
	}
	rest := query[start+len(field)+1:]
	end := strings.Index(rest, ")")
	if end < 0 {
		t.Fatalf("unterminated arguments for %s", field)
	}
	return rest[:end]
}
