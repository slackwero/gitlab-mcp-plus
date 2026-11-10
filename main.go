package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Variables injected at build time via -ldflags. A binary built locally with
// `go build` keeps their default values.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// defaultMaxResponseBytes caps what is read from a single GitLab response, so
// a misbehaving instance or proxy cannot exhaust the memory of the server.
const defaultMaxResponseBytes = 32 << 20

type App struct {
	token     string
	endpoint  string
	gitlabURL string
	client    *http.Client

	maxResponseBytes int64
}

func NewApp(token, gitlabURL string) *App {
	if gitlabURL == "" {
		gitlabURL = "https://gitlab.com"
	}
	return &App{
		token:     token,
		endpoint:  gitlabURL + "/api/graphql",
		gitlabURL: gitlabURL,
		client:    &http.Client{Timeout: 30 * time.Second},

		maxResponseBytes: defaultMaxResponseBytes,
	}
}

// readBody reads a GitLab response body, refusing one larger than
// maxResponseBytes instead of buffering it whole.
func (a *App) readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, a.maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > a.maxResponseBytes {
		return nil, fmt.Errorf("GitLab response is larger than %d bytes", a.maxResponseBytes)
	}
	return body, nil
}

func (a *App) graphql(ctx context.Context, query string, variables map[string]any) (map[string]any, error) {
	body := map[string]any{
		"query":     query,
		"variables": variables,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.token)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := a.readBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitLab API %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if errs, ok := result["errors"]; ok {
		if errList, ok := errs.([]any); ok && len(errList) > 0 {
			var msgs []string
			for _, e := range errList {
				if em, ok := e.(map[string]any); ok {
					if msg, ok := em["message"].(string); ok {
						msgs = append(msgs, msg)
					}
				}
			}
			return nil, fmt.Errorf("%s", strings.Join(msgs, "; "))
		}
	}

	data, ok := result["data"]
	if !ok {
		return nil, fmt.Errorf("no data returned from GitLab GraphQL API")
	}

	dataMap, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected data format from GitLab GraphQL API")
	}

	return dataMap, nil
}

func (a *App) rest(ctx context.Context, method, path string, body any) (map[string]any, error) {
	url := a.gitlabURL + "/api/v4" + path

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := a.readBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GitLab REST %d: %s", resp.StatusCode, string(respBody))
	}

	if len(respBody) == 0 {
		return map[string]any{}, nil
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result, nil
}

// restList runs a REST GET whose response is a JSON array and also returns the
// X-Next-Page header for offset pagination.
func (a *App) restList(ctx context.Context, path string) ([]any, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.gitlabURL+"/api/v4"+path, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := a.readBody(resp)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("GitLab REST %d: %s", resp.StatusCode, string(respBody))
	}

	var result []any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, "", fmt.Errorf("unmarshal response: %w", err)
	}
	return result, resp.Header.Get("X-Next-Page"), nil
}

func okResult(data interface{}) *mcp.CallToolResult {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errResult(fmt.Sprintf("marshal result: %v", err))
	}
	return mcp.NewToolResultText(string(b))
}

func errResult(message string) *mcp.CallToolResult {
	r := mcp.NewToolResultText(message)
	r.IsError = true
	return r
}

func normalizeVulnID(id string) string {
	if strings.HasPrefix(id, "gid://") {
		return id
	}
	return "gid://gitlab/Vulnerability/" + id
}

func resolveScope(args map[string]interface{}) (string, string, error) {
	project, _ := args["project_path"].(string)
	group, _ := args["group_path"].(string)

	if project != "" && group != "" {
		return "", "", fmt.Errorf("provide either project_path or group_path, not both")
	}
	if project != "" {
		return "project", project, nil
	}
	if group != "" {
		return "group", group, nil
	}
	return "", "", fmt.Errorf("either project_path or group_path is required")
}

type aiRates struct {
	acceptance    float64
	locAcceptance float64
	satisfaction  float64
}

func calculateAIRates(shown, accepted, shownLOC, acceptedLOC, thumbsUp, thumbsDown int) aiRates {
	var r aiRates
	if shown > 0 {
		r.acceptance = round2(float64(accepted) / float64(shown) * 100)
	}
	if shownLOC > 0 {
		r.locAcceptance = round2(float64(acceptedLOC) / float64(shownLOC) * 100)
	}
	if thumbsUp+thumbsDown > 0 {
		r.satisfaction = round2(float64(thumbsUp) / float64(thumbsUp+thumbsDown) * 100)
	}
	return r
}

func buildAIDashboard(metrics map[string]interface{}, periodLabel string) map[string]interface{} {
	cs := mapGet(metrics, "codeSuggestions")
	cr := mapGet(metrics, "codeReview")
	apChats := mapGet(metrics, "agentPlatformChats")
	apFlows := mapGet(metrics, "agentPlatformFlows")
	ap := mapGet(metrics, "agentPlatform")
	chat := mapGet(metrics, "chat")
	mcpCalls := mapGet(metrics, "mcp")
	troubleshoot := mapGet(metrics, "troubleshoot")

	shown := intGet(cs, "shownCount")
	accepted := intGet(cs, "acceptedCount")
	shownLOC := intGet(cs, "shownLinesOfCode")
	acceptedLOC := intGet(cs, "acceptedLinesOfCode")
	thumbsUp := intGet(cr, "reactThumbsUpOnDuoCodeReviewCommentEventCount")
	thumbsDown := intGet(cr, "reactThumbsDownOnDuoCodeReviewCommentEventCount")

	rates := calculateAIRates(shown, accepted, shownLOC, acceptedLOC, thumbsUp, thumbsDown)

	dashboard := map[string]interface{}{
		"summary": map[string]interface{}{
			"duoUsedCount":                metrics["duoUsedCount"],
			"duoChatContributorsCount":    metrics["duoChatContributorsCount"],
			"rootCauseAnalysisUsersCount": metrics["rootCauseAnalysisUsersCount"],
			"codeContributorsCount":       metrics["codeContributorsCount"],
		},
		"chat": map[string]interface{}{
			"requestCount":       chat["requestDuoChatResponseEventCount"],
			"responseCount":      chat["completeDuoChatResponseEventCount"],
			"toolSucceededCount": chat["toolSucceededDuoChatEventCount"],
			"toolFailedCount":    chat["toolFailedDuoChatEventCount"],
		},
		"mcp": map[string]interface{}{
			"toolCallsStarted":  mcpCalls["startMcpToolCallEventCount"],
			"toolCallsFinished": mcpCalls["finishMcpToolCallEventCount"],
		},
		"troubleshoot": map[string]interface{}{
			"jobCount": troubleshoot["troubleshootJobEventCount"],
		},
		"codeSuggestions": map[string]interface{}{
			"contributorsCount":   cs["contributorsCount"],
			"shownCount":          shown,
			"acceptedCount":       accepted,
			"acceptanceRate":      rates.acceptance,
			"shownLinesOfCode":    shownLOC,
			"acceptedLinesOfCode": acceptedLOC,
			"locAcceptanceRate":   rates.locAcceptance,
			"languageBreakdown":   cs["languages"],
			"ideNames":            cs["ideNames"],
		},
		"codeReview": map[string]interface{}{
			"requestByAuthorCount":    cr["requestReviewDuoCodeReviewOnMrByAuthorEventCount"],
			"requestByNonAuthorCount": cr["requestReviewDuoCodeReviewOnMrByNonAuthorEventCount"],
			"commentsPostedCount":     cr["postCommentDuoCodeReviewOnDiffEventCount"],
			"commentsPublishedCount":  cr["publishDuoCodeReviewCommentsEventCount"],
			"approvalsCount":          cr["approveMergeRequestDuoCodeReviewEventCount"],
			"noIssuesFoundCount":      cr["findNoIssuesDuoCodeReviewAfterReviewEventCount"],
			"errorCount":              cr["encounterDuoCodeReviewErrorDuringReviewEventCount"],
			"thumbsUp":                thumbsUp,
			"thumbsDown":              thumbsDown,
			"satisfactionRate":        rates.satisfaction,
		},
		"agentPlatform": map[string]interface{}{
			"chatSessionsCreated": apChats["createdSessionEventCount"],
			"flowSessionsCreated": apFlows["createdSessionEventCount"],
			"sessions": map[string]interface{}{
				"created":  ap["createdSessionEventCount"],
				"started":  ap["startedSessionEventCount"],
				"finished": ap["finishedSessionEventCount"],
				"dropped":  ap["droppedSessionEventCount"],
				"stopped":  ap["stoppedSessionEventCount"],
				"resumed":  ap["resumedSessionEventCount"],
			},
			"flowMetrics": ap["flowMetrics"],
		},
	}

	if periodLabel != "" {
		dashboard["period"] = periodLabel
	}

	return dashboard
}

func mapGet(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	v, ok := m[key]
	if !ok || v == nil {
		return map[string]interface{}{}
	}
	if result, ok := v.(map[string]interface{}); ok {
		return result
	}
	return map[string]interface{}{}
}

func intGet(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

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
	flag.BoolVar(&readOnlyFlag, "read-only", false, "Register the server with only its read tools ("+envReadOnly+"=true)")
	flag.StringVar(&toolsFlag, "tools", "", "Register the server with only these comma-separated tools ("+envTools+")")

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

	opts := adminOpts{
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
		exitOn(runInstall(installFlag, opts))
	case uninstallFlag != "":
		exitOn(runUninstall(uninstallFlag, opts))
	case checkFlag != "":
		exitOn(runCheck(checkFlag, opts))
	case printConfigFlag != "":
		exitOn(runPrintConfig(printConfigFlag, opts))
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

	gitlabURL, err := normalizeGitLabURL(os.Getenv("GITLAB_URL"))
	if err != nil {
		exitServer(fmt.Errorf("GITLAB_URL: %w", err))
	}
	policy, err := toolPolicyFromEnv()
	if err != nil {
		exitServer(err)
	}

	s := newServer(NewApp(token, gitlabURL), policy)
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
