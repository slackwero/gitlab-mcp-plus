package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	// maxBulkVulnerabilities is the most vulnerabilities GitLab accepts in one
	// bulk mutation.
	maxBulkVulnerabilities = 100
	// maxFindingDueDates is the most findings GitLab accepts in one
	// bulkSetVulnerabilityFindingsDueDates call.
	maxFindingDueDates = 1000
	// maxWorkflowFindings is the most findings one startVulnerabilityWorkflow
	// call may name.
	maxWorkflowFindings = 1000

	dueDateLayout = "2006-01-02"
)

// vulnerabilityWorkflows are the values of GitLab's VulnerabilityDuoWorkflow
// enum.
var vulnerabilityWorkflows = []string{"SAST_FP_DETECTION_V1", "SECRETS_FP_DETECTION_V1", "RESOLVE_SAST_VULNERABILITY_V1"}

// vulnerabilitySeverities are the values of GitLab's VulnerabilitySeverity
// enum.
var vulnerabilitySeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}

// startWorkflowArguments are the only arguments start_vulnerability_workflow
// accepts. A billed run never drops an argument it does not know: a misspelled
// filter would widen the run.
var startWorkflowArguments = []string{"project_path", "workflow", "finding_uuids", "severities", "all_findings"}

const workflowParamDescription = "Duo workflow: SAST_FP_DETECTION_V1 (detect SAST false positives), " +
	"SECRETS_FP_DETECTION_V1 (detect secret false positives), RESOLVE_SAST_VULNERABILITY_V1 (generate resolutions with AI)"

// startMayHaveRunNote ends the error of a start request that failed in
// transit or with a GraphQL error: GitLab may have started the billed run
// anyway, and a blind retry would start a second one.
const startMayHaveRunNote = " The run may have started: check get_vulnerability_workflow before retrying."

const mutationVulnerabilitiesDismiss = `mutation($ids: [VulnerabilityID!]!, $comment: String, $dismissalReason: VulnerabilityDismissalReason) {
  vulnerabilitiesDismiss(input: { vulnerabilityIds: $ids, comment: $comment, dismissalReason: $dismissalReason }) {
    vulnerabilities { id title state severity dismissalReason }
    errors
  }
}`

const mutationVulnerabilitiesSeverityOverride = `mutation($ids: [VulnerabilityID!]!, $severity: VulnerabilitySeverity!, $comment: String!) {
  vulnerabilitiesSeverityOverride(input: { vulnerabilityIds: $ids, severity: $severity, comment: $comment }) {
    vulnerabilities { id title state severity }
    errors
  }
}`

const queryIssueID = `query($fullPath: ID!, $iid: String!) {
  project(fullPath: $fullPath) { issue(iid: $iid) { id iid title webUrl } }
}`

const mutationVulnerabilityIssueLinkCreate = `mutation($issueId: IssueID!, $ids: [VulnerabilityID!]!) {
  vulnerabilityIssueLinkCreate(input: { issueId: $issueId, vulnerabilityIds: $ids }) {
    issueLinks { id linkType issue { iid title webUrl state } }
    errors
  }
}`

const mutationSetFindingsDueDates = `mutation($projectFullPath: String!, $updates: [FindingDueDatesSetInput!]!) {
  bulkSetVulnerabilityFindingsDueDates(input: { projectFullPath: $projectFullPath, updates: $updates }) {
    assigned removed skipped
    errors { code findingUuid message }
  }
}`

const mutationStartVulnerabilityWorkflow = `mutation($projectId: ProjectID!, $workflow: VulnerabilityDuoWorkflow!, $findingUuids: [String!], $severities: [VulnerabilitySeverity!]) {
  startVulnerabilityWorkflow(input: { projectId: $projectId, workflow: $workflow, findingUuids: $findingUuids, severities: $severities }) {
    execution { executionId workflow status createdAt startedAt endedAt cancelRequested batchSize
      progress { total pending processing completed failed cancelled percentage } }
    errorReason
    errors
  }
}`

const mutationCancelVulnerabilityWorkflow = `mutation($projectId: ProjectID!, $workflow: VulnerabilityDuoWorkflow!) {
  cancelVulnerabilityWorkflow(input: { projectId: $projectId, workflow: $workflow }) {
    execution { executionId workflow status cancelRequested
      progress { total pending processing completed failed cancelled percentage } }
    errorReason
    errors
  }
}`

const queryVulnerabilityWorkflowExecution = `query($fullPath: ID!, $workflow: VulnerabilityDuoWorkflow!, $executionId: String, $withItems: Boolean!) {
  project(fullPath: $fullPath) {
    vulnerabilityWorkflowExecution(workflow: $workflow, executionId: $executionId) {
      executionId workflow status createdAt startedAt endedAt cancelRequested batchSize
      currentStage { name order }
      progress { total pending processing completed failed cancelled percentage }
      itemStates @include(if: $withItems) { state vulnerability { id title severity state } }
    }
  }
}`

func (a *App) registerVulnerabilityActionTools(s toolAdder) {
	// ── vulnerabilities_bulk_dismiss ──
	s.AddTool(mcp.NewTool("vulnerabilities_bulk_dismiss",
		stateChangingTool(),
		mcp.WithDescription("Dismiss up to 100 vulnerabilities at once with an optional comment and dismissal reason."),
		mcp.WithArray("ids",
			mcp.Required(),
			mcp.Description("Vulnerability IDs (1 to 100), each a global ID ('gid://gitlab/Vulnerability/12345') or just '12345'"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("comment", mcp.Description("Dismissal comment")),
		mcp.WithString("dismissal_reason",
			mcp.Description("Reason for dismissal"),
			mcp.Enum("ACCEPTABLE_RISK", "FALSE_POSITIVE", "MITIGATING_CONTROL", "USED_IN_TESTS", "NOT_APPLICABLE"),
		),
	), a.handleVulnerabilitiesBulkDismiss)

	// ── vulnerabilities_override_severity ──
	s.AddTool(mcp.NewTool("vulnerabilities_override_severity",
		stateChangingTool(),
		mcp.WithDescription("Override the severity of up to 100 vulnerabilities at once. A comment explaining the override is required."),
		mcp.WithArray("ids",
			mcp.Required(),
			mcp.Description("Vulnerability IDs (1 to 100), each a global ID ('gid://gitlab/Vulnerability/12345') or just '12345'"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("severity",
			mcp.Required(),
			mcp.Description("New severity"),
			mcp.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"),
		),
		mcp.WithString("comment", mcp.Required(), mcp.Description("Reason for the override (must not be empty)")),
	), a.handleVulnerabilitiesOverrideSeverity)

	// ── vulnerabilities_link_issue ──
	s.AddTool(mcp.NewTool("vulnerabilities_link_issue",
		additiveTool(),
		mcp.WithDescription("Link up to 100 vulnerabilities to an existing issue."),
		mcp.WithArray("ids",
			mcp.Required(),
			mcp.Description("Vulnerability IDs (1 to 100), each a global ID ('gid://gitlab/Vulnerability/12345') or just '12345'"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("issue_project_path", mcp.Required(), mcp.Description("Full path of the project that holds the issue (e.g. 'group/subgroup/project')")),
		mcp.WithString("issue_iid", mcp.Required(), mcp.Description("Issue IID within that project")),
	), a.handleVulnerabilitiesLinkIssue)

	// ── vulnerabilities_set_due_date ──
	s.AddTool(mcp.NewTool("vulnerabilities_set_due_date",
		stateChangingTool(),
		mcp.WithDescription("Set or remove the due date of up to 1000 vulnerability findings of a project. Pass due_date to set the date or remove_due_date=true to remove it; exactly one of the two is required. Findings GitLab cannot update are reported as skipped, with their errors."),
		mcp.WithString("project_path", mcp.Required(), mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithArray("finding_uuids",
			mcp.Required(),
			mcp.Description("UUIDs of the vulnerability findings (1 to 1000)"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("due_date", mcp.Description("Due date as YYYY-MM-DD. Required unless remove_due_date is true")),
		mcp.WithBoolean("remove_due_date", mcp.Description("Set to true to remove the current due date instead of setting one. Do not combine with due_date")),
	), a.handleVulnerabilitiesSetDueDate)

	// ── start_vulnerability_workflow ──
	s.AddTool(mcp.NewTool("start_vulnerability_workflow",
		stateChangingTool(),
		mcp.WithDescription("Start a bulk GitLab Duo workflow on a project's vulnerability findings: SAST or secret false-positive detection, "+
			"or AI-assisted SAST resolution (RESOLVE_SAST_VULNERABILITY_V1 may open merge requests). "+
			"Every call starts a new billed run that consumes GitLab Credits in proportion to the findings processed. "+
			"Before calling, confirm the project, the workflow and the scope with the user unless they already stated them. "+
			"Pass finding_uuids (the uuid field of list_vulnerabilities), or set all_findings=true only when the user asked for the whole project. "+
			"Report the returned executionId; use get_vulnerability_workflow for status and cancel_vulnerability_workflow to stop the run."),
		mcp.WithSchemaAdditionalProperties(false),
		mcp.WithString("project_path", mcp.Required(), mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("workflow", mcp.Required(), mcp.Description(workflowParamDescription), mcp.Enum(vulnerabilityWorkflows...)),
		mcp.WithArray("finding_uuids",
			mcp.Description("UUIDs of the vulnerability findings to process (1 to 1000), the uuid field of list_vulnerabilities. Required unless all_findings is true"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithArray("severities",
			mcp.Description("Narrows the selected findings (every finding with all_findings, or the given finding_uuids) to these severities. "+
				"It never starts a run on its own: finding_uuids or all_findings=true is still required"),
			mcp.WithStringEnumItems(vulnerabilitySeverities),
		),
		mcp.WithBoolean("all_findings", mcp.Description("Set to true to process every finding in the project. "+
			"Set it only when the user asked for the whole project. Do not combine with finding_uuids")),
	), a.handleStartVulnerabilityWorkflow)

	// ── get_vulnerability_workflow ──
	s.AddTool(mcp.NewTool("get_vulnerability_workflow",
		readOnlyTool(),
		mcp.WithDescription("Get the status and progress of a GitLab Duo vulnerability workflow execution in a project: current stage and progress counts, "+
			"plus the state of each processed vulnerability when include_items is true. Without execution_id, returns the latest execution of the workflow."),
		mcp.WithString("project_path", mcp.Required(), mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("workflow", mcp.Required(), mcp.Description(workflowParamDescription), mcp.Enum(vulnerabilityWorkflows...)),
		mcp.WithString("execution_id", mcp.Description("Execution ID returned by start_vulnerability_workflow. Without it, the latest execution is returned")),
		mcp.WithBoolean("include_items", mcp.Description("Set to true to also return the state of each processed vulnerability (itemStates). "+
			"Off by default: the list grows with the findings of the run")),
	), a.handleGetVulnerabilityWorkflow)

	// ── cancel_vulnerability_workflow ──
	s.AddTool(mcp.NewTool("cancel_vulnerability_workflow",
		stateChangingTool(),
		mcp.WithDescription("Cancel the running execution of a GitLab Duo vulnerability workflow in a project. Returns the execution with its cancellation flag and progress."),
		mcp.WithString("project_path", mcp.Required(), mcp.Description("Full project path (e.g. 'group/subgroup/project')")),
		mcp.WithString("workflow", mcp.Required(), mcp.Description(workflowParamDescription), mcp.Enum(vulnerabilityWorkflows...)),
	), a.handleCancelVulnerabilityWorkflow)
}

func (a *App) handleVulnerabilitiesBulkDismiss(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	ids, err := gidList("ids", "Vulnerability", args["ids"], maxBulkVulnerabilities)
	if err != nil {
		return errResult(err.Error()), nil
	}

	variables := map[string]any{"ids": ids}
	if comment, _ := args["comment"].(string); comment != "" {
		variables["comment"] = comment
	}
	if reason, _ := args["dismissal_reason"].(string); reason != "" {
		variables["dismissalReason"] = reason
	}

	return a.vulnerabilitiesMutation(ctx, "vulnerabilities_bulk_dismiss", "dismiss vulnerabilities",
		mutationVulnerabilitiesDismiss, "vulnerabilitiesDismiss", "vulnerabilities", variables)
}

func (a *App) handleVulnerabilitiesOverrideSeverity(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	ids, err := gidList("ids", "Vulnerability", args["ids"], maxBulkVulnerabilities)
	if err != nil {
		return errResult(err.Error()), nil
	}
	severity, _ := args["severity"].(string)
	if severity == "" {
		return errResult("severity is required"), nil
	}
	comment, _ := args["comment"].(string)
	if strings.TrimSpace(comment) == "" {
		return errResult("comment is required"), nil
	}

	return a.vulnerabilitiesMutation(ctx, "vulnerabilities_override_severity", "override severity",
		mutationVulnerabilitiesSeverityOverride, "vulnerabilitiesSeverityOverride", "vulnerabilities",
		map[string]any{"ids": ids, "severity": severity, "comment": comment})
}

func (a *App) handleVulnerabilitiesLinkIssue(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	ids, err := gidList("ids", "Vulnerability", args["ids"], maxBulkVulnerabilities)
	if err != nil {
		return errResult(err.Error()), nil
	}
	projectPath, _ := args["issue_project_path"].(string)
	if strings.TrimSpace(projectPath) == "" {
		return errResult("issue_project_path is required"), nil
	}
	iid, err := issueIID(args["issue_iid"])
	if err != nil {
		return errResult(err.Error()), nil
	}

	data, err := a.graphql(ctx, queryIssueID, map[string]any{"fullPath": projectPath, "iid": iid})
	if err != nil {
		return toolError("vulnerabilities_link_issue", err)
	}
	issueID, _ := mapGet(mapGet(data, "project"), "issue")["id"].(string)
	if issueID == "" {
		return errResult(fmt.Sprintf("Issue #%s not found in project '%s'", iid, projectPath)), nil
	}

	return a.vulnerabilitiesMutation(ctx, "vulnerabilities_link_issue", "link issue",
		mutationVulnerabilityIssueLinkCreate, "vulnerabilityIssueLinkCreate", "issueLinks",
		map[string]any{"issueId": issueID, "ids": ids})
}

func (a *App) handleVulnerabilitiesSetDueDate(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	projectPath, _ := args["project_path"].(string)
	if strings.TrimSpace(projectPath) == "" {
		return errResult("project_path is required"), nil
	}

	dueDate, err := dueDateArg(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	uuids, err := limitedStrings("finding_uuids", args["finding_uuids"], maxFindingDueDates)
	if err != nil {
		return errResult(err.Error()), nil
	}
	if len(uuids) == 0 {
		return errResult("finding_uuids is required"), nil
	}
	updates := make([]any, len(uuids))
	for i, u := range uuids {
		updates[i] = map[string]any{"findingUuid": u, "dueDate": dueDate}
	}

	data, err := a.graphql(ctx, mutationSetFindingsDueDates, map[string]any{
		"projectFullPath": projectPath,
		"updates":         updates,
	})
	if err != nil {
		return toolError("vulnerabilities_set_due_date", err)
	}

	// Per-finding errors travel inside the result, not as a tool error. The
	// counts must be present: without them nothing says what was updated, and
	// GitLab's errors are the only explanation left, so they are kept.
	payload, ok := data["bulkSetVulnerabilityFindingsDueDates"].(map[string]any)
	if !ok {
		return errResult("Unexpected GitLab response for vulnerabilities_set_due_date: missing mutation payload"), nil
	}
	for _, key := range []string{"assigned", "removed", "skipped"} {
		if _, isNumber := payload[key].(float64); !isNumber {
			msg := fmt.Sprintf("Unexpected GitLab response for vulnerabilities_set_due_date: missing or non-numeric %q", key)
			if gitlabErrors := findingErrorMessages(payload["errors"]); len(gitlabErrors) > 0 {
				msg += " (GitLab errors: " + strings.Join(gitlabErrors, "; ") + ")"
			}
			return errResult(msg), nil
		}
	}
	findingErrors := payload["errors"]
	if findingErrors == nil {
		findingErrors = []any{}
	}
	return okResult(map[string]any{
		"assigned": payload["assigned"],
		"removed":  payload["removed"],
		"skipped":  payload["skipped"],
		"errors":   findingErrors,
	}), nil
}

// workflowRequest is what start_vulnerability_workflow asked GitLab for,
// returned next to the execution so the run can be checked against the
// request.
type workflowRequest struct {
	ProjectPath string   `json:"project_path"`
	Workflow    string   `json:"workflow"`
	Scope       string   `json:"scope"` // "all_findings" or "<n> finding_uuids"
	Severities  []string `json:"severities"`
}

func (a *App) handleStartVulnerabilityWorkflow(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	if err := checkStartArguments(args); err != nil {
		return errResult(err.Error()), nil
	}
	path, workflow, err := workflowTarget(args)
	if err != nil {
		return errResult(err.Error()), nil
	}
	uuids, severities, err := workflowSelection(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	variables := map[string]any{"workflow": workflow}
	scope := "all_findings"
	if len(uuids) > 0 {
		variables["findingUuids"] = uuids
		scope = fmt.Sprintf("%d finding_uuids", len(uuids))
	}
	if len(severities) > 0 {
		variables["severities"] = severities
	}
	execution, failure := a.workflowMutation(ctx, workflowMutationSpec{
		tool:               "start_vulnerability_workflow",
		action:             "start workflow",
		document:           mutationStartVulnerabilityWorkflow,
		field:              "startVulnerabilityWorkflow",
		requestFailureNote: startMayHaveRunNote,
	}, path, variables)
	if failure != nil {
		return failure, nil
	}
	return okResult(struct {
		Requested workflowRequest `json:"requested"`
		Execution map[string]any  `json:"execution"`
	}{
		Requested: workflowRequest{ProjectPath: path, Workflow: workflow, Scope: scope, Severities: severities},
		Execution: execution,
	}), nil
}

func (a *App) handleGetVulnerabilityWorkflow(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	path, workflow, err := workflowTarget(args)
	if err != nil {
		return errResult(err.Error()), nil
	}

	variables := map[string]any{"fullPath": path, "workflow": workflow}
	switch v := args["execution_id"].(type) {
	case nil:
	case string:
		if id := strings.TrimSpace(v); id != "" {
			variables["executionId"] = id
		}
	default:
		// Dropping it would answer with the latest execution instead.
		return errResult("execution_id must be a string"), nil
	}
	// Per-finding states are unbounded, so they are only sent on request.
	withItems, err := optionalBool(args, "include_items")
	if err != nil {
		return errResult(err.Error()), nil
	}
	variables["withItems"] = withItems

	data, err := a.graphql(ctx, queryVulnerabilityWorkflowExecution, variables)
	if err != nil {
		return toolError("get_vulnerability_workflow", err)
	}
	project := mapGet(data, "project")
	if len(project) == 0 {
		return errResult(fmt.Sprintf("Project '%s' not found", path)), nil
	}
	execution, _ := project["vulnerabilityWorkflowExecution"].(map[string]any)
	if execution == nil {
		return errResult(fmt.Sprintf("No %s execution found for project '%s'", workflow, path)), nil
	}
	return okResult(execution), nil
}

func (a *App) handleCancelVulnerabilityWorkflow(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	path, workflow, err := workflowTarget(args)
	if err != nil {
		return errResult(err.Error()), nil
	}
	execution, failure := a.workflowMutation(ctx, workflowMutationSpec{
		tool:     "cancel_vulnerability_workflow",
		action:   "cancel workflow",
		document: mutationCancelVulnerabilityWorkflow,
		field:    "cancelVulnerabilityWorkflow",
	}, path, map[string]any{"workflow": workflow})
	if failure != nil {
		return failure, nil
	}
	return okResult(execution), nil
}

// workflowMutationSpec describes a vulnerability workflow mutation.
type workflowMutationSpec struct {
	tool     string // tool name, the prefix of its request errors
	action   string // what a "Failed to ..." error says failed
	document string
	field    string // payload field of the mutation
	// requestFailureNote ends the error when the mutation request itself
	// fails, for a mutation GitLab may have run anyway.
	requestFailureNote string
}

// workflowMutation resolves the global ID of the project at path, adds it to
// variables as projectId and runs the mutation m. It returns the execution, or
// the error result to return instead. It fails closed: an errorReason or
// errors in the payload is a tool error, and so is a response without the
// payload object or without the execution.
func (a *App) workflowMutation(ctx context.Context, m workflowMutationSpec, path string, variables map[string]any) (map[string]any, *mcp.CallToolResult) {
	projectID, err := a.resolveGID(ctx, "project", path)
	if err != nil {
		return nil, errResult(err.Error())
	}
	variables["projectId"] = projectID

	data, err := a.graphql(ctx, m.document, variables)
	if err != nil {
		return nil, errResult(fmt.Sprintf("%s: %v", m.tool, err) + m.requestFailureNote)
	}
	payload, ok := data[m.field].(map[string]any)
	if !ok {
		return nil, errResult(fmt.Sprintf("Unexpected GitLab response for %s: missing %q payload", m.tool, m.field))
	}
	if res := workflowPayloadError(m.action, payload); res != nil {
		return nil, res
	}
	execution, ok := payload["execution"].(map[string]any)
	if !ok {
		return nil, errResult(fmt.Sprintf("Unexpected GitLab response for %s: missing \"execution\" in the payload", m.tool))
	}
	return execution, nil
}

// vulnerabilitiesMutation runs a mutation whose payload carries a list under
// resultKey and a plain errors list. It fails closed: a response without the
// payload object or the result list is an error, never a success.
func (a *App) vulnerabilitiesMutation(ctx context.Context, tool, action, document, field, resultKey string, variables map[string]any) (*mcp.CallToolResult, error) {
	data, err := a.graphql(ctx, document, variables)
	if err != nil {
		return toolError(tool, err)
	}
	payload, ok := data[field].(map[string]any)
	if !ok {
		return errResult(fmt.Sprintf("Unexpected GitLab response for %s: missing %q payload", tool, field)), nil
	}
	if res := payloadError(action, payload); res != nil {
		return res, nil
	}
	result, ok := payload[resultKey].([]any)
	if !ok {
		return errResult(fmt.Sprintf("Unexpected GitLab response for %s: missing %q in the payload", tool, resultKey)), nil
	}
	return okResult(result), nil
}

// issueIID reads issue_iid, given as a string or as a whole JSON number, and
// returns it as the decimal string GitLab expects.
func issueIID(arg any) (string, error) {
	switch v := arg.(type) {
	case nil:
		return "", errors.New("issue_iid is required")
	case string:
		if strings.TrimSpace(v) == "" {
			return "", errors.New("issue_iid is required")
		}
		return v, nil
	case float64:
		if v == math.Trunc(v) {
			return strconv.FormatFloat(v, 'f', -1, 64), nil
		}
	}
	return "", errors.New("issue_iid must be a string or integer")
}

// dueDateArg returns the dueDate to send for every finding: the due_date
// string, or nil (JSON null, which GitLab reads as "remove") when
// remove_due_date is true. Removal is never implied by a missing date: the
// caller must ask for exactly one of the two.
func dueDateArg(args map[string]any) (any, error) {
	date := args["due_date"]
	remove, _ := args["remove_due_date"].(bool)
	switch {
	case date != nil && remove:
		return nil, errors.New("provide either due_date or remove_due_date, not both")
	case remove:
		return nil, nil
	case date == nil:
		return nil, errors.New("due_date is required; pass remove_due_date=true to remove the due date")
	}
	text, _ := date.(string)
	if _, err := time.Parse(dueDateLayout, text); err != nil {
		return nil, errors.New("due_date must be YYYY-MM-DD")
	}
	return text, nil
}

// findingErrorMessages returns the message of each element of the errors list
// of a bulkSetVulnerabilityFindingsDueDates payload.
func findingErrorMessages(errs any) []string {
	items, _ := errs.([]any)
	var messages []string
	for _, item := range items {
		entry, _ := item.(map[string]any)
		if msg, _ := entry["message"].(string); msg != "" {
			messages = append(messages, msg)
		}
	}
	return messages
}

// workflowTarget reads the project_path and workflow arguments every
// vulnerability workflow tool requires.
func workflowTarget(args map[string]any) (string, string, error) {
	path, _ := args["project_path"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", errors.New("project_path is required")
	}
	workflow, _ := args["workflow"].(string)
	workflow = strings.TrimSpace(workflow)
	if workflow == "" {
		return "", "", errors.New("workflow is required")
	}
	return path, workflow, nil
}

// workflowSelection returns the finding UUIDs and the uppercased severities
// start_vulnerability_workflow sends. The scope is never implied, because a
// run consumes GitLab Credits: the caller names the findings or opts in to
// every finding with all_findings=true, never both. Only a JSON true opts in;
// null counts as absent and any other type is rejected.
func workflowSelection(args map[string]any) ([]string, []string, error) {
	uuids, err := limitedStrings("finding_uuids", args["finding_uuids"], maxWorkflowFindings)
	if err != nil {
		return nil, nil, err
	}
	severities, err := limitedStrings("severities", args["severities"], len(vulnerabilitySeverities))
	if err != nil {
		return nil, nil, err
	}
	for i, s := range severities {
		severities[i] = strings.ToUpper(s)
	}

	allFindings, err := optionalBool(args, "all_findings")
	if err != nil {
		return nil, nil, err
	}
	switch {
	case len(uuids) > 0 && allFindings:
		return nil, nil, errors.New("provide either finding_uuids or all_findings, not both")
	case len(uuids) == 0 && !allFindings:
		return nil, nil, errors.New("finding_uuids is required; pass all_findings=true to process every finding in the project")
	}
	return uuids, severities, nil
}

// optionalBool reads a boolean argument that defaults to false. JSON null
// counts as absent; any other non-boolean is rejected instead of being read
// as false or true.
func optionalBool(args map[string]any, param string) (bool, error) {
	raw := args[param]
	if raw == nil {
		return false, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", param)
	}
	return b, nil
}

// checkStartArguments rejects any argument start_vulnerability_workflow does
// not declare, naming the keys in sorted order.
func checkStartArguments(args map[string]any) error {
	var unknown []string
	for key := range args {
		if !slices.Contains(startWorkflowArguments, key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	slices.Sort(unknown)

	quoted := make([]string, len(unknown))
	for i, key := range unknown {
		quoted[i] = strconv.Quote(key)
	}
	msg := "unknown argument " + quoted[0]
	if len(quoted) > 1 {
		msg = "unknown arguments " + strings.Join(quoted, ", ")
	}
	if slices.Contains(unknown, "severity") {
		msg += `; did you mean "severities"?`
	}
	return errors.New(msg)
}

// workflowPayloadError turns the errorReason and errors of a vulnerability
// workflow mutation payload into a tool error, or returns nil when GitLab
// reported neither. An execution GitLab returned next to the error is named,
// so the run it refers to can still be looked up.
func workflowPayloadError(action string, payload map[string]any) *mcp.CallToolResult {
	reason := payload["errorReason"]
	errs := getErrorStrings(payload)
	if reason == nil && len(errs) == 0 {
		return nil
	}
	msg := "Failed to " + action
	if reason != nil {
		msg += fmt.Sprintf(" (%v)", reason)
	}
	if len(errs) > 0 {
		msg += ": " + strings.Join(errs, ", ")
	}
	if id, _ := mapGet(payload, "execution")["executionId"].(string); id != "" {
		msg += " (executionId: " + id + ")"
	}
	return errResult(msg)
}
