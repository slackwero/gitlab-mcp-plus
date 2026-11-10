# gitlab-mcp-plus

[![platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-blue)](#requirements)
[![go](https://img.shields.io/badge/go-%E2%89%A51.26-00ADD8)](go.mod)
[![MCP tools](https://img.shields.io/badge/MCP%20tools-44-blue)](#tools)
[![GitLab](https://img.shields.io/badge/GitLab-.com%20%7C%20self--managed-FC6D26)](#self-managed-gitlab)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)
[![Built with Claude Code](https://img.shields.io/badge/Built_with-Claude_Code-D97757?logo=claude&logoColor=white)](https://claude.com/product/claude-code)

[![CI](https://github.com/slackwero/gitlab-mcp-plus/actions/workflows/ci.yml/badge.svg)](https://github.com/slackwero/gitlab-mcp-plus/actions/workflows/ci.yml)
[![Security](https://github.com/slackwero/gitlab-mcp-plus/actions/workflows/security.yml/badge.svg)](https://github.com/slackwero/gitlab-mcp-plus/actions/workflows/security.yml)
[![CodeQL](https://github.com/slackwero/gitlab-mcp-plus/actions/workflows/codeql.yml/badge.svg)](https://github.com/slackwero/gitlab-mcp-plus/actions/workflows/codeql.yml)

An [MCP](https://modelcontextprotocol.io) server that gives AI assistants (Claude Code, Cursor and any other MCP client) the **security, compliance and GitLab Duo** side of GitLab: vulnerability triage and bulk actions, security policies, compliance violations, dependencies (SBOM), scanner coverage, Duo usage, seats and credits, AI governance, and group inventory and audit.

It is designed to run **next to the official GitLab MCP server**, which covers day-to-day work on issues, merge requests and pipelines. This server adds the operations that one does not have.

- Works with **gitlab.com and self-managed GitLab**, for an organization's groups or for your personal namespace.
- **One static binary**, no runtime dependencies. Linux and macOS, amd64 and arm64.
- **Built-in installer** for Claude Code and Cursor: no JSON to edit by hand.
- Every tool tells the client whether it only reads, creates or changes data, so the client can ask before anything is modified, and a **read-only mode** removes the tools that change data altogether.

## Quick start

```bash
# 1. Download the binary for your system (see "Installation" for other options)
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; esac
curl -fsSL -o gitlab-mcp-plus "https://github.com/slackwero/gitlab-mcp-plus/releases/latest/download/gitlab-mcp-plus-${OS}-${ARCH}"
chmod +x gitlab-mcp-plus && sudo mv gitlab-mcp-plus /usr/local/bin/

# 2. Register it in your client with a GitLab token (it is prompted for, without echo, if not set)
export GITLAB_TOKEN=glpat-...
gitlab-mcp-plus --install claude     # or: --install cursor

# 3. Restart the client
```

Then ask your assistant things like *"List the critical vulnerabilities of group my-org that have no linked issue"* or *"How many Duo seats are unassigned in my-org?"*.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Create a GitLab token](#create-a-gitlab-token)
- [Connect your MCP client](#connect-your-mcp-client)
- [Configuration reference](#configuration-reference)
- [Tools](#tools)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Upgrading and uninstalling](#upgrading-and-uninstalling)
- [Development](#development)

## Requirements

- **Linux or macOS** (amd64 or arm64). Windows is not supported.
- A **GitLab token** (see [Create a GitLab token](#create-a-gitlab-token)).
- An **MCP client**: Claude Code and Cursor are set up automatically; any other client that runs stdio MCP servers can be configured by hand.

### What your GitLab plan needs

The token acts as its user: tools only see and change what that user's role allows. Many tools also depend on your GitLab tier, add-ons and version. Roughly:

| Area | Tools | Typically requires |
|---|---|---|
| Groups, projects, members, merge requests, branches | `get_group`, `list_groups`, `list_descendant_groups`, `list_group_projects`, `list_group_members`, `list_group_merge_requests`, `create_project`, `create_group`, `fork_project`, `delete_branch` | Any tier |
| Audit events | `list_group_audit_events` | Premium or Ultimate |
| Compliance | `list_compliance_frameworks`, `list_compliance_violations` | Premium or Ultimate (violations: Ultimate) |
| Vulnerabilities and security posture | `list_vulnerabilities`, `get_vulnerability`, the `vulnerability_*` / `vulnerabilities_*` actions, `list_pipeline_security_findings`, `list_vulnerability_scanners`, `list_security_policies`, `list_scan_execution_policies`, `list_dependencies`, `get_security_scanner_coverage`, `get_vulnerability_trend` | Ultimate |
| GitLab Duo and AI | `get_duo_ai_metrics`, `list_duo_user_metrics`, `get_duo_seat_usage`, `list_duo_seat_users`, `get_gitlab_credits_usage`, the `*_ai_governance_*` tools, `list_ai_catalog_items`, `list_ai_flow_triggers`, the `*_vulnerability_workflow` tools | A GitLab Duo add-on; seats and credits are read from the top-level group |

When a feature is not available to the token, the tool returns a clear error (for example `"Group 'my-org' has no Duo metrics available (not licensed or not permitted)"`) instead of an empty result. The server is developed against gitlab.com (GitLab 19.x); on older self-managed versions, tools that use newer GraphQL fields return a GraphQL error while the rest keep working.

## Installation

Pick one option. The MCP client runs the binary by its absolute path, so it does not have to be on your `PATH`, but **if you move it later, run `--install` again**.

### Option A — Prebuilt binary (recommended)

Every [release](https://github.com/slackwero/gitlab-mcp-plus/releases) ships one binary per platform plus its SHA-256 checksum:

| System | Asset |
|---|---|
| macOS, Apple Silicon (M1–M4) | `gitlab-mcp-plus-darwin-arm64` |
| macOS, Intel | `gitlab-mcp-plus-darwin-amd64` |
| Linux x86_64 | `gitlab-mcp-plus-linux-amd64` |
| Linux ARM64 | `gitlab-mcp-plus-linux-arm64` |

Download, verify and install it:

```bash
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; esac
ASSET="gitlab-mcp-plus-${OS}-${ARCH}"
BASE="https://github.com/slackwero/gitlab-mcp-plus/releases/latest/download"

curl -fsSLO "${BASE}/${ASSET}"
curl -fsSLO "${BASE}/${ASSET}.sha256"
sha256sum -c "${ASSET}.sha256" 2>/dev/null || shasum -a 256 -c "${ASSET}.sha256"

chmod +x "${ASSET}"
sudo mv "${ASSET}" /usr/local/bin/gitlab-mcp-plus
rm "${ASSET}.sha256"
```

Without `sudo`, use a directory in your home instead, for example `mkdir -p ~/.local/bin && mv "${ASSET}" ~/.local/bin/gitlab-mcp-plus`.

**macOS:** if you downloaded the file with a browser, Gatekeeper may block it the first time because it is not signed. Allow it with:

```bash
xattr -d com.apple.quarantine /usr/local/bin/gitlab-mcp-plus
```

### Option B — `go install`

With Go 1.26 or later (use a [supported Go release](https://go.dev/doc/devel/release#policy): the binary embeds Go's TLS and HTTP code, so an outdated toolchain ships its vulnerabilities):

```bash
go install github.com/slackwero/gitlab-mcp-plus@latest
```

The binary lands in `$(go env GOPATH)/bin` (usually `~/go/bin`). Builds made this way report version `dev`.

### Option C — Build from source

```bash
git clone https://github.com/slackwero/gitlab-mcp-plus.git
cd gitlab-mcp-plus
make build        # produces ./gitlab-mcp-plus
```

### Check the installation

```bash
gitlab-mcp-plus --version
# gitlab-mcp-plus v1.0.0 (commit abc1234, built 2026-11-10T12:00:00Z, darwin/arm64)
```

## Create a GitLab token

1. In GitLab, open **User settings → Personal access tokens** (on gitlab.com: <https://gitlab.com/-/user_settings/personal_access_tokens>; on self-managed, the same path on your instance).
2. Click **Add new token**, give it a name and an expiration date.
3. Select the scope:
   - **`api`** — full use: read tools plus the tools that change vulnerabilities, create projects or groups, or delete branches.
   - **`read_api`** — read-only use. Every `list_*` and `get_*` tool works; tools that change data fail with a permission error.
4. Create it and copy the value (`glpat-...`); GitLab shows it only once.

For a shared, organization-wide setup you can use a **group access token** or a **service account** token instead of a personal one: the tools then see exactly what that bot user can see.

## Connect your MCP client

### Claude Code

Requires the `claude` CLI on your `PATH` (check with `claude --version`).

```bash
export GITLAB_TOKEN=glpat-...
gitlab-mcp-plus --install claude
```

The installer validates the token against GitLab (and tells you which user it belongs to), checks that `claude` is available, asks before overwriting an existing registration, and then runs:

```bash
claude mcp add --scope user gitlab-mcp-plus \
  --env GITLAB_TOKEN=<token> \
  --env GITLAB_URL=https://gitlab.com \
  -- /usr/local/bin/gitlab-mcp-plus
```

Restart Claude Code afterwards. To run that command yourself instead, print it with `gitlab-mcp-plus --print-config claude` (the printed command reads the token from `$GITLAB_TOKEN`, so it never lands in your shell history).

Scopes (`--scope`):

- `user` *(default)* — available in all your projects.
- `local` — only for you, in the current project.
- `project` — writes the server to the project's `.mcp.json` so the whole team gets it. The file stores `${GITLAB_TOKEN}` instead of your token, and Claude Code expands it from the environment of each person who opens the project: everyone uses their own token and the file is safe to commit.

### Cursor

Cursor has no CLI for MCP servers; the installer edits its configuration file for you:

```bash
export GITLAB_TOKEN=glpat-...
gitlab-mcp-plus --install cursor
```

It reads `~/.cursor/mcp.json` (creating it if needed), saves the previous content to `~/.cursor/mcp.json.bak` (without the `gitlab-mcp-plus` entry, so the backup never keeps a token), adds or updates the entry **without touching your other servers**, and writes the file atomically with `0600` permissions. It refuses to follow a symbolic link: if your `mcp.json` is one, edit its target by hand. Restart Cursor afterwards.

With `--scope project` it writes `<current directory>/.cursor/mcp.json` with `${env:GITLAB_TOKEN}` instead of the token, which Cursor expands from each user's environment: the file is safe to commit, and each user needs `GITLAB_TOKEN` set in the environment Cursor starts from.

### Any other MCP client

Most clients accept the standard `mcpServers` format. Print a ready-made snippet with the binary path filled in; it never contains your token, only a `<GITLAB_TOKEN>` placeholder:

```bash
gitlab-mcp-plus --print-config cursor
```

```json
{
  "mcpServers": {
    "gitlab-mcp-plus": {
      "command": "/usr/local/bin/gitlab-mcp-plus",
      "args": [],
      "env": {
        "GITLAB_TOKEN": "glpat-...",
        "GITLAB_URL": "https://gitlab.com"
      }
    }
  }
}
```

Merge it into your client's MCP configuration file (see your client's documentation for its location), replace the placeholder with your token, and restart the client.

### Self-managed GitLab

Add your instance URL to any of the commands above:

```bash
gitlab-mcp-plus --install claude --gitlab-url https://gitlab.example.com
```

or set `GITLAB_URL=https://gitlab.example.com` before running them. The URL must use `https` (plain `http` is accepted only for `localhost`), since the token travels with every request.

### Read-only and restricted setups

Tools that are not registered cannot be called, even by a client that approves tool calls automatically or by an assistant tricked by text it read. To expose only what you need:

```bash
# Only the read tools: nothing can be changed in GitLab
gitlab-mcp-plus --install claude --read-only

# Only the tools you list
gitlab-mcp-plus --install claude --tools list_vulnerabilities,get_vulnerability,get_vulnerability_statistics
```

These set `GITLAB_MCP_READ_ONLY` and `GITLAB_MCP_TOOLS` in the registration (see [Environment variables](#environment-variables)). A misspelled tool name, or a write tool listed together with `--read-only`, is an error rather than a silent change. For a read-only setup, a `read_api` token adds the same guarantee on GitLab's side.

### Together with the official GitLab MCP server

Register both servers in your client. Each client namespaces tools by server, so they never conflict: the assistant uses the official server for issues, merge requests and pipelines, and this one for security, compliance and Duo.

## Configuration reference

### Environment variables

The server reads these when the client starts it. `--install` stores them in the client's registration, so you set them only once.

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITLAB_TOKEN` | Yes | — | GitLab token with the `api` (or `read_api`) scope |
| `GITLAB_URL` | No | `https://gitlab.com` | GitLab instance URL; `https` only (`http` only for `localhost`) |
| `GITLAB_MCP_READ_ONLY` | No | `false` | `true` registers only the read tools |
| `GITLAB_MCP_TOOLS` | No | all | Comma-separated list of the only tools to register |

The server refuses to start, with the reason on stderr, when any of these is invalid.

### Command line

Run with no arguments, `gitlab-mcp-plus` starts the MCP server over stdio; this is how clients invoke it. The administrative commands are:

| Flag | Description |
|---|---|
| `--install <claude\|cursor>` | Registers the server in the client. |
| `--uninstall <claude\|cursor>` | Removes the registration. |
| `--check <claude\|cursor>` | Diagnoses an installation: client availability, binary path, registration and token validity. |
| `--print-config <claude\|cursor>` | Prints the `claude mcp add` command or the JSON to configure it by hand, without your token. Runs nothing. |
| `--version` | Prints version, commit and build date. |
| `--help`, `-h` | Shows the help with examples. |

Modifiers for those commands:

| Flag | Default | Description |
|---|---|---|
| `--name <string>` | `gitlab-mcp-plus` | Name the server is registered under (e.g. to register two GitLab instances side by side). |
| `--scope <string>` | `user` | Claude: `user`, `local`, `project`. Cursor: `user`, `project`. |
| `--gitlab-token <string>` | `$GITLAB_TOKEN` | Token to use. If neither is set, it is prompted for without echo. Prefer the variable or the prompt: a flag stays in your shell history. |
| `--gitlab-url <string>` | `$GITLAB_URL` or `https://gitlab.com` | GitLab instance URL. |
| `--force`, `-f` | `false` | Overwrites an existing registration without asking. |
| `--yes`, `-y` | `false` | Skips confirmations (non-interactive use). |
| `--no-validate` | `false` | Skips the token check against GitLab (for a machine that cannot reach the API). |
| `--read-only` | `false` | Registers the server with only its read tools. |
| `--tools <a,b,...>` | all | Registers the server with only these tools. |

Examples:

```bash
# Non-interactive installation for a self-managed instance
gitlab-mcp-plus --install claude --gitlab-url https://gitlab.example.com --force --yes

# Two instances side by side
gitlab-mcp-plus --install claude --name gitlab-com
gitlab-mcp-plus --install claude --name gitlab-internal --gitlab-url https://gitlab.example.com

# Diagnose an installation, without contacting GitLab
gitlab-mcp-plus --check claude --no-validate
```

## Tools

Each tool declares MCP annotations so your client knows which ones only read and which change data:

| Kind | Annotations | Tools |
|---|---|---|
| Read | `readOnlyHint: true` | Every `list_*` and `get_*` tool |
| Create | `readOnlyHint: false`, `destructiveHint: false` | `create_project`, `create_group`, `fork_project`, `vulnerabilities_link_issue` |
| Change state | `readOnlyHint: false`, `destructiveHint: true` | `vulnerability_confirm`, `vulnerability_dismiss`, `vulnerability_resolve`, `vulnerability_revert_to_detected`, `vulnerabilities_bulk_dismiss`, `vulnerabilities_override_severity`, `vulnerabilities_set_due_date`, `start_vulnerability_workflow`, `cancel_vulnerability_workflow`, `delete_branch` |

Tools that accept `project_path` or `group_path` take exactly one of the two, as a full path (`my-org/team/app`). List tools page with `first` (default 20, max 100) and the `after` cursor.

### Vulnerability management

- **list_vulnerabilities** — Vulnerabilities of a project or group. Filters: `severity`, `state`, `report_type`, `scanner`, `has_issues`, `has_resolution`, `identifier_name` (e.g. `CVE-2026-1234`), `has_merge_request`, `has_ai_resolution`, `has_remediations`, `dismissal_reason` (`ACCEPTABLE_RISK`, `FALSE_POSITIVE`, `MITIGATING_CONTROL`, `USED_IN_TESTS`, `NOT_APPLICABLE`); `sort` (`severity_desc`, `severity_asc`, `detected_desc`, `detected_asc`). Besides `nodes`, it returns `totalCount` and `severityCounts` computed with the same filters.
- **get_vulnerability** — Full detail of one vulnerability: identifiers, location, solution, CVSS, EPSS and KEV (`cveEnrichment`), linked issues and merge requests, severity overrides, AI resolution availability, notes and state history.
- **get_vulnerability_statistics** — Severity distribution of a project or group.
- **vulnerability_confirm** / **vulnerability_resolve** / **vulnerability_revert_to_detected** — Change the state of one vulnerability.
- **vulnerability_dismiss** — Dismisses one vulnerability with a reason and comment.
- **vulnerabilities_bulk_dismiss** — Dismisses up to 100 vulnerabilities (`ids`), with an optional `comment` and `dismissal_reason`.
- **vulnerabilities_override_severity** — Overrides the severity of up to 100 vulnerabilities (`ids`). `severity` and a non-empty `comment` are required.
- **vulnerabilities_link_issue** — Links up to 100 vulnerabilities (`ids`) to an existing issue (`issue_project_path`, `issue_iid`).
- **vulnerabilities_set_due_date** — Sets (`due_date`, `YYYY-MM-DD`) or removes (`remove_due_date: true`) the due date of up to 1000 findings of a project (`finding_uuids`); exactly one of the two is required. Returns `assigned`, `removed`, `skipped` and per-finding `errors`.
- **start_vulnerability_workflow** — Starts a GitLab Duo workflow over the findings of a project (`project_path`): `SAST_FP_DETECTION_V1` (detect SAST false positives), `SECRETS_FP_DETECTION_V1` (detect secret false positives) or `RESOLVE_SAST_VULNERABILITY_V1` (generate fixes with AI, which may open merge requests). **Every call starts a billed run that consumes GitLab Credits in proportion to the findings processed**, so the tool asks the assistant to confirm project, workflow and scope with you first. The scope is never implied: pass `finding_uuids` (up to 1000, the `uuid` field of `list_vulnerabilities`) or `all_findings: true`, not both. `severities` narrows the selection. Unknown arguments are rejected before calling GitLab. If the request fails midway, the error says the run may have started: check `get_vulnerability_workflow` before retrying.
- **get_vulnerability_workflow** — Status of a Duo workflow execution (`project_path`, `workflow`, optional `execution_id`; latest by default). Per-finding states only with `include_items: true`.
- **cancel_vulnerability_workflow** — Cancels the running execution of a Duo workflow in a project.

### Pipeline security

- **list_pipeline_security_findings** — Security findings of one pipeline. Filters: `report_type` (`sast`, `dependency_scanning`, `secret_detection`, …) and `severity`.
- **list_vulnerability_scanners** — Scanners that have produced findings.

### Security policies and compliance

- **list_security_policies** — Policies of every type (approval, scan execution, pipeline execution, vulnerability management). Filter with `policy_type`, include each policy's YAML with `include_yaml`, and use `relationship=DESCENDANT` (groups only) to include descendant groups and projects. Returns one GitLab page; `pageInfo.hasNextPage` is `true` when more exist.
- **list_scan_execution_policies** — Scan execution policies with their YAML.
- **list_compliance_frameworks** — Compliance frameworks of a project or group.
- **list_compliance_violations** — Compliance violations in the projects of a group (`group_path`): control, requirement, framework, project, triggering audit event and status. Filters: `status` (`DETECTED`, `IN_REVIEW`, `RESOLVED`, `DISMISSED`), `created_after` / `created_before` (`YYYY-MM-DD`), `project_path`.

### Security posture

- **list_dependencies** — Dependencies (SBOM) of a project or group: version, package manager, licenses, reachability, vulnerability count and location. Filters: `component_names` (exact names, to find where a package is used) and `package_managers` (`NPM`, `MAVEN`, `GO`, …); `sort` (e.g. `SEVERITY_DESC`).
- **get_security_scanner_coverage** — Scanner coverage of a group and its subgroups: for each analyzer (`SAST`, `DEPENDENCY_SCANNING`, `SECRET_DETECTION`, …) the projects where it succeeded, failed, is stale or is not configured, plus `coveragePercent`.
- **get_vulnerability_trend** — Daily count of open vulnerabilities by severity for a project or group. `start_date` / `end_date` (`YYYY-MM-DD`, default: the last 30 days). GitLab keeps 365 days and the tool pages internally, so a full year comes back in one call. On a very large top-level group GitLab may time out: use a subgroup or a shorter range.

### GitLab Duo usage and cost

- **get_duo_ai_metrics** — Duo usage of a group or project: code suggestions (with acceptance rates), chat, code review, MCP tool calls, troubleshooting and Agent Platform sessions and flows. `periods` splits the date range into a trend; `ide_names` and `languages` restrict the code suggestion metrics.
- **list_duo_user_metrics** — Per-user Duo activity of a group or project: last Duo activity and event counts. Useful to find inactive seats and top adopters. `start_date` / `end_date` (default: the current month), `sort`.
- **get_duo_seat_usage** — Purchased, assigned and unassigned seats per Duo add-on of a top-level group.
- **list_duo_seat_users** — Users of a Duo add-on in a top-level group with their last activity. `add_on_type` (default `DUO_ENTERPRISE`), `assigned` (`false` lists eligible users without a seat), `search`, `sort`.
- **get_gitlab_credits_usage** — GitLab Credits consumption of a top-level group: credits used, daily usage, commitment, overage, budget caps, usage per product and the top consuming users. `start_date` / `end_date`, `flow_types`, `top_users` (default 10, max 100).

### AI governance

- **get_ai_governance_metrics** — AI sessions and agents with trend, distribution by agent or flow type, externally connected agents (Claude Code, Cursor, Codex), top users and projects, and tool calls grouped by risk. `timeframe` (`LAST_24_HOURS`, `LAST_7_DAYS` default, `LAST_30_DAYS`), `agent_class` (`ALL`, `INTERNAL_DAP`, `EXTERNAL`), `top`.
- **list_ai_governance_sessions** — AI sessions recorded for governance, from GitLab Duo and external agents: who triggered each one, its source and audit event count. Filters: `flow_type`, `agent_class`, `started_after` / `started_before`, `session_project_path`.
- **get_ai_governance_session** — One session (`id`) with its audit events. Pass the same `group_path` or `project_path` used to list it.
- **list_ai_catalog_items** — AI Catalog agents and flows enabled in a group or project, with the service account each runs as.
- **list_ai_flow_triggers** — AI flow triggers of a project: event types, config path, the user each runs as and the catalog item it uses.

> The session tools return personal data (user names, IP addresses).

### Groups and projects

- **get_group** — Group metadata, settings, statistics and storage breakdown.
- **list_groups** — Groups, filtered by `search`, `parent_path`, `owned_only`, `top_level_only`, `ids`, `sort`.
- **list_descendant_groups** — Subgroups of a group, optionally recursive.
- **list_group_projects** — Projects of a group. Filters: `search`, `include_subgroups`, `archived` (`INCLUDE`/`EXCLUDE`/`ONLY`), `has_merge_requests_enabled`, `has_vulnerabilities`, `ids`, `not_aimed_for_deletion`, `sort` (e.g. `STORAGE_SIZE_DESC`). Includes compliance frameworks and storage statistics.
- **list_group_members** — Members with `access_levels`, `relations`, `search`, `sort`; returns `lastActivityOn` to spot inactive accounts.
- **list_group_audit_events** — Group audit events. Filters: `created_after`, `created_before`, `author_username`. Paginates by page number (`after` = page; `pageInfo.endCursor` is the next one).
- **list_group_merge_requests** — Merge requests across a group's projects, with `state`, `labels`, `milestone_title`, `assignee_username`, `author_username`, `reviewer_username`, date ranges, branches, `draft` and `sort`. Returns merge status and approvals.
- **create_project** — Creates a project (`name`; optional `path`, `namespace_path` — default: your personal namespace —, `description`, `visibility` — default `private` —, `initialize_with_readme`).
- **create_group** — Creates a group or subgroup (`name`, `path`; optional `parent_path`, `description`, `visibility` — default `private`).
- **fork_project** — Forks a project (`project_path`; optional `namespace_path`, `name`, `path`, `description`, `visibility`).
- **delete_branch** — Deletes a branch (`project_path`, `branch`). It always refuses the default branch and protected branches, and refuses unmerged branches unless `allow_unmerged: true`. Returns the last commit so the branch can be restored.

## Security

- **Untrusted content and prompt injection.** Results include text written by other people: vulnerability descriptions, merge request titles, audit event details. Text crafted to look like instructions can push an assistant to call a write tool, for example to dismiss vulnerabilities. Clients that honour MCP annotations ask before running write tools, but auto-approval removes that check. If you do not need to change data, use `--read-only` (and a `read_api` token); otherwise, keep confirmations on for write tools.
- **Least privilege.** Give the token an expiration date, and for shared setups prefer a group access token or a service account limited to the groups it needs. `--tools` narrows the server to the tools a use case needs.
- **Token storage.** The client keeps the token in its own configuration: Claude Code in `~/.claude.json`, Cursor in `~/.cursor/mcp.json` (written with `0600`). Project-scope installs store a reference to `GITLAB_TOKEN`, never the token. `--print-config` never prints the token.
- **Token exposure while installing.** The `claude` CLI takes environment values only as arguments, so during `--install claude` (user or local scope) the token is briefly visible in the process list. Prefer `export GITLAB_TOKEN=...` or the hidden prompt over `--gitlab-token`, which also stays in your shell history.
- **Transport.** The server only talks to the configured `GITLAB_URL` over https and caps each GitLab response at 32 MiB. It opens no port: the client talks to it over stdio.
- **Guarded changes.** `delete_branch` refuses default, protected and (by default) unmerged branches; bulk tools reject the whole request, before calling GitLab, if any ID is invalid or the list exceeds GitLab's limit.
- **Cost.** `start_vulnerability_workflow` consumes GitLab Credits on every call.
- **Personal data.** The AI governance session tools, member lists, audit events and per-user Duo metrics return names and IP addresses, which reach your AI provider. Leave those tools out with `--tools` if that is a concern.

## Troubleshooting

| Symptom | What to do |
|---|---|
| The client does not show the tools | Restart the client after installing. Run `gitlab-mcp-plus --check claude` (or `cursor`) to see the registration, binary path and token status. |
| `HTTP 401: invalid or expired token` | Create a new token and run `--install` again with `--force`. |
| `HTTP 403` or a permission error on a write tool | The token lacks the `api` scope or its user lacks the role for that action. |
| `... not available (not licensed or not permitted)` | The feature is not in your GitLab tier or add-ons, or the user cannot see it (see [What your GitLab plan needs](#what-your-gitlab-plan-needs)). |
| `... not found` for a group or project | Check the full path (`my-org/team/app`) and that the token's user can access it. |
| Seats or credits fail on a subgroup | Those are only available on the top-level group. |
| `get_vulnerability_trend` times out | Use a subgroup or a shorter date range. |
| The client stopped finding the binary | You moved it: run `--install` again from its new location. |
| `'claude' CLI not found in PATH` | Install Claude Code, or configure it by hand with `--print-config claude`. |
| `GITLAB_URL: the GitLab URL must use https` | Use the `https://` address of your instance. |
| `unknown tool ... in GITLAB_MCP_TOOLS` | Fix the name; the tool names are listed in [Tools](#tools). |
| `refusing to use .../mcp.json: it is a symbolic link` | Edit the file the link points to by hand, using `--print-config cursor`. |
| A project-scope install starts without a token | Export `GITLAB_TOKEN` in the environment the client starts from. |

## Upgrading and uninstalling

**Upgrade:** replace the binary with the new one (same path) and restart the client. No reinstallation is needed unless the path changed.

**Uninstall:**

```bash
gitlab-mcp-plus --uninstall claude     # or: --uninstall cursor
sudo rm /usr/local/bin/gitlab-mcp-plus
```

Then revoke the token in GitLab if you no longer need it.

## Development

Requires Go 1.26 or later; the `toolchain` line of `go.mod` pins the patched release that CI, releases and local builds use (the `go` command downloads it automatically).

### Project layout

```
main.go              flags, --version/--help and startup
internal/gitlab/     GitLab API client: GraphQL, REST, URL and token validation
internal/tools/      the MCP tools, one file per domain, and the server with its tool policy
internal/setup/      --install, --uninstall, --check and --print-config for Claude Code and Cursor
```

Dependencies point one way: `main` uses `tools` and `setup`, and both use `gitlab`. Tests live next to the code they cover.

```bash
make build                          # ./gitlab-mcp-plus
go vet ./... && go test ./...       # unit tests, offline against a fake GitLab
go test -run 'TestListVulnerabilities' -v .     # a subset of tests
```

Two opt-in suites talk to real GitLab:

- `make check-schema` validates every GraphQL query and mutation of the server against the live gitlab.com schema. It sends them unauthenticated and without variables, so nothing is executed. gitlab.com rate-limits unauthenticated traffic per IP, so run it once rather than in a loop. Set `GITLAB_URL` to check another instance.
- `make smoke` calls every read tool through the real MCP server. It needs `GITLAB_TOKEN`, `SMOKE_GROUP` (a top-level group) and `SMOKE_PROJECT` (a project path) and skips otherwise. It never runs a write tool.

### Security checks

Every push and pull request, and a weekly schedule, run:

| Workflow | What it checks |
|---|---|
| [Security](.github/workflows/security.yml) | `govulncheck` (known vulnerabilities in the dependencies and in the Go standard library that the code actually reaches) and `gitleaks` (secrets in every commit of the history; exceptions live in `.gitleaks.toml`) |
| [CodeQL](.github/workflows/codeql.yml) | Static analysis (SAST) with the `security-extended` queries; results under **Security → Code scanning** |
| [Dependency review](.github/workflows/dependency-review.yml) | Pull requests that add or upgrade a dependency with a known vulnerability |

Dependabot keeps the Go modules and the GitHub Actions up to date.

### Releasing

Push a semver tag; the [Release workflow](.github/workflows/release.yml) runs the tests, builds the four binaries with their version information and publishes them with their checksums as a GitHub Release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

[MIT](LICENSE)
