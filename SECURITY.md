# Security policy

## Supported versions

Security fixes go into the latest release only. Upgrade to it before reporting, and see [Upgrading](README.md#upgrading-and-uninstalling).

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub: [Security → Report a vulnerability](https://github.com/slackwero/gitlab-mcp-plus/security/advisories/new).

Include, when you can:

- the version (`gitlab-mcp-plus --version`), the MCP client, and gitlab.com or self-managed;
- what an attacker controls and what they gain;
- the steps or the input that reproduce it. Never include a real token or private GitLab data: redact them.

Reports are triaged in the private advisory. A confirmed issue is fixed in a new release and disclosed through a GitHub Security Advisory that credits the reporter, unless you prefer otherwise.

## Scope

In scope, among others:

- a way to run a tool that the configured policy excludes (`GITLAB_MCP_READ_ONLY`, `GITLAB_MCP_TOOLS`);
- token exposure: in files, output, logs, error messages or process arguments beyond what the [README](README.md#security) documents;
- a write tool acting beyond its arguments, or a guard that can be bypassed (`delete_branch`, bulk limits, the explicit scope of `start_vulnerability_workflow`);
- the installer writing outside the client's configuration file, or following links;
- requests reaching a host other than the configured `GITLAB_URL`.

Not vulnerabilities by themselves:

- a tool doing what the token's GitLab permissions allow: the server acts as the token's user;
- an assistant following instructions embedded in GitLab content (prompt injection). That is a risk of every MCP server; restrict the tools with `--read-only` or `--tools` and keep confirmations on for write tools;
- [GO-2026-6911](https://pkg.go.dev/vuln/GO-2026-6911) in `github.com/mark3labs/mcp-go`, reported by binary scanners: the affected HTTP client transport is linked but never called. It will be upgraded as soon as a fixed version exists.

## Verifying a release

Each binary has a `.sha256` file next to it. Releases after v1.0.0 also carry a signed [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation that proves the binary was built by this repository's release workflow:

```bash
gh attestation verify gitlab-mcp-plus-darwin-arm64 --repo slackwero/gitlab-mcp-plus
```
