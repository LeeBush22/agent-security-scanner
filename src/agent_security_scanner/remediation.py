from __future__ import annotations

from agent_security_scanner.models import Finding, Remediation
from agent_security_scanner.rules_catalog import rule_prefix


DEFAULT_STEPS = [
    "Review the finding and confirm whether the behavior is intentional.",
    "Apply the recommendation with the smallest permission or configuration change possible.",
    "Re-run agent-scan to confirm the finding is resolved or explicitly ignored with a reason.",
]


RULE_REMEDIATION: dict[str, Remediation] = {
    "SEC": Remediation(
        summary="Remove plaintext credentials from files and rotate exposed values.",
        steps=[
            "Move the credential to an environment variable or secret manager.",
            "Rotate the exposed credential in the provider console.",
            "Remove the plaintext value from source history if it was committed.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP001": Remediation(
        summary="Restrict MCP filesystem access to a narrow project directory.",
        steps=[
            "Replace root, home, or drive-level paths with a project-specific directory.",
            "Keep only directories that the MCP server must read or write.",
            "Run the scanner again to confirm broad paths are gone.",
        ],
        effort="low",
        automatable=False,
    ),
    "MCP002": Remediation(
        summary="Review and restrict shell-capable MCP server commands.",
        steps=[
            "Confirm the MCP server requires shell-capable execution.",
            "Replace broad shell commands with a dedicated executable when possible.",
            "Require manual approval for command execution paths.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP003": Remediation(
        summary="Remove embedded secrets from MCP environment settings.",
        steps=[
            "Replace plaintext env values with references to local environment variables.",
            "Rotate any exposed credentials.",
            "Document required environment variable names without committing values.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP004": Remediation(
        summary="Review remote MCP servers before enabling them.",
        steps=[
            "Verify the remote server owner and transport security.",
            "Document what data may be sent to the remote server.",
            "Prefer local MCP servers for sensitive repositories.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP005": Remediation(
        summary="Remove dangerous MCP permission flags.",
        steps=[
            "Remove unsafe flags such as --allow-all or --no-sandbox.",
            "Grant only the minimum permission set required.",
            "Use project-local paths and manual approval for high-risk operations.",
        ],
        effort="low",
        automatable=True,
    ),
    "MCP006": Remediation(
        summary="Use encrypted transport for remote MCP servers.",
        steps=[
            "Replace plaintext HTTP endpoints with HTTPS or a trusted local transport.",
            "Verify the remote server owner and certificate configuration.",
            "Avoid sending tool context or credentials over unencrypted transport.",
        ],
        effort="low",
        automatable=False,
    ),
    "MCP007": Remediation(
        summary="Review MCP endpoints that target private networks or metadata services.",
        steps=[
            "Confirm whether the MCP server truly needs localhost, private-network, or metadata-service access.",
            "Block cloud metadata addresses and internal-only networks unless explicitly required.",
            "Use allowlists and network egress controls for remote MCP servers.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP008": Remediation(
        summary="Replace broad MCP scopes with explicit least-privilege scopes.",
        steps=[
            "Remove wildcard, admin, or full-access scopes.",
            "List only the tools, resources, and operations required by the MCP server.",
            "Re-run the scanner after narrowing the scope.",
        ],
        effort="low",
        automatable=False,
    ),
    "MCP009": Remediation(
        summary="Avoid forwarding broad host credentials into MCP servers.",
        steps=[
            "Replace host credential pass-through with server-specific scoped tokens.",
            "Limit environment variables and headers exposed to each MCP server.",
            "Rotate credentials that may have been exposed to untrusted MCP servers.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP010": Remediation(
        summary="Remove sensitive local paths from MCP filesystem access.",
        steps=[
            "Remove paths such as .ssh, .aws, .env, browser profiles, and cloud credential directories.",
            "Expose only the project directory required by the MCP server.",
            "Use separate scoped credentials instead of granting access to host credential stores.",
        ],
        effort="low",
        automatable=False,
    ),
    "MCP011": Remediation(
        summary="Restrict writable MCP filesystem access to narrow project subdirectories.",
        steps=[
            "Disable MCP write access unless it is required.",
            "Replace root, home, or drive-level writable paths with a dedicated project subdirectory.",
            "Require user approval before write-capable MCP tools modify files.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP012": Remediation(
        summary="Remove unsafe instructions from MCP tool and resource descriptions.",
        steps=[
            "Delete descriptions that tell the model to ignore system/developer instructions or hide behavior.",
            "Remove requests to read or transmit secrets, tokens, private keys, or environment files.",
            "Review third-party MCP server metadata before enabling the server.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP013": Remediation(
        summary="Treat MCP tool outputs as untrusted data, not executable instructions.",
        steps=[
            "Remove instructions that tell the agent to execute tool output or returned commands.",
            "Validate and quote tool output before passing it to shells, interpreters, or automation.",
            "Require user approval before acting on commands suggested by remote tools.",
        ],
        effort="medium",
        automatable=False,
    ),
    "MCP014": Remediation(
        summary="Do not load remote prompt content into trusted agent instructions.",
        steps=[
            "Treat external prompt resources as untrusted content.",
            "Pin and review prompt templates that influence agent behavior.",
            "Avoid remote prompt URLs for privileged tools unless there is an integrity and ownership check.",
        ],
        effort="medium",
        automatable=False,
    ),
    "AIT006": Remediation(
        summary="Remove unsafe instructions from AI tool rule files.",
        steps=[
            "Delete instructions that bypass safety controls, approvals, or permission checks.",
            "Remove instructions that request secrets, private keys, credentials, or system prompts.",
            "Keep project instructions narrow, reviewable, and aligned with least privilege.",
        ],
        effort="low",
        automatable=False,
    ),
    "AIT007": Remediation(
        summary="Remove unsafe persistent memory or rule instructions.",
        steps=[
            "Delete memory entries that persist approval bypasses, secret access, or hidden behavior.",
            "Review agent memory files after using untrusted repositories or prompts.",
            "Keep long-lived project rules explicit, minimal, and version reviewed.",
        ],
        effort="low",
        automatable=False,
    ),
    "AIT008": Remediation(
        summary="Require user review for autonomous agent actions.",
        steps=[
            "Remove instructions that tell agents to deploy, publish, merge, or execute without approval.",
            "Require explicit confirmation for long-running work and external side effects.",
            "Limit automation to narrow, reversible tasks.",
        ],
        effort="low",
        automatable=False,
    ),
    "AIT009": Remediation(
        summary="Remove instructions that allow data exfiltration.",
        steps=[
            "Delete instructions that upload repositories, workspace files, tokens, or credentials.",
            "Route necessary telemetry or uploads through reviewed, documented destinations.",
            "Treat external webhooks and callbacks as untrusted unless explicitly approved.",
        ],
        effort="medium",
        automatable=False,
    ),
    "AIT010": Remediation(
        summary="Avoid granting shell, file-write, and network access together without approval gates.",
        steps=[
            "Split high-risk tools into separate approval-required permissions.",
            "Require manual confirmation before shell, file-write, browser, or network actions.",
            "Use least-privilege allowlists instead of all-tools permissions.",
        ],
        effort="medium",
        automatable=False,
    ),
    "SH": Remediation(
        summary="Replace dangerous shell patterns with reviewable, least-privilege commands.",
        steps=[
            "Avoid piping downloaded content directly into a shell.",
            "Avoid broad destructive commands and opaque encoded execution.",
            "Use explicit paths, integrity checks, and reviewed scripts.",
        ],
        effort="medium",
        automatable=False,
    ),
    "SC": Remediation(
        summary="Harden supply-chain configuration and pin trusted inputs.",
        steps=[
            "Review install hooks, remote dependency sources, container mounts, and build-time downloads.",
            "Pin dependency versions and container images to reviewed versions or digests.",
            "Move package manager credentials to environment variables or a secret manager.",
        ],
        effort="medium",
        automatable=False,
    ),
    "FS": Remediation(
        summary="Reduce filesystem exposure and remove sensitive local files from the project.",
        steps=[
            "Remove local credential files and host security directories from the project workspace.",
            "Add sensitive file patterns to .gitignore or the scanner allowlist only with a documented reason.",
            "Use owner-only permissions for credential files and avoid broad chmod patterns.",
        ],
        effort="low",
        automatable=False,
    ),
    "SC005": Remediation(
        summary="Remove package manager credentials from config files.",
        steps=[
            "Move npm, PyPI, or netrc credentials to environment variables or a secret manager.",
            "Rotate exposed package registry credentials.",
            "Avoid committing package manager auth files with plaintext values.",
        ],
        effort="medium",
        automatable=False,
    ),
    "SC009": Remediation(
        summary="Avoid privileged or host-level container settings.",
        steps=[
            "Remove privileged mode and host namespace/network settings unless explicitly required.",
            "Run containers with least privilege and scoped capabilities.",
            "Isolate development containers that need elevated access.",
        ],
        effort="medium",
        automatable=False,
    ),
    "SC010": Remediation(
        summary="Avoid mounting sensitive host paths into containers.",
        steps=[
            "Remove Docker socket, host root, SSH, cloud credential, and broad home-directory mounts.",
            "Mount only project-local directories required by the service.",
            "Use scoped credentials instead of sharing host credential stores.",
        ],
        effort="medium",
        automatable=False,
    ),
    "SC012": Remediation(
        summary="Avoid mounting sensitive host paths into devcontainers.",
        steps=[
            "Remove SSH, cloud credential, Docker socket, or broad host mounts from devcontainer settings.",
            "Use per-project credentials and explicit mount paths.",
            "Review devcontainer lifecycle commands before onboarding contributors.",
        ],
        effort="medium",
        automatable=False,
    ),
    "GHA": Remediation(
        summary="Harden GitHub Actions workflow permissions and execution paths.",
        steps=[
            "Use least-privilege workflow permissions.",
            "Pin third-party actions to full commit SHAs.",
            "Avoid running untrusted code with elevated events or self-hosted runners.",
        ],
        effort="medium",
        automatable=False,
    ),
    "GHA007": Remediation(
        summary="Avoid interpolating untrusted GitHub event data directly into shell commands.",
        steps=[
            "Move untrusted expressions into environment variables.",
            "Quote and validate values before using them in shell commands.",
            "Avoid executing commands derived from pull request titles, bodies, comments, or branch names.",
        ],
        effort="medium",
        automatable=False,
    ),
    "GHA008": Remediation(
        summary="Restrict OIDC token permissions and cloud trust policies.",
        steps=[
            "Grant id-token: write only to jobs that need cloud federation.",
            "Verify cloud role trust policies restrict repository, branch, workflow, subject, and audience.",
            "Avoid combining broad repository write permissions with OIDC deployment permissions.",
        ],
        effort="medium",
        automatable=False,
    ),
    "GHA009": Remediation(
        summary="Avoid trusting cache or artifact contents from untrusted workflow contexts.",
        steps=[
            "Use separate cache keys for trusted and untrusted events.",
            "Avoid restoring privileged caches in pull request workflows from forks.",
            "Treat downloaded artifacts as untrusted input until validated.",
        ],
        effort="medium",
        automatable=False,
    ),
    "GHA010": Remediation(
        summary="Validate artifacts or cache content before execution.",
        steps=[
            "Do not execute files from artifacts or caches without integrity checks.",
            "Validate checksums, provenance, and expected file paths before execution.",
            "Keep artifact-processing jobs read-only unless write access is required.",
        ],
        effort="medium",
        automatable=False,
    ),
    "GHA011": Remediation(
        summary="Harden workflow_run pipelines that process artifacts.",
        steps=[
            "Assume artifacts from upstream workflows may be attacker-controlled.",
            "Validate artifact provenance and contents before using them in privileged jobs.",
            "Keep workflow_run permissions read-only unless deployment or publishing explicitly requires writes.",
        ],
        effort="medium",
        automatable=False,
    ),
    "AIT": Remediation(
        summary="Reduce AI coding tool automation and filesystem permissions.",
        steps=[
            "Disable broad auto-approval and permission bypass settings.",
            "Limit workspace access to the current project directory.",
            "Require confirmation before shell commands, file edits, and network access.",
        ],
        effort="low",
        automatable=False,
    ),
}


def enrich_remediation(findings: list[Finding]) -> list[Finding]:
    return [finding.model_copy(update={"remediation": remediation_for(finding)}) for finding in findings]


def remediation_for(finding: Finding) -> Remediation:
    specific = RULE_REMEDIATION.get(finding.rule_id)
    if specific:
        return specific
    prefix = RULE_REMEDIATION.get(rule_prefix(finding.rule_id))
    if prefix:
        return prefix
    return Remediation(
        summary=finding.recommendation,
        steps=DEFAULT_STEPS,
        effort="medium",
        automatable=False,
    )
