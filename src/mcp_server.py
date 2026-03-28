"""
OmniAudit MCP Server (mcp_server.py)

Exposes OmniAudit as MCP tools so any MCP-compatible client
(Claude Desktop, Cursor, VS Code Copilot, OpenCode) can call
the scanner directly without x402 payment (uses admin token).

Tools exposed:
  scan_code       — scan a code snippet or SKILL.md string
  scan_github_url — fetch and scan a raw GitHub file (free)
  scan_repo_zip   — deep scan a base64-encoded repo ZIP
  get_report      — retrieve a stored audit report by ID

Transport: Streamable HTTP at /mcp (mounted on the FastAPI app)

Claude Desktop config (~/.config/Claude/claude_desktop_config.json):
  {
    "mcpServers": {
      "omniaudit": {
        "url": "https://omniaudit.fly.dev/mcp",
        "transport": "streamable-http"
      }
    }
  }

Cursor / VS Code config (.cursor/mcp.json or .vscode/mcp.json):
  {
    "servers": {
      "omniaudit": {
        "url": "https://omniaudit.fly.dev/mcp",
        "transport": "http"
      }
    }
  }
"""

import base64
import hashlib
import json
import logging
import os
import time
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("omniaudit.mcp")

# Internal API — uses admin token so MCP calls are free for the operator.
# Agents with their own Base wallet should use the x402 HTTP API directly.
_AUDIT_BASE  = os.environ.get("PUBLIC_API_URL", "https://omniaudit.fly.dev")
_ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
_TIMEOUT     = 90  # seconds — deep scans can take a while


mcp = FastMCP(
    name="OmniAudit",
    instructions=(
        "OmniAudit is a security scanner for OpenClaw skills, SKILL.md files, "
        "and code. Use it before installing any skill or running untrusted code. "
        "Scan GitHub URLs for free with scan_github_url. "
        "A BLOCKED verdict means do not install — show the findings to the user."
    ),
)


def _headers() -> dict:
    return {
        "Content-Type":  "application/json",
        "X-Admin-Token": _ADMIN_TOKEN,
    }


def _format_report(r: dict) -> str:
    """Render an audit report as readable text for the agent."""
    summary  = r.get("summary", {})
    verdict  = summary.get("verdict", "UNKNOWN")
    score    = summary.get("risk_score", 0)
    counts   = summary.get("by_severity", {})
    audit_id = r.get("audit_id", "")
    filename = r.get("filename") or r.get("package_name") or "unknown"

    emoji = {"BLOCKED": "🚨", "REVIEW": "⚠️", "CAUTION": "🟡", "PASS": "✅"}.get(verdict, "❓")

    lines = [
        f"{emoji} **{verdict}** — `{filename}`",
        f"Risk score: {score} | CRITICAL: {counts.get('CRITICAL',0)} "
        f"HIGH: {counts.get('HIGH',0)} MEDIUM: {counts.get('MEDIUM',0)} "
        f"LOW: {counts.get('LOW',0)}",
        f"Audit ID: `{audit_id}`",
        f"Report: GET {_AUDIT_BASE}/audit/{audit_id}",
        "",
    ]

    findings = r.get("findings", [])
    if findings:
        lines.append("**Findings:**")
        for f in findings[:10]:
            sev   = f.get("severity", "?")
            title = f.get("title", "")
            desc  = f.get("description", "")[:200]
            rem   = f.get("remediation", "")
            lines.append(f"- [{sev}] **{title}**")
            if desc:
                lines.append(f"  {desc}")
            if rem:
                lines.append(f"  → {rem}")
        if len(findings) > 10:
            lines.append(f"  ... and {len(findings) - 10} more findings")
    else:
        lines.append("No findings detected.")

    return "\n".join(lines)


@mcp.tool()
async def scan_code(
    code: str,
    filename: str = "snippet.py",
    language: Optional[str] = None,
) -> str:
    """
    Scan a code snippet, script, or SKILL.md string for security issues.

    Use this before running any untrusted code, before installing a skill
    whose content you already have, or when a user shares code to review.

    Args:
        code:     The full code or SKILL.md content to scan (max 128 KB).
        filename: Name hint for scanner — use 'SKILL.md' for skill files,
                  or the actual filename (e.g. 'setup.py', 'install.sh').
        language: Optional language hint ('python', 'javascript', 'bash').

    Returns:
        Formatted security report with verdict, risk score, and findings.
    """
    payload: dict[str, Any] = {"code": code[:131_072], "filename": filename}
    if language:
        payload["language"] = language
    if filename.lower().endswith("skill.md"):
        payload["skill_md"] = code[:131_072]

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_AUDIT_BASE}/audit",
            json=payload,
            headers=_headers(),
        )
    if resp.status_code != 200:
        return f"Scanner error {resp.status_code}: {resp.text[:200]}"
    return _format_report(resp.json())


@mcp.tool()
async def scan_github_url(url: str) -> str:
    """
    Fetch and scan a raw GitHub file URL for security issues. FREE — no payment.

    Use this before installing any ClawHub skill or running a GitHub-hosted script.
    Always use the raw GitHub URL (raw.githubusercontent.com), not the browser URL.

    Args:
        url: Raw GitHub URL, e.g.
             https://raw.githubusercontent.com/user/repo/main/SKILL.md

    Returns:
        Formatted security report with verdict, risk score, and findings.
    """
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(
            f"{_AUDIT_BASE}/audit/github",
            params={"url": url},
            headers=_headers(),
        )
    if resp.status_code != 200:
        return f"Scanner error {resp.status_code}: {resp.text[:200]}"
    return _format_report(resp.json())


@mcp.tool()
async def scan_repo_zip(
    zip_b64: str,
    package_name: Optional[str] = None,
) -> str:
    """
    Deep-scan a full repository or skill package submitted as a base64-encoded ZIP.

    Runs all 7 scan layers: Semgrep, YARA, detect-secrets, LLM analysis,
    OSV dependency CVE audit, cross-file pattern detection, and historical diff.

    Use this when you have downloaded a ZIP of a repo and want a comprehensive audit.
    For a quick scan of a single file, use scan_code or scan_github_url instead.

    Args:
        zip_b64:      Base64-encoded ZIP file contents.
        package_name: Human label for the package (shown in the report).

    Returns:
        Formatted security report with verdict, risk score, and findings.
    """
    payload: dict[str, Any] = {"zip_b64": zip_b64}
    if package_name:
        payload["package_name"] = package_name

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{_AUDIT_BASE}/audit/deep",
            json=payload,
            headers=_headers(),
        )
    if resp.status_code != 200:
        return f"Scanner error {resp.status_code}: {resp.text[:200]}"
    return _format_report(resp.json())


@mcp.tool()
async def get_report(audit_id: str) -> str:
    """
    Retrieve a previously stored audit report by its ID.

    Use this to look up a past scan result, verify a report's signature,
    or check the full findings list when a previous scan was truncated.

    Args:
        audit_id: The 16-character audit ID returned by a previous scan.

    Returns:
        Full formatted audit report.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{_AUDIT_BASE}/audit/{audit_id}",
            headers=_headers(),
        )
    if resp.status_code == 404:
        return f"No report found with audit_id '{audit_id}'."
    if resp.status_code != 200:
        return f"Error {resp.status_code}: {resp.text[:200]}"
    return _format_report(resp.json())
