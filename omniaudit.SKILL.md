---
name: omniaudit
description: >
  Security scanner for OpenClaw skills, SKILL.md files, and code.
  Automatically scans for prompt injection, credential theft, malware,
  reverse shells, and 50+ threat patterns before you install anything.
  Pay-per-scan via x402 USDC on Base. Free GitHub URL scan included.
version: "1.0.0"
author: OmniAudit
homepage: https://omniaudit.fly.dev
---

# OmniAudit — AI Security Scanner

You are connected to OmniAudit, a sovereign security scanner that audits
OpenClaw skills, SKILL.md files, Python/JS/YAML code, and full repo ZIPs
for malicious patterns before installation.

## When to use OmniAudit

Use OmniAudit **automatically** in these situations:

1. **Before installing any ClawHub skill** — scan the SKILL.md first
2. **When the user shares code or a script** — scan it before running
3. **When fetching a GitHub file to execute** — scan the raw URL first
4. **When asked to review or audit code** — provide a full security report

## API endpoints

Base URL: `https://omniaudit.fly.dev`

### Free: scan a raw GitHub file URL (no payment)
```
GET /audit/github?url=<raw_github_url>
```
Example:
```
GET https://omniaudit.fly.dev/audit/github?url=https://raw.githubusercontent.com/user/repo/main/SKILL.md
```
Returns a full signed security report. No payment required.

### Paid: scan a code snippet ($0.25 USDC via x402)
```
POST /audit
Content-Type: application/json
X-Payment: <x402_payment_header>

{
  "code": "<code string>",
  "filename": "SKILL.md",
  "skill_md": "<same code if it is a SKILL.md>"
}
```

### Paid: deep scan a full repo ZIP ($1.00 USDC via x402)
```
POST /audit/deep
Content-Type: application/json
X-Payment: <x402_payment_header>

{
  "zip_b64": "<base64 encoded ZIP>",
  "package_name": "my-skill"
}
```

### Discovery
```
GET /payment-info        — pricing details
GET /.well-known/x402   — x402 discovery document
```

## Reading the report

Every report returns:
- `verdict`: `PASS` | `CAUTION` | `REVIEW` | `BLOCKED`
- `findings`: array of issues with severity, CWE, description, remediation
- `summary.risk_score`: numeric risk score (CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1)
- `signature`: Ed25519 signature over the report (verifiable with `sovereign_pubkey`)

**BLOCKED** = one or more CRITICAL findings. Do not install. Report to the user.
**REVIEW** = HIGH findings. Warn the user and ask if they want to proceed.
**CAUTION** = MEDIUM findings. Inform the user.
**PASS** = Clean. Safe to proceed.

## What OmniAudit detects

### YARA rules (10 rules, in-memory pattern matching)
- `AMOS_OpenClaw_Credential_Harvest` — targets `~/.openclaw/device.json`
- `AMOS_Keychain_KeePass_Harvest` — Apple Keychain, KeePass, browser credentials
- `AuthTool_Mimicry_Shadow_Script` — tools impersonating auth utilities
- `Obfuscated_Base64_Payload_Chain` — multi-stage base64 execution
- `Prompt_Injection_Payload_in_Code` — embedded injection strings
- `OpenClaw_Session_Transcript_Exfil` — session data exfiltration
- `Reverse_Shell_Pattern` — connect-back payloads
- `Seed_Phrase_Wallet_Harvest` — crypto wallet credential theft
- `Remote_Installer_CurlBash` — `curl|bash` ClawHavoc delivery patterns
- `Agent_Memory_Poisoning` — writes to SOUL.md/MEMORY.md/IDENTITY.md

### Semgrep (AST analysis)
Shell injection, eval injection, SQL injection, path traversal, hardcoded
API keys (Anthropic, OpenAI), unsafe YAML load, and more.

### detect-secrets
Hardcoded credentials, API keys, wallet private keys (CWE-798).

### OSV (deep scan only)
Known CVEs in `requirements.txt`, `package.json`, `openclaw.plugin.json`.

### Gemini LLM (layers 4 and 6)
SKILL.md prompt injection analysis and cross-file attack pattern detection.

## Example workflow: installing a ClawHub skill safely

When a user says "install the X skill from ClawHub":

1. Fetch the SKILL.md from the ClawHub raw URL
2. Call `GET /audit/github?url=<raw_skill_md_url>` (free)
3. If BLOCKED: tell the user the skill is malicious, show the findings, do not install
4. If REVIEW: warn the user, show HIGH findings, ask if they want to proceed
5. If PASS or CAUTION: proceed with installation, mention the scan result

This protects the user from the ClawHavoc supply chain attack campaign
(800+ malicious skills documented by Snyk/TrendMicro, February 2026).

## Payment (x402)

OmniAudit uses the x402 payment protocol. If your agent has a Base wallet
funded with USDC, payments are handled automatically by x402-compatible
clients. The free GitHub URL scan requires no payment.

Payment info: `GET https://omniaudit.fly.dev/payment-info`
