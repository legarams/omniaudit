# OmniAudit — AI Agent Supply-Chain Security Scanner

**Live demo:** [omniaudit.fly.dev](https://omniaudit.fly.dev)  
**Status:** Production-ready MVP, scanning agent skills across ClawHub and Agentverse.

OmniAudit is a security scanner built to prevent attacks like **ClawHavoc** (341 malicious skills that stole SSH keys from 300,000 users). It audits agent skills before they reach users or agent-to-agent payment networks.

## 🔍 Detection Layers

- **YARA** – Rule-based malware signature matching
- **Semgrep** – AST-level analysis for insecure code patterns (eval, command injection)
- **Dependency auditing** – Checks third-party packages against CVE databases
- **LLM prompt-injection detection** – Uses Claude to flag instruction-hijacking attempts
- **Cross-file attack chaining** – Tracks suspicious flows across multiple files
- **Ed25519 cryptographic signing** – Tamper-proof audit reports
- **x402 micropayments** – Agent-to-agent payments on Base ($0.25–$1.00 per scan)

## 🚀 Quick Start (Local Development)

```bash
git clone https://github.com/legarams/omniaudit
cd omniaudit
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="sqlite:///./test.db"
export ANTHROPIC_API_KEY="your-key"
uvicorn src.main:app --reload
