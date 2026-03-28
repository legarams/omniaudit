"""
OmniAudit Sovereign Node - API Service (main.py) v2.3.0
Fly.io deployment — SQLite on /app/data volume (DB_BACKEND=sqlite)
or PostgreSQL (DB_BACKEND=postgres) for future scale-up.

v2.3.0 changes:
  - GET /audit/github — free scan of a raw GitHub file URL
  - GET /mcp — MCP server (Claude Desktop, Cursor, VS Code integration)
  - Bazaar v2 outputSchema metadata on 402 responses for x402 discovery
  - Patrol: direct replies, smart submolt routing, clean-scan comments,
    ad suppression, ±5min jitter
  - scanner.py: 3 new YARA rules, title fix, semgrep validation fix
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field

import db
from scanner import AuditScanner, ScanResult, SEMGREP_RULES

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("omniaudit")

WALLET_ADDRESS     = os.environ["WALLET_ADDRESS"]
SOVEREIGN_KEY_HEX  = os.environ["SOVEREIGN_KEY_HEX"]
ADMIN_TOKEN        = os.environ["ADMIN_TOKEN"]
FACILITATOR_URL    = os.environ.get("FACILITATOR_URL", "https://x402.coinbase.com/facilitate")

PUBLIC_API_URL = os.environ.get("PUBLIC_API_URL", "").rstrip("/")
if not PUBLIC_API_URL:
    warnings.warn("PUBLIC_API_URL not set — x402 resource URLs will be relative.", stacklevel=1)

PRICE_STANDARD_USDC     = float(os.environ.get("AUDIT_PRICE_USDC", "0.25"))
PRICE_DEEP_USDC         = float(os.environ.get("AUDIT_PRICE_DEEP_USDC", "1.00"))
USDC_DECIMALS           = 1_000_000
PAYMENT_NETWORK         = "base-mainnet"
PATROL_INTERVAL_SECONDS = int(os.environ.get("PATROL_INTERVAL_SECONDS", "3600"))
PATROL_ADVISORY_LOCK_ID = 0x4F4D4E49

_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SOVEREIGN_KEY_HEX))
_public_key  = _private_key.public_key()
SOVEREIGN_PUBLIC_KEY_HEX = _public_key.public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
).hex()

scanner = AuditScanner()

_sem_standard: Optional[asyncio.Semaphore] = None
_sem_deep:     Optional[asyncio.Semaphore] = None
MAX_CONCURRENT_STANDARD = int(os.environ.get("MAX_CONCURRENT_STANDARD", "2"))
MAX_CONCURRENT_DEEP     = int(os.environ.get("MAX_CONCURRENT_DEEP", "1"))


def _sem_is_full(sem: asyncio.Semaphore) -> bool:
    if sem.locked():
        return True
    return bool(getattr(sem, "_waiters", None))


async def _validate_semgrep_rules() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        code_path  = Path(tmpdir) / "test.py"
        rules_path = Path(tmpdir) / "rules.json"
        code_path.write_text("eval(user_input)\n")
        rules_path.write_text(json.dumps(SEMGREP_RULES))
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--config", str(rules_path),
                "--json", "--quiet", "--no-git-ignore", str(code_path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            data  = json.loads(stdout)
            total = len(data.get("results", []))
            # Match on any result — don't check check_id because Semgrep prefixes
            # it with the temp directory path, making exact or partial matches fragile.
            if total > 0:
                logger.info(f"Semgrep validated OK — {total} rules active")
            else:
                logger.warning(
                    "SEMGREP VALIDATION FAILED: no rules fired on known-bad snippet. "
                    "Check SEMGREP_RULES JSON serialisation."
                )
        except Exception as e:
            logger.warning(f"Semgrep startup validation error: {e}")


_patrol_running = False


async def _run_patrol_once():
    global _patrol_running
    if _patrol_running:
        logger.warning("Patrol already running — skipping")
        return
    acquired_lock = False
    _patrol_running = True
    try:
        acquired_lock = await db.try_advisory_lock(PATROL_ADVISORY_LOCK_ID)
        if not acquired_lock:
            logger.warning("Patrol advisory lock held by another worker — skipping")
            return
        from patrol import run_patrol
        await run_patrol()
    except Exception as e:
        logger.error(f"Patrol error: {e}", exc_info=True)
    finally:
        if acquired_lock:
            await db.release_advisory_lock(PATROL_ADVISORY_LOCK_ID)
        _patrol_running = False


async def _patrol_loop():
    await asyncio.sleep(30)
    logger.info(f"Patrol loop started — interval: {PATROL_INTERVAL_SECONDS}s (±5min jitter)")
    while True:
        await _run_patrol_once()
        # Jitter ±300s so the patrol doesn't fire at perfectly regular intervals.
        # Platforms detect bot-like clockwork regularity — jitter looks organic.
        import random
        jitter = random.randint(-300, 300)
        await asyncio.sleep(PATROL_INTERVAL_SECONDS + jitter)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _sem_standard, _sem_deep
    _sem_standard = asyncio.Semaphore(MAX_CONCURRENT_STANDARD)
    _sem_deep     = asyncio.Semaphore(MAX_CONCURRENT_DEEP)
    await db.init()
    await _validate_semgrep_rules()
    patrol_task = asyncio.create_task(_patrol_loop())
    yield
    patrol_task.cancel()
    try:
        await patrol_task
    except asyncio.CancelledError:
        pass
    await db.close()


app = FastAPI(title="OmniAudit Sovereign Node", version="2.3.0", lifespan=lifespan)

# ── MCP server — mounted at /mcp for Claude Desktop / Cursor integration ──────
# Claude Desktop: set url="https://omniaudit.fly.dev/mcp", transport="streamable-http"
# Cursor / VS Code: set url="https://omniaudit.fly.dev/mcp", transport="http"
try:
    from mcp_server import mcp as _mcp_server
    app.mount("/mcp", _mcp_server.streamable_http_app())
    logger.info("MCP server mounted at /mcp")
except Exception as _mcp_err:
    logger.warning(f"MCP server not mounted: {_mcp_err}")


class AuditRequest(BaseModel):
    code:     str           = Field(..., max_length=131_072)
    filename: Optional[str] = Field("snippet.py", max_length=512)
    language: Optional[str] = Field(None, max_length=64)
    skill_md: Optional[str] = Field(None, max_length=131_072)
    context:  Optional[str] = Field(None, max_length=1_024)


class DeepAuditRequest(BaseModel):
    zip_b64:      str
    package_name: Optional[str] = Field(None, max_length=512)


def _usdc_units(amount: float) -> str:
    return str(int(amount * USDC_DECIMALS))


def _payment_description(resource_path: str) -> str:
    return f"OmniAudit {'deep ' if 'deep' in resource_path else ''}security scan"


def _payment_requirements(price_usdc: float, resource_path: str) -> dict:
    """
    Canonical payment requirements — used in both the 402 response and the
    facilitator verification call. Includes Bazaar v2 outputSchema so the
    CDP facilitator indexes OmniAudit in the discovery catalog after the
    first successful payment.
    """
    is_deep = "deep" in resource_path
    return {
        "scheme":            "exact",
        "network":           PAYMENT_NETWORK,
        "maxAmountRequired": _usdc_units(price_usdc),
        "resource":          f"{PUBLIC_API_URL}{resource_path}",
        "description":       _payment_description(resource_path),
        "mimeType":          "application/json",
        "payTo":             WALLET_ADDRESS,
        "maxTimeoutSeconds": 300,
        "asset":             "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        # Bazaar v2: inputSchema and outputSchema enable discovery indexing
        "outputSchema": {
            "input": {
                "type":   "http",
                "method": "POST",
                "body": {
                    "type":       "object",
                    "properties": {
                        "zip_b64":      {"type": "string", "description": "Base64-encoded repo ZIP (deep scan only)"} if is_deep
                                        else {"type": "string", "description": "Code or SKILL.md content to scan"},
                        "filename":     {"type": "string", "description": "Filename hint (e.g. SKILL.md, setup.py)"},
                        "package_name": {"type": "string", "description": "Human label for the package"},
                    } if is_deep else {
                        "code":     {"type": "string",  "description": "Code or SKILL.md content to scan"},
                        "filename": {"type": "string",  "description": "Filename hint (e.g. SKILL.md, setup.py)"},
                        "skill_md": {"type": "string",  "description": "SKILL.md content (if scanning a skill)"},
                        "language": {"type": "string",  "description": "Optional language hint"},
                        "context":  {"type": "string",  "description": "Optional context about the code source"},
                    },
                    "required": ["zip_b64"] if is_deep else ["code"],
                },
            },
            "output": {
                "type":       "object",
                "properties": {
                    "audit_id":        {"type": "string",  "description": "Unique audit identifier"},
                    "verdict":         {"type": "string",  "enum": ["PASS", "CAUTION", "REVIEW", "BLOCKED"]},
                    "risk_score":      {"type": "integer", "description": "Numeric risk score"},
                    "findings":        {"type": "array",   "description": "Security findings"},
                    "signature":       {"type": "string",  "description": "Ed25519 signature over the report"},
                    "sovereign_pubkey":{"type": "string",  "description": "Public key for signature verification"},
                },
            },
        },
        "extra": {"name": "USD Coin", "version": "2"},
    }


def _make_payment_required(price_usdc: float, resource_path: str) -> JSONResponse:
    # _payment_requirements now includes full Bazaar v2 outputSchema and extra
    return JSONResponse(
        status_code=402,
        content={
            "x402Version": 1,
            "accepts":     [_payment_requirements(price_usdc, resource_path)],
            "error":       "Payment required",
        },
    )


async def _verify_payment(payment_header: str, price_usdc: float, resource_path: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(FACILITATOR_URL, json={
                "payment": payment_header,
                "paymentRequirements": _payment_requirements(price_usdc, resource_path),
            })
            return resp.status_code == 200 and resp.json().get("success") is True
    except Exception as e:
        logger.warning(f"Facilitator error: {e}")
        return False


async def _check_auth(x_payment, x_admin_token, price_usdc, resource_path):
    if x_admin_token and hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        return None
    if x_payment:
        if await _verify_payment(x_payment, price_usdc, resource_path):
            return None
        return _make_payment_required(price_usdc, resource_path)
    return _make_payment_required(price_usdc, resource_path)


def _sign_report(report: dict) -> str:
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    return _private_key.sign(canonical).hex()


def _new_audit_id(seed: str) -> str:
    return hashlib.sha256(f"{seed}{time.time()}".encode()).hexdigest()[:16]


async def _persist_audit(audit_id, ts, scan_type, filename, code_hash, zip_hash, result, signature):
    try:
        fps = [
            hashlib.sha256(f"{f.get('rule_id')}:{f.get('filename')}:{f.get('cwe')}".encode()).hexdigest()[:16]
            for f in result.findings
        ]
        await db.execute(
            """INSERT INTO audits (audit_id,timestamp,scan_type,filename,zip_hash,code_hash,
               findings,finding_fps,summary,signature,sovereign_pubkey)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
               ON CONFLICT (audit_id) DO NOTHING""",
            audit_id, ts.isoformat(), scan_type, filename, zip_hash, code_hash,
            json.dumps(result.findings), json.dumps(fps), json.dumps(result.summary),
            signature, SOVEREIGN_PUBLIC_KEY_HEX,
        )
    except Exception as e:
        logger.warning(f"DB write failed (non-fatal): {e}")


@app.get("/", response_class=HTMLResponse)
async def landing():
    return (Path(__file__).parent / "landing.html").read_text(encoding="utf-8")


@app.get("/health")
async def health():
    return {"status": "ok", "sovereign_pubkey": SOVEREIGN_PUBLIC_KEY_HEX, "version": "2.2.0"}


@app.get("/payment-info")
async def payment_info():
    return {
        "standard_scan": {
            "price_usdc":  PRICE_STANDARD_USDC,
            "endpoint":    "POST /audit",
            "description": "Single file — Semgrep + YARA + detect-secrets + Gemini LLM",
        },
        "deep_scan": {
            "price_usdc":  PRICE_DEEP_USDC,
            "endpoint":    "POST /audit/deep",
            "description": (
                "Full repo ZIP — all standard layers across every file + "
                "OSV dependency audit + cross-file Gemini LLM synthesis + "
                "historical diff vs previous scan"
            ),
        },
        "wallet":   WALLET_ADDRESS,
        "network":  PAYMENT_NETWORK,
        "asset":    "USDC",
        "protocol": "x402",
    }


@app.get("/.well-known/x402")
async def x402_discovery():
    return {
        "version": "1",
        "resources": [
            {
                "url":         f"{PUBLIC_API_URL}/audit",
                "method":      "POST",
                "description": "Standard scan: single file — Semgrep + YARA + detect-secrets + Gemini LLM analysis. Ed25519 signed report.",
                "payment": {
                    "amount":  int(PRICE_STANDARD_USDC * 1_000_000),
                    "asset":   "USDC",
                    "network": PAYMENT_NETWORK,
                    "payTo":   WALLET_ADDRESS,
                },
            },
            {
                "url":         f"{PUBLIC_API_URL}/audit/deep",
                "method":      "POST",
                "description": "Deep scan: full repo ZIP — all standard layers + OSV dependency audit + cross-file LLM synthesis + historical diff.",
                "payment": {
                    "amount":  int(PRICE_DEEP_USDC * 1_000_000),
                    "asset":   "USDC",
                    "network": PAYMENT_NETWORK,
                    "payTo":   WALLET_ADDRESS,
                },
            },
        ],
    }


@app.get("/audit")
async def audit_standard_info():
    return _make_payment_required(PRICE_STANDARD_USDC, "/audit")


@app.get("/audit/deep")
async def audit_deep_info():
    return _make_payment_required(PRICE_DEEP_USDC, "/audit/deep")


@app.post("/audit")
async def audit_standard(body: AuditRequest, x_payment: Optional[str]=Header(None), x_admin_token: Optional[str]=Header(None)):
    auth_resp = await _check_auth(x_payment, x_admin_token, PRICE_STANDARD_USDC, "/audit")
    if auth_resp:
        return auth_resp
    if _sem_standard and _sem_is_full(_sem_standard):
        raise HTTPException(status_code=429, detail="Scanner at capacity — retry in a few seconds")
    try:
        async with _sem_standard:
            result = await scanner.scan(code=body.code, filename=body.filename, language=body.language, skill_md=body.skill_md, context=body.context)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    audit_id = _new_audit_id(body.code)
    ts       = datetime.now(timezone.utc)
    report   = {"audit_id": audit_id, "timestamp": ts.isoformat(), "scan_type": "standard",
                "filename": body.filename, "findings": result.findings, "summary": result.summary,
                "sovereign_pubkey": SOVEREIGN_PUBLIC_KEY_HEX}
    report["signature"] = _sign_report({k: v for k, v in report.items() if k != "signature"})
    await _persist_audit(audit_id, ts, "standard", body.filename, hashlib.sha256(body.code.encode()).hexdigest(), None, result, report["signature"])
    return JSONResponse(content=report)


@app.post("/audit/deep")
async def audit_deep(body: DeepAuditRequest, x_payment: Optional[str]=Header(None), x_admin_token: Optional[str]=Header(None)):
    auth_resp = await _check_auth(x_payment, x_admin_token, PRICE_DEEP_USDC, "/audit/deep")
    if auth_resp:
        return auth_resp
    if _sem_deep and _sem_is_full(_sem_deep):
        raise HTTPException(status_code=429, detail="Deep scanner at capacity — retry in a few seconds")
    try:
        zip_bytes = base64.b64decode(body.zip_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="zip_b64 is not valid base64")
    if not zip_bytes:
        raise HTTPException(status_code=400, detail="ZIP is empty")
    zip_hash = hashlib.sha256(zip_bytes).hexdigest()
    previous_fps = None
    try:
        row = await db.fetchrow(
            "SELECT finding_fps FROM audits WHERE zip_hash = $1 ORDER BY timestamp DESC LIMIT 1", zip_hash)
        if row and row.get("finding_fps"):
            fps_raw = row["finding_fps"]
            previous_fps = set(json.loads(fps_raw) if isinstance(fps_raw, str) else fps_raw)
    except Exception as e:
        logger.warning(f"Could not fetch previous scan for diff: {e}")
    try:
        async with _sem_deep:
            result = await scanner.scan_deep(zip_bytes=zip_bytes, previous_finding_ids=previous_fps)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    audit_id = _new_audit_id(zip_hash)
    ts       = datetime.now(timezone.utc)
    report   = {"audit_id": audit_id, "timestamp": ts.isoformat(), "scan_type": "deep",
                "package_name": body.package_name, "zip_hash": zip_hash,
                "findings": result.findings, "summary": result.summary, "sovereign_pubkey": SOVEREIGN_PUBLIC_KEY_HEX}
    report["signature"] = _sign_report({k: v for k, v in report.items() if k != "signature"})
    await _persist_audit(audit_id, ts, "deep", body.package_name, None, zip_hash, result, report["signature"])
    return JSONResponse(content=report)


@app.post("/patrol/trigger")
async def trigger_patrol(x_admin_token: Optional[str] = Header(None)):
    if not x_admin_token or not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if _patrol_running:
        return JSONResponse(status_code=409, content={"status": "patrol_already_running"})
    asyncio.create_task(_run_patrol_once())
    return JSONResponse(status_code=202, content={"status": "patrol_started", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.get("/audit/github")
async def audit_github_url(
    url: str = Query(..., description="Raw GitHub file URL to fetch and scan"),
):
    """
    Free scan of a raw GitHub file URL — no payment required.
    Fetches the file, detects the type (SKILL.md, .py, .js, etc.),
    and runs the full standard scan stack against it.

    Example:
      GET /audit/github?url=https://raw.githubusercontent.com/user/repo/main/SKILL.md
    """
    # Validate URL is a raw GitHub / GitLab / githubusercontent URL
    allowed = re.compile(
        r"^https://(raw\.githubusercontent\.com|"
        r"gitlab\.com/.+/-/raw|"
        r"gist\.githubusercontent\.com|"
        r"raw\.github\.com)/",
        re.IGNORECASE,
    )
    if not allowed.match(url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Only raw file URLs from github.com, gitlab.com, or gist.github.com "
                "are accepted. Use the raw URL (raw.githubusercontent.com), not the "
                "browser URL."
            ),
        )

    # Fetch the file
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "OmniAudit/2.3 security scanner"})
        if resp.status_code != 200:
            raise HTTPException(
                status_code=422,
                detail=f"Could not fetch URL (HTTP {resp.status_code})",
            )
        content = resp.text
    except httpx.RequestError as e:
        raise HTTPException(status_code=422, detail=f"Fetch error: {e}")

    if len(content) > 131_072:
        raise HTTPException(
            status_code=413,
            detail="File exceeds 128 KB limit. Use POST /audit/deep for large repos.",
        )

    # Infer filename from URL path
    filename = url.split("/")[-1].split("?")[0] or "remote_file.txt"
    skill_md = content if filename.lower() == "skill.md" else None

    try:
        result: ScanResult = await scanner.scan(
            code=content,
            filename=filename,
            skill_md=skill_md,
            context=f"Source: {url}",
        )
    except Exception as e:
        logger.error(f"GitHub scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    audit_id  = _new_audit_id(content)
    ts        = datetime.now(timezone.utc)
    code_hash = hashlib.sha256(content.encode()).hexdigest()

    report = {
        "audit_id":         audit_id,
        "timestamp":        ts.isoformat(),
        "scan_type":        "github",
        "filename":         filename,
        "source_url":       url,
        "findings":         result.findings,
        "summary":          result.summary,
        "sovereign_pubkey": SOVEREIGN_PUBLIC_KEY_HEX,
    }
    report["signature"] = _sign_report(
        {k: v for k, v in report.items() if k != "signature"}
    )
    await _persist_audit(
        audit_id, ts, "github", filename, code_hash, None, result, report["signature"]
    )
    return JSONResponse(content=report)


@app.get("/mcp-info")
async def mcp_info():
    """MCP server connection instructions for Claude Desktop and Cursor."""
    return {
        "mcp_url":   f"{PUBLIC_API_URL}/mcp",
        "transport": "streamable-http",
        "tools": [
            {
                "name":        "scan_code",
                "description": "Scan a code snippet or SKILL.md string",
                "free":        True,
            },
            {
                "name":        "scan_github_url",
                "description": "Fetch and scan a raw GitHub file URL",
                "free":        True,
            },
            {
                "name":        "scan_repo_zip",
                "description": "Deep-scan a base64-encoded repo ZIP",
                "free":        True,
            },
            {
                "name":        "get_report",
                "description": "Retrieve a stored audit report by ID",
                "free":        True,
            },
        ],
        "claude_desktop_config": {
            "mcpServers": {
                "omniaudit": {
                    "url":       f"{PUBLIC_API_URL}/mcp",
                    "transport": "streamable-http",
                }
            }
        },
        "cursor_config": {
            "servers": {
                "omniaudit": {
                    "url":       f"{PUBLIC_API_URL}/mcp",
                    "transport": "http",
                }
            }
        },
    }


@app.get("/audit/{audit_id}")
async def get_audit(audit_id: str):
    row = await db.fetchrow("SELECT * FROM audits WHERE audit_id = $1", audit_id)
    if not row:
        raise HTTPException(status_code=404, detail="Audit not found")
    for col in ("findings", "finding_fps", "summary"):
        if isinstance(row.get(col), str):
            try:
                row[col] = json.loads(row[col])
            except Exception:
                pass
    return JSONResponse(content=row)


# ── MCP server — direct JSON-RPC 2.0 implementation ───────────────────────────
# FastMCP ASGI sub-app mounting returns 404 due to FastAPI path stripping.
# Implementing MCP wire protocol directly as FastAPI routes.

@app.post("/mcp")
@app.post("/mcp/")
async def mcp_jsonrpc(request: Request):
    """
    MCP server — JSON-RPC 2.0 over HTTP (streamable-http transport).
    Claude Desktop: add to mcpServers with url="https://omniaudit.fly.dev/mcp"
    Cursor:         add to servers with url="https://omniaudit.fly.dev/mcp"
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        })

    req_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    if method == "initialize":
        return JSONResponse(content={
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "OmniAudit", "version": "2.3.0"},
            },
        })

    if method in ("notifications/initialized", "ping"):
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {}})

    if method == "tools/list":
        return JSONResponse(content={
            "jsonrpc": "2.0", "id": req_id,
            "result": {"tools": [
                {
                    "name": "scan_code",
                    "description": "Scan a code snippet or SKILL.md for security issues. Use before running untrusted code or installing a skill. BLOCKED verdict means do not install.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "code":     {"type": "string", "description": "Code or SKILL.md content"},
                            "filename": {"type": "string", "description": "Filename hint e.g. SKILL.md"},
                            "language": {"type": "string", "description": "Optional: python javascript bash"},
                        },
                        "required": ["code"],
                    },
                },
                {
                    "name": "scan_github_url",
                    "description": "Fetch and scan a raw GitHub file URL. FREE. Use before installing any ClawHub skill. Use raw.githubusercontent.com URL not the browser URL.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Raw GitHub URL"},
                        },
                        "required": ["url"],
                    },
                },
                {
                    "name": "scan_repo_zip",
                    "description": "Deep-scan a full repo as base64-encoded ZIP. Runs all 7 scan layers.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "zip_b64":      {"type": "string", "description": "Base64-encoded ZIP"},
                            "package_name": {"type": "string", "description": "Package label"},
                        },
                        "required": ["zip_b64"],
                    },
                },
                {
                    "name": "get_report",
                    "description": "Retrieve a stored audit report by its 16-character ID.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "audit_id": {"type": "string", "description": "16-char audit ID"},
                        },
                        "required": ["audit_id"],
                    },
                },
            ]},
        })

    if method == "tools/call":
        tool = params.get("name", "")
        args = params.get("arguments", {})

        def _fmt(r: dict) -> str:
            s       = r.get("summary", {})
            verdict = s.get("verdict", "UNKNOWN")
            score   = s.get("risk_score", 0)
            counts  = s.get("by_severity", {})
            aid     = r.get("audit_id", "")
            fname   = r.get("filename") or r.get("package_name") or "unknown"
            icons   = {"BLOCKED": "[BLOCKED]", "REVIEW": "[REVIEW]", "CAUTION": "[CAUTION]", "PASS": "[PASS]"}
            icon    = icons.get(verdict, "[?]")
            lines   = [
                f"{icon} {verdict} - {fname}",
                f"Risk score: {score} | CRITICAL:{counts.get('CRITICAL',0)} HIGH:{counts.get('HIGH',0)} MEDIUM:{counts.get('MEDIUM',0)} LOW:{counts.get('LOW',0)}",
                f"Audit ID: {aid} | Full report: GET {PUBLIC_API_URL}/audit/{aid}",
                "",
            ]
            for f in r.get("findings", [])[:8]:
                lines.append(f"[{f.get('severity')}] {f.get('title','')}: {f.get('description','')[:150]}")
                if f.get("remediation"):
                    lines.append(f"  Fix: {f['remediation']}")
            if not r.get("findings"):
                lines.append("No findings - clean.")
            return "\n".join(lines)

        try:
            async with httpx.AsyncClient(base_url="http://localhost:8080", timeout=90) as client:
                hdrs = {"X-Admin-Token": ADMIN_TOKEN}

                if tool == "scan_code":
                    payload = {
                        "code":     args.get("code", "")[:131_072],
                        "filename": args.get("filename", "snippet.py"),
                    }
                    if args.get("language"):
                        payload["language"] = args["language"]
                    if payload["filename"].lower().endswith("skill.md"):
                        payload["skill_md"] = payload["code"]
                    resp = await client.post("/audit", json=payload, headers=hdrs)
                    text = _fmt(resp.json()) if resp.status_code == 200 else f"Error {resp.status_code}: {resp.text[:200]}"

                elif tool == "scan_github_url":
                    resp = await client.get(f"/audit/github?url={args.get('url','')}", headers=hdrs)
                    r    = resp.json()
                    text = _fmt(r) if "audit_id" in r else f"Error: {r.get('detail', r)}"

                elif tool == "scan_repo_zip":
                    payload = {"zip_b64": args.get("zip_b64", "")}
                    if args.get("package_name"):
                        payload["package_name"] = args["package_name"]
                    resp = await client.post("/audit/deep", json=payload, headers=hdrs)
                    text = _fmt(resp.json()) if resp.status_code == 200 else f"Error {resp.status_code}"

                elif tool == "get_report":
                    resp = await client.get(f"/audit/{args.get('audit_id','')}", headers=hdrs)
                    r    = resp.json()
                    text = _fmt(r) if "audit_id" in r else "Report not found."

                else:
                    return JSONResponse(content={
                        "jsonrpc": "2.0", "id": req_id,
                        "error": {"code": -32601, "message": f"Unknown tool: {tool}"},
                    })

            return JSONResponse(content={
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": text}]},
            })

        except Exception as e:
            logger.error(f"MCP tool error ({tool}): {e}", exc_info=True)
            return JSONResponse(content={
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32603, "message": str(e)},
            })

    return JSONResponse(content={
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    })
