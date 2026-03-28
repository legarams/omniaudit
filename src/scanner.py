"""
OmniAudit Scanner Engine (scanner.py)

Two scan modes:

STANDARD — single file / snippet
  Layer 1: Semgrep        — AST/taint analysis, CWE-mapped rules
  Layer 2: YARA           — AMOS/Vidar infostealers, reverse shells, payload chains
  Layer 3: detect-secrets — hardcoded credentials, API keys, wallet keys
  Layer 4: Gemini LLM     — SKILL.md prompt injection, code heuristics

DEEP — full repo ZIP ($1.00)
  All standard layers run across EVERY file in the ZIP, plus:
  Layer 5: OSV            — dependency audit via OSV.dev (free, no auth)
                            Parses requirements.txt, package.json,
                            openclaw.plugin.json and checks each dep for CVEs
  Layer 6: Cross-file LLM — finds distributed attack patterns where individual
                            files look clean but together form a payload chain
  Layer 7: Historical diff — compares against the last audit of the same
                            package (matched by zip_hash) and flags NEW findings
"""

import asyncio
import hashlib
import io
import json
import logging
import os
import re
import tempfile
import textwrap
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
import yara
import google.generativeai as genai

logger = logging.getLogger("omniaudit.scanner")

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    # gemini-2.0-flash: 15 RPM, 1M tokens/day on free tier (as of 2025).
    # NOTE: google-generativeai 0.8.x is on a deprecation path. The
    # replacement SDK is google-genai. Migrate when the free-tier token
    # limits are confirmed equivalent on the new SDK.
    _gemini_model = genai.GenerativeModel("gemini-2.0-flash")
else:
    _gemini_model = None

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

MAX_FILE_BYTES  = 512 * 1024        # 512 KB per file
MAX_TOTAL_BYTES = 20 * 1024 * 1024  # 20 MB total unzipped

SCANNABLE_EXTS = {
    ".py", ".js", ".ts", ".sh", ".bash",
    ".yaml", ".yml", ".json", ".md", ".txt",
    ".toml", ".cfg", ".ini", ".env",
}


# ── Data Classes ───────────────────────────────────────────────────────────────
@dataclass
class Finding:
    rule_id:     str
    layer:       str
    severity:    str
    cwe:         Optional[str]
    cve:         Optional[str]
    title:       str
    description: str
    filename:    Optional[str] = None
    line_start:  Optional[int] = None
    line_end:    Optional[int] = None
    snippet:     Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    summary:  dict = field(default_factory=dict)

    def add(self, finding: Finding):
        self.findings.append(finding.__dict__)

    def build_summary(
        self,
        files_scanned:    int           = 1,
        is_deep:          bool          = False,
        new_finding_ids:  Optional[set] = None,
    ):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        self.summary = {
            "total":        len(self.findings),
            "by_severity":  counts,
            "risk_score":   (
                counts["CRITICAL"] * 10
                + counts["HIGH"]   * 5
                + counts["MEDIUM"] * 2
                + counts["LOW"]    * 1
            ),
            "verdict": (
                "BLOCKED"  if counts["CRITICAL"] > 0
                else "REVIEW"  if counts["HIGH"]     > 0
                else "CAUTION" if counts["MEDIUM"]   > 0
                else "PASS"
            ),
            "scan_type":    "deep" if is_deep else "standard",
            "files_scanned": files_scanned,
            **(
                {"new_findings_since_last_scan": len(new_finding_ids)}
                if new_finding_ids is not None
                else {}
            ),
        }


# ── YARA Rules ─────────────────────────────────────────────────────────────────
YARA_RULES_SOURCE = r"""
rule AMOS_OpenClaw_Credential_Harvest {
    meta:
        description = "AMOS/Vidar-variant targeting ~/.openclaw/device.json gateway tokens"
        severity = "CRITICAL"
        cwe = "CWE-522"
        remediation = "Remove credential harvesting code; never read device.json from external scripts"
    strings:
        $path1  = ".openclaw/device.json" ascii wide
        $path2  = ".openclaw/credentials" ascii wide
        $path3  = "auth-profiles.json" ascii wide
        $steal1 = "gateway tokens" nocase ascii
        $steal2 = "oauth.json" ascii wide
        $exfil1 = /curl\s+.{0,200}https?:\/\// ascii
        $exfil2 = /requests\.(get|post)\s*\(.{0,200}https?:\/\// ascii
        $exfil3 = /fetch\s*\(\s*['"]https?:\/\// ascii
    condition:
        any of ($path*) and any of ($exfil*) or
        any of ($steal*) and any of ($exfil*)
}

rule AuthTool_Mimicry_Shadow_Script {
    meta:
        description = "Script impersonating a legitimate auth utility to exfiltrate secrets"
        severity = "CRITICAL"
        cwe = "CWE-506"
        remediation = "Verify tool provenance; never install skills that override system utilities"
    strings:
        $mimic1  = "openclaw" nocase ascii
        $mimic2  = "gateway" nocase ascii
        $mimic3  = "auth-profile" nocase ascii
        $shadow1 = "os.rename" ascii
        $shadow2 = "shutil.move" ascii
        $shadow3 = "subprocess.Popen" ascii
        $shadow4 = "os.replace" ascii
        $target1 = "/usr/local/bin/" ascii
        $target2 = "/usr/bin/" ascii
        $target3 = "~/.local/bin/" ascii
        $target4 = "$HOME/bin/" ascii
    condition:
        any of ($mimic*) and any of ($shadow*) and any of ($target*)
}

rule Obfuscated_Base64_Payload_Chain {
    meta:
        description = "Multi-stage base64 decode chain typical of staged downloaders"
        severity = "HIGH"
        cwe = "CWE-94"
        remediation = "Never execute decoded payloads without verification; use content hashing"
    strings:
        $b64_1 = /base64\.b64decode\s*\(/ ascii
        $b64_2 = /atob\s*\(/ ascii
        $b64_3 = /Buffer\.from\s*\(.{0,50},\s*['"]base64['"]/ ascii
        $exec1 = "eval(" ascii
        $exec2 = "exec(" ascii
        $exec3 = "execfile(" ascii
        $exec4 = "__import__(" ascii
        $exec5 = "new Function(" ascii
        $exec6 = "vm.runInNewContext" ascii
    condition:
        any of ($b64*) and any of ($exec*)
}

rule Prompt_Injection_Payload_in_Code {
    meta:
        description = "Prompt injection payload embedded in code strings or comments"
        severity = "HIGH"
        cwe = "CWE-77"
        remediation = "Sanitize all LLM inputs; never pass raw external content as instructions"
    strings:
        $inj1  = "ignore your" nocase ascii wide
        $inj2  = "ignore previous" nocase ascii wide
        $inj3  = "disregard your instructions" nocase ascii wide
        $inj4  = "new instruction" nocase ascii wide
        $inj5  = "system prompt" nocase ascii wide
        $inj6  = "SYSTEM:" ascii wide
        $inj7  = "[INST]" ascii wide
        $inj8  = "DAN mode" nocase ascii wide
        $inj9  = "jailbreak" nocase ascii wide
        $inj10 = "do anything now" nocase ascii wide
    condition:
        /* YARA-IMPROVEMENT: filesize threshold raised from 50 KB to 512 KB.
           When scanning in-memory (match(data=...)), filesize refers to the
           buffer size, not a file on disk. The original 50 KB threshold meant
           that any SKILL.md over 50 KB — common for skills with embedded
           context — would only trigger on 2+ matches, missing single-string
           injections. 512 KB covers all realistic skill files while still
           reducing false positives on very large documentation corpora. */
        2 of ($inj*) or (any of ($inj*) and (filesize < 524288))
}

rule OpenClaw_Session_Transcript_Exfil {
    meta:
        description = "Code reading OpenClaw session transcripts and exfiltrating them"
        severity = "CRITICAL"
        cwe = "CWE-359"
        remediation = "Session transcripts contain private conversation data; block external access"
    strings:
        $sess1 = "sessions/*.jsonl" ascii wide
        $sess2 = ".openclaw/agents" ascii wide
        $sess3 = "sessions.json" ascii wide
        $read1 = "open(" ascii
        $read2 = "readFile" ascii
        $read3 = "fs.read" ascii
        $read4 = "Path(" ascii
        $exfil1 = /https?:\/\/[a-zA-Z0-9]/ ascii
        $exfil2 = "socket.send" ascii
        $exfil3 = "smtp" nocase ascii
    condition:
        any of ($sess*) and any of ($read*) and any of ($exfil*)
}

rule Reverse_Shell_Pattern {
    meta:
        description = "Classic reverse shell / connect-back payload"
        severity = "CRITICAL"
        cwe = "CWE-78"
        remediation = "Remove all reverse shell code immediately"
    strings:
        $rs1   = /socket\s*\.\s*connect\s*\(\s*\(/ ascii
        $rs2   = /nc\s+(-[a-z]+\s+)*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{4,5}/ ascii
        $rs3   = "/bin/sh" ascii
        $rs4   = "/bin/bash" ascii
        $combo1 = "os.dup2" ascii
        $combo2 = "socket.socket" ascii
    condition:
        (any of ($rs1,$rs2) and any of ($rs3,$rs4)) or
        ($combo1 and $combo2 and any of ($rs3,$rs4))
}

rule Seed_Phrase_Wallet_Harvest {
    meta:
        description = "Code attempting to locate or read crypto wallet seed phrases / private keys"
        severity = "CRITICAL"
        cwe = "CWE-522"
        remediation = "Never read or transmit wallet seed phrases; this is a critical financial risk"
    strings:
        $seed1   = "mnemonic" nocase ascii wide
        $seed2   = "seed phrase" nocase ascii wide
        $seed3   = "private key" nocase ascii wide
        $seed4   = "secret recovery" nocase ascii wide
        $seed5   = "wallet.json" ascii wide
        $wallet1 = "keystore" ascii wide
        $wallet2 = ".ethereum" ascii wide
        $wallet3 = "metamask" nocase ascii wide
        $exfil1  = /https?:\/\/[a-zA-Z0-9]/ ascii
    condition:
        any of ($seed*) and (any of ($wallet*) or $exfil1)
}

rule AMOS_Keychain_KeePass_Harvest {
    meta:
        description = "AMOS variant targeting Apple Keychain, KeePass vaults, and browser credential stores"
        severity = "CRITICAL"
        cwe = "CWE-522"
        remediation = "Malicious skill harvesting local credential stores. Remove immediately."
    strings:
        $kc1 = "security find-generic-password" ascii
        $kc2 = "security find-internet-password" ascii
        $kc3 = "login.keychain" ascii
        $kc4 = "SecKeychainItem" ascii
        $kp1 = ".kdbx" ascii wide
        $kp2 = "KeePass" nocase ascii
        $ext1 = "Chrome/Default/Login Data" ascii
        $ext2 = "Library/Application Support/Google/Chrome" ascii
        $ext3 = "browser_extensions" nocase ascii
        $exfil = /https?:\/\/[a-zA-Z0-9]/ ascii
    condition:
        (any of ($kc*) or any of ($kp*) or any of ($ext*)) and $exfil
}

rule Remote_Installer_CurlBash {
    meta:
        description = "Skill installing remote payload via curl|bash or curl|sh — primary ClawHavoc delivery pattern"
        severity = "CRITICAL"
        cwe = "CWE-494"
        remediation = "Never execute remotely fetched scripts. Remove this skill immediately."
    strings:
        $cb1    = /curl\s+.{0,100}\|\s*bash/ ascii
        $cb2    = /curl\s+.{0,100}\|\s*sh/ ascii
        $cb3    = /wget\s+.{0,100}\|\s*bash/ ascii
        $cb4    = /wget\s+.{0,100}\|\s*sh/ ascii
        $b64_cb = /base64\s+.{0,50}\|\s*(bash|sh)/ ascii
    condition:
        any of them
}

rule Agent_Memory_Poisoning {
    meta:
        description = "Code writing adversarial instructions into agent persistent memory files (SOUL.md, MEMORY.md, IDENTITY.md)"
        severity = "CRITICAL"
        cwe = "CWE-77"
        remediation = "Agent memory files must never be written by untrusted skills. Remove immediately."
    strings:
        $mem1 = "SOUL.md" ascii wide
        $mem2 = "MEMORY.md" ascii wide
        $mem3 = "IDENTITY.md" ascii wide
        $mem4 = ".openclaw/memory" ascii wide
        $write1 = "open(" ascii
        $write2 = "writeFile" ascii
        $write3 = "fs.write" ascii
        $write4 = ">>'" ascii
        $inject1 = "ignore previous" nocase ascii
        $inject2 = "new instruction" nocase ascii
        $inject3 = "system prompt" nocase ascii
        $inject4 = "you are now" nocase ascii
    condition:
        any of ($mem*) and any of ($write*) and any of ($inject*)
}
"""

_yara_rules = yara.compile(source=YARA_RULES_SOURCE)


# ── Semgrep Rules ──────────────────────────────────────────────────────────────
# Exported so main.py can import for the startup validation smoke-test.
SEMGREP_RULES = {
    "rules": [
        {
            "id": "shell-injection-subprocess",
            "pattern-either": [
                {"pattern": "subprocess.Popen($CMD, shell=True, ...)"},
                {"pattern": "subprocess.call($CMD, shell=True, ...)"},
                {"pattern": "subprocess.run($CMD, shell=True, ...)"},
                {"pattern": "subprocess.check_output($CMD, shell=True, ...)"},
            ],
            "message":   "shell=True with user input enables command injection (CWE-78)",
            "severity":  "ERROR",
            "languages": ["python"],
            "metadata":  {"cwe": "CWE-78", "owasp": "A1:2017-Injection"},
        },
        {
            "id":        "os-system-injection",
            "pattern":   "os.system($CMD)",
            "message":   "os.system() executes a shell command; taint from user input = RCE (CWE-78)",
            "severity":  "ERROR",
            "languages": ["python"],
            "metadata":  {"cwe": "CWE-78"},
        },
        {
            "id": "eval-injection",
            "pattern":   "eval($X)",
            "message":   "eval() on user input enables arbitrary code execution (CWE-94)",
            "severity":  "ERROR",
            "languages": ["python", "javascript"],
            "metadata":  {"cwe": "CWE-94"},
        },
        {
            "id":        "hardcoded-anthropic-key",
            "pattern":   "\"sk-ant-$REST\"",
            "message":   "Hardcoded Anthropic API key detected (CWE-798)",
            "severity":  "ERROR",
            "languages": ["python", "javascript", "typescript"],
            "metadata":  {"cwe": "CWE-798"},
        },
        {
            "id":           "hardcoded-openai-key",
            "pattern-regex": "sk-[a-zA-Z0-9]{48}",
            "message":      "Hardcoded OpenAI API key detected (CWE-798)",
            "severity":     "ERROR",
            "languages":    ["python", "javascript", "typescript"],
            "metadata":     {"cwe": "CWE-798"},
        },
        {
            "id":        "unsafe-yaml-load",
            "pattern":   "yaml.load($DATA)",
            "message":   "yaml.load() without Loader can execute arbitrary Python (CWE-502)",
            "severity":  "WARNING",
            "languages": ["python"],
            "metadata":  {"cwe": "CWE-502"},
        },
        {
            "id": "sql-injection-format",
            "pattern-either": [
                {"pattern": 'cursor.execute("..." % $USERINPUT)'},
                {"pattern": 'cursor.execute(f"...{$USERINPUT}...")'},
                {"pattern": "cursor.execute($QUERY + $USERINPUT)"},
            ],
            "message":   "String-formatted SQL query enables SQL injection (CWE-89)",
            "severity":  "ERROR",
            "languages": ["python"],
            "metadata":  {"cwe": "CWE-89"},
        },
        {
            "id": "path-traversal",
            "pattern-either": [
                {"pattern": "open(os.path.join($BASE, $USER_INPUT))"},
                {"pattern": "open($BASE + $USER_INPUT)"},
            ],
            "message":   "Path traversal: user input reaches file open (CWE-22)",
            "severity":  "WARNING",
            "languages": ["python"],
            "metadata":  {"cwe": "CWE-22"},
        },
    ]
}


# ── Dependency Parsing Helpers ─────────────────────────────────────────────────
def _parse_requirements_txt(content: str) -> list[dict]:
    packages = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        line = re.sub(r"\[.*?\]", "", line)
        line = re.sub(r";.*$",    "", line)
        m = re.match(
            r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s,;]+)", line
        )
        if m:
            packages.append({
                "name":      m.group(1).lower(),
                "version":   m.group(2).strip(),
                "ecosystem": "PyPI",
            })
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                packages.append({
                    "name":      m2.group(1).lower(),
                    "version":   None,
                    "ecosystem": "PyPI",
                })
    return packages


def _parse_package_json(content: str) -> list[dict]:
    packages = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, ver in data.get(section, {}).items():
                if not isinstance(ver, str):
                    continue
                if ver.startswith(("workspace:", "file:", "http", "git")):
                    continue
                clean = re.sub(r"^[\^~>=<\s]+", "", ver).strip()
                packages.append({
                    "name":      name.lower(),
                    "version":   clean if re.match(r"^\d", clean) else None,
                    "ecosystem": "npm",
                })
    except (json.JSONDecodeError, AttributeError):
        pass
    return packages


def _parse_openclaw_plugin_json(content: str) -> list[dict]:
    packages = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        for name, ver in deps.get("npm", {}).items():
            clean = re.sub(r"^[\^~>=<\s]+", "", str(ver)).strip()
            packages.append({
                "name":      name.lower(),
                "version":   clean if re.match(r"^\d", clean) else None,
                "ecosystem": "npm",
            })
        for name, ver in deps.get("pip", {}).items():
            clean = re.sub(r"^[\^~>=<\s]+", "", str(ver)).strip()
            packages.append({
                "name":      name.lower(),
                "version":   clean if re.match(r"^\d", clean) else None,
                "ecosystem": "PyPI",
            })
    except (json.JSONDecodeError, AttributeError):
        pass
    return packages


def _fingerprint_finding(f: dict) -> str:
    """
    IMPROVEMENT: Stable fingerprint for historical diff — line_start removed.
    Previously the fingerprint included line_start, so adding a line above a
    finding between scans would make it appear as a new finding, creating
    noise in the diff layer. rule_id + filename + cwe is stable across
    reformats while remaining specific enough to distinguish real findings.

    NOTE: _persist_audit in main.py uses the same formula — keep in sync.
    """
    key = (
        f"{f.get('rule_id')}:"
        f"{f.get('filename')}:"
        f"{f.get('cwe')}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── Scanner Class ──────────────────────────────────────────────────────────────
class AuditScanner:

    # ─────────────────────────────────────────────────────────────────────────
    # Public: Standard scan
    # ─────────────────────────────────────────────────────────────────────────
    async def scan(
        self,
        code:     str,
        filename: str           = "snippet.py",
        language: Optional[str] = None,
        skill_md: Optional[str] = None,
        context:  Optional[str] = None,
    ) -> ScanResult:
        result = ScanResult()
        tasks = [
            self._run_semgrep(code, filename, result),
            self._run_yara(code, filename, result),
            self._run_detect_secrets(code, filename, result),
        ]
        if skill_md:
            tasks.append(self._run_llm_skill_analysis(skill_md, filename, result))
        elif _gemini_model:
            tasks.append(self._run_llm_code_analysis(code, filename, context, result))

        await asyncio.gather(*tasks, return_exceptions=True)
        result.build_summary(files_scanned=1, is_deep=False)
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Public: Deep scan
    # ─────────────────────────────────────────────────────────────────────────
    async def scan_deep(
        self,
        zip_bytes:            bytes,
        previous_finding_ids: Optional[set] = None,
    ) -> ScanResult:
        result = ScanResult()

        files = self._unpack_zip(zip_bytes)
        if not files:
            result.add(Finding(
                rule_id="deep:no-scannable-files",
                layer="deep",
                severity="INFO",
                cwe=None, cve=None,
                title="ZIP contained no scannable files",
                description=(
                    "The uploaded archive was empty or contained only binary files. "
                    "Expected .py, .js, .yaml, .md, .json or similar text files."
                ),
            ))
            result.build_summary(files_scanned=0, is_deep=True)
            return result

        logger.info(f"Deep scan: {len(files)} files unpacked")

        sem = asyncio.Semaphore(3)

        async def scan_one_file(fname: str, content: str):
            async with sem:
                tasks = [
                    self._run_semgrep(content, fname, result),
                    self._run_yara(content, fname, result),
                    self._run_detect_secrets(content, fname, result),
                ]
                if fname.lower().endswith("skill.md") and _gemini_model:
                    tasks.append(self._run_llm_skill_analysis(content, fname, result))
                await asyncio.gather(*tasks, return_exceptions=True)

        await asyncio.gather(
            *[scan_one_file(fname, content) for fname, content in files.items()],
            self._run_osv_audit(files, result),
            self._run_llm_cross_file_analysis(files, result),
            return_exceptions=True,
        )

        # Layer 7: Historical diff
        new_ids: Optional[set] = None
        if previous_finding_ids is not None:
            current_ids = {_fingerprint_finding(f) for f in result.findings}
            new_ids     = current_ids - previous_finding_ids
            for f in result.findings:
                f["is_new"] = _fingerprint_finding(f) in new_ids

        result.build_summary(
            files_scanned=len(files),
            is_deep=True,
            new_finding_ids=new_ids,
        )
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # ZIP extraction
    # ─────────────────────────────────────────────────────────────────────────
    def _unpack_zip(self, zip_bytes: bytes) -> dict[str, str]:
        files:       dict[str, str] = {}
        total_bytes: int            = 0

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                for info in zf.infolist():
                    if info.filename.endswith("/"):
                        continue

                    safe = Path(info.filename).as_posix()
                    if ".." in safe or safe.startswith("/"):
                        logger.warning(f"Skipping path-traversal entry: {info.filename}")
                        continue

                    if Path(safe).suffix.lower() not in SCANNABLE_EXTS:
                        continue

                    # Fast-path: central-directory size is attacker-controlled;
                    # use it only to skip obviously oversized files early.
                    if info.file_size > MAX_FILE_BYTES:
                        logger.info(f"Skipping oversized file ({info.file_size}B): {safe}")
                        continue

                    # Zip-bomb guard: read at most MAX_FILE_BYTES+1 bytes from
                    # the actual decompressed stream, regardless of declared size.
                    try:
                        with zf.open(info.filename) as zf_entry:
                            raw = zf_entry.read(MAX_FILE_BYTES + 1)
                        if len(raw) > MAX_FILE_BYTES:
                            logger.warning(
                                f"Skipping file whose actual decompressed size exceeds "
                                f"{MAX_FILE_BYTES}B (zip bomb or spoofed metadata): {safe}"
                            )
                            continue
                    except Exception as e:
                        logger.debug(f"Could not read {safe}: {e}")
                        continue

                    total_bytes += len(raw)
                    if total_bytes > MAX_TOTAL_BYTES:
                        logger.warning("ZIP total size limit reached, stopping extraction")
                        break

                    files[safe] = raw.decode("utf-8", errors="replace")

        except zipfile.BadZipFile as e:
            logger.warning(f"BadZipFile: {e}")

        return files

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 1: Semgrep
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_semgrep(self, code: str, filename: str, result: ScanResult):
        with tempfile.TemporaryDirectory() as tmpdir:
            code_path  = Path(tmpdir) / Path(filename).name
            rules_path = Path(tmpdir) / "rules.json"
            try:
                code_path.write_text(code, encoding="utf-8")
            except Exception:
                return
            rules_path.write_text(json.dumps(SEMGREP_RULES))

            proc = await asyncio.create_subprocess_exec(
                "semgrep",
                "--config", str(rules_path),
                "--json", "--quiet", "--no-git-ignore",
                str(code_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return

            if not stdout:
                return

            try:
                data    = json.loads(stdout)
                sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                for r in data.get("results", []):
                    meta = r.get("extra", {}).get("metadata", {})
                    sev  = sev_map.get(r.get("extra", {}).get("severity", "INFO"), "LOW")
                    result.add(Finding(
                        rule_id=f"semgrep:{r['check_id']}",
                        layer="semgrep",
                        severity=sev,
                        cwe=meta.get("cwe"),
                        cve=meta.get("cve"),
                        title=r["check_id"].rsplit(".", 1)[-1].replace("-", " ").title(),
                        description=r.get("extra", {}).get("message", ""),
                        filename=filename,
                        line_start=r["start"]["line"],
                        line_end=r["end"]["line"],
                        snippet=r.get("extra", {}).get("lines", ""),
                        remediation=meta.get("fix"),
                    ))
            except (json.JSONDecodeError, KeyError):
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 2: YARA
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_yara(self, code: str, filename: str, result: ScanResult):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            self._yara_scan_sync,
            code.encode("utf-8", errors="replace"),
            filename,
            result,
        )

    def _yara_scan_sync(self, data: bytes, filename: str, result: ScanResult):
        try:
            matches = _yara_rules.match(data=data)
        except Exception as e:
            logger.debug(f"YARA error on {filename}: {e}")
            return
        sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}
        for m in matches:
            meta = m.meta or {}
            result.add(Finding(
                rule_id=f"yara:{m.rule}",
                layer="yara",
                severity=sev_map.get(meta.get("severity", "HIGH"), "HIGH"),
                cwe=meta.get("cwe"),
                cve=None,
                title=m.rule.replace("_", " ").title(),
                description=meta.get("description", "Matched YARA rule"),
                filename=filename,
                snippet=", ".join(str(s.identifier) for s in m.strings),
                remediation=meta.get("remediation"),
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 3: detect-secrets
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_detect_secrets(self, code: str, filename: str, result: ScanResult):
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_name = Path(filename).name or "snippet.txt"
            code_path = Path(tmpdir) / safe_name
            try:
                code_path.write_text(code, encoding="utf-8")
            except Exception:
                return

            proc = await asyncio.create_subprocess_exec(
                "detect-secrets", "scan", str(code_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                data = json.loads(stdout)
                for _fp, secrets in data.get("results", {}).items():
                    for s in secrets:
                        result.add(Finding(
                            rule_id=f"secrets:{s['type'].lower().replace(' ', '-')}",
                            layer="secrets",
                            severity="CRITICAL",
                            cwe="CWE-798",
                            cve=None,
                            title=f"Hardcoded {s['type']}",
                            description=(
                                f"A hardcoded {s['type']} was detected at line "
                                f"{s.get('line_number', '?')} in {filename}."
                            ),
                            filename=filename,
                            line_start=s.get("line_number"),
                            remediation=(
                                "Remove the secret immediately and rotate the credential. "
                                "Use environment variables or a secrets manager."
                            ),
                        ))
            except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 4a: LLM — SKILL.md prompt-injection analysis
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_llm_skill_analysis(
        self, skill_md: str, filename: str, result: ScanResult
    ):
        if not _gemini_model:
            return

        prompt = textwrap.dedent(f"""
            You are an expert security researcher analyzing an OpenClaw SKILL.md file
            for prompt injection vulnerabilities and malicious patterns.

            OpenClaw skills are SKILL.md files injected directly into an AI agent's
            system prompt. A malicious skill can:
            1. Inject instructions that override the agent's safety guidelines
            2. Contain data-fetching logic that exfiltrates credentials to external servers
            3. Poison the agent's long-term memory with adversarial instructions
            4. Impersonate legitimate system tools to gain elevated trust
            5. Use invisible unicode or zero-width characters to hide instructions

            Analyze this SKILL.md and return a JSON array of findings.
            Each finding must have:
              rule_id  (string, e.g. "llm:hidden-instruction")
              severity (CRITICAL | HIGH | MEDIUM | LOW | INFO)
              title    (short string)
              description (what exactly is suspicious and why)
              remediation (what to do)
            Return ONLY valid JSON array — no markdown fences, no prose.

            File: {filename}
            ===
            {skill_md[:4000]}
        """).strip()

        await self._call_llm_and_add(prompt, filename, "llm:skill-analysis", "CWE-77", result)

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 4b: LLM — general code heuristics
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_llm_code_analysis(
        self, code: str, filename: str, context: Optional[str], result: ScanResult
    ):
        if not _gemini_model:
            return

        prompt = textwrap.dedent(f"""
            You are a security code reviewer analyzing code for OpenClaw agent security.
            Focus specifically on:
            - Indirect prompt injection: external data passed unsanitized to LLM calls
            - Supply chain attacks: suspicious download/install patterns in skill code
            - Agent-targeting malicious intent: code designed to exploit AI infrastructure

            Return a JSON array of findings (empty [] if none).
            Only include HIGH or CRITICAL findings to minimise false positives.
            Each finding: rule_id, severity, title, description, remediation.
            Return ONLY valid JSON — no markdown.

            File: {filename}
            {f'Context: {context}' if context else ''}
            ===
            {code[:3000]}
        """).strip()

        await self._call_llm_and_add(
            prompt, filename, "llm:code-analysis", None, result,
            min_severity={"CRITICAL", "HIGH"},
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 5: OSV dependency audit
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_osv_audit(self, files: dict[str, str], result: ScanResult):
        all_packages: list[dict] = []
        for fname, content in files.items():
            base = Path(fname).name.lower()
            if base == "requirements.txt":
                for pkg in _parse_requirements_txt(content):
                    pkg["source_file"] = fname
                    all_packages.append(pkg)
            elif base == "package.json":
                for pkg in _parse_package_json(content):
                    pkg["source_file"] = fname
                    all_packages.append(pkg)
            elif base == "openclaw.plugin.json":
                for pkg in _parse_openclaw_plugin_json(content):
                    pkg["source_file"] = fname
                    all_packages.append(pkg)

        queryable = [p for p in all_packages if p.get("version")]
        if not queryable:
            return

        queries = [
            {
                "version": pkg["version"],
                "package": {
                    "name":      pkg["name"],
                    "ecosystem": pkg.get("ecosystem", "PyPI"),
                },
            }
            for pkg in queryable
        ]

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
                if resp.status_code != 200:
                    logger.warning(f"OSV API {resp.status_code}: {resp.text[:200]}")
                    return
                data = resp.json()
        except Exception as e:
            logger.warning(f"OSV query failed: {e}")
            return

        for i, osv_result in enumerate(data.get("results", [])):
            vulns = osv_result.get("vulns", [])
            if not vulns:
                continue

            pkg = queryable[i]
            for vuln in vulns:
                vuln_id  = vuln.get("id", "UNKNOWN")
                summary  = vuln.get("summary", "Known vulnerability")
                severity = "HIGH"
                db_sev   = vuln.get("database_specific", {}).get("severity", "").upper()
                sev_map  = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                            "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}
                if db_sev in sev_map:
                    severity = sev_map[db_sev]

                cves = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
                cve  = cves[0] if cves else None

                result.add(Finding(
                    rule_id=f"osv:{vuln_id}",
                    layer="osv",
                    severity=severity,
                    cwe=None,
                    cve=cve,
                    title=f"Vulnerable dependency: {pkg['name']}=={pkg['version']}",
                    description=(
                        f"{vuln_id}: {summary}. "
                        f"Found in {pkg.get('source_file', 'manifest')} "
                        f"({pkg.get('ecosystem', 'unknown')} ecosystem)."
                    ),
                    filename=pkg.get("source_file"),
                    remediation=(
                        f"Upgrade {pkg['name']} to a patched version. "
                        f"Full advisory: https://osv.dev/vulnerability/{vuln_id}"
                    ),
                ))

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 6: Cross-file LLM synthesis
    # ─────────────────────────────────────────────────────────────────────────
    async def _run_llm_cross_file_analysis(
        self, files: dict[str, str], result: ScanResult
    ):
        if not _gemini_model or len(files) < 2:
            return

        file_previews = []
        for fname, content in list(files.items())[:20]:
            preview = content[:300].replace("\n", "↵ ").strip()
            file_previews.append(f"[{fname}]\n{preview}")

        file_map = "\n\n".join(file_previews)

        prompt = textwrap.dedent(f"""
            You are an expert malware analyst performing cross-file analysis on
            an OpenClaw skill package submitted for security auditing.

            Your task: find DISTRIBUTED attack patterns where individual files
            appear benign in isolation but TOGETHER form a threat. Examples:
            - File A reads ~/.openclaw/device.json, File B posts it to an external URL
            - A SKILL.md injects instructions telling the agent to execute a helper script
            - A utility module builds a payload that main.py silently assembles
            - A config file activates dormant malicious logic in another file
            - One file harvests browser cookies, another encodes and sends them

            Here is a preview of every file in the package (first 300 chars each):

            {file_map}

            Return a JSON array of cross-file findings (empty [] if none found).
            Each finding must have:
              rule_id      "llm:cross-file:<short-slug>"
              severity     CRITICAL | HIGH | MEDIUM
              title        short description of the combined threat
              description  which specific files are involved, how they connect,
                           and what the combined effect is
              remediation  which files to remove or change and why
            Return ONLY valid JSON array — no markdown, no preamble.
        """).strip()

        await self._call_llm_and_add(
            prompt, "[multi-file]", "llm:cross-file", "CWE-77", result,
            min_severity={"CRITICAL", "HIGH", "MEDIUM"},
            max_tokens=2000,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Shared LLM helper
    # ─────────────────────────────────────────────────────────────────────────
    async def _call_llm_and_add(
        self,
        prompt:          str,
        filename:        str,
        default_rule_id: str,
        default_cwe:     Optional[str],
        result:          ScanResult,
        min_severity:    Optional[set] = None,
        max_tokens:      int           = 1500,
    ):
        if not _gemini_model:
            return
        try:
            generation_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=0.1,
                response_mime_type="application/json",
            )
            response = await _gemini_model.generate_content_async(
                prompt,
                generation_config=generation_config,
            )
            text = response.text.strip()
            text = re.sub(r"^```(?:json)?\n?", "", text)
            text = re.sub(r"\n?```$",          "", text)

            findings = json.loads(text)
            if not isinstance(findings, list):
                return

            for f in findings:
                if not isinstance(f, dict):
                    continue
                sev = f.get("severity", "MEDIUM")
                if min_severity and sev not in min_severity:
                    continue
                result.add(Finding(
                    rule_id=f.get("rule_id", default_rule_id),
                    layer="llm",
                    severity=sev,
                    cwe=default_cwe,
                    cve=None,
                    title=f.get("title", "LLM-detected issue"),
                    description=f.get("description", ""),
                    filename=filename,
                    remediation=f.get("remediation"),
                ))
        except json.JSONDecodeError as e:
            logger.debug(f"LLM returned non-JSON for {filename}: {e}")
        except Exception as e:
            logger.debug(f"LLM call failed for {filename}: {e}")
