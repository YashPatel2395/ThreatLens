"""
normalizer.py — Convert raw scanner JSON into a unified finding schema.

Common schema:
{
    "tool":           str,
    "title":          str,
    "severity":       str,   # critical | high | medium | low | info | unknown
    "category":       str,
    "file":           str,
    "line":           int | None,
    "evidence":       str,
    "recommendation": str,
    "confidence":     str,   # high | medium | low
    "raw":            dict,
}

Guarantees:
  • Secrets are redacted before any finding is stored.
  • Findings from ignored directories (node_modules, venv, …) are dropped.
"""
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from config import IGNORED_DIRS, RAW_FILES

log = logging.getLogger(__name__)

REDACTED = "[REDACTED]"

# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

_SECRET_KEY_RE = re.compile(
    r"(secret|password|passwd|token|api[_-]?key|auth|credential|private[_-]?key)",
    re.IGNORECASE,
)
# High-entropy strings that look like tokens / encoded secrets
_SECRET_VALUE_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")


def _redact(text: str) -> str:
    """Replace high-entropy strings that resemble credentials."""
    if not text:
        return text
    return _SECRET_VALUE_RE.sub(REDACTED, text)


def _redact_dict(d: Any) -> Any:
    """Recursively redact secret-looking values from a dict / list."""
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            if isinstance(v, str) and _SECRET_KEY_RE.search(k):
                out[k] = REDACTED
            else:
                out[k] = _redact_dict(v)
        return out
    if isinstance(d, list):
        return [_redact_dict(i) for i in d]
    if isinstance(d, str):
        return _redact(d)
    return d


# ---------------------------------------------------------------------------
# Path filtering
# ---------------------------------------------------------------------------

def _is_ignored(file_path: str) -> bool:
    return any(part in IGNORED_DIRS for part in Path(file_path).parts)


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

_SEV_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "moderate": "medium",
    "low":      "low",
    "info":     "info",
    "informational": "info",
    "warning":  "low",
    "error":    "high",
    "note":     "info",
}


def _norm_sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower().strip(), "unknown")


# ---------------------------------------------------------------------------
# Blank finding factory
# ---------------------------------------------------------------------------

def _blank(tool: str) -> dict:
    return {
        "tool":           tool,
        "title":          "",
        "severity":       "unknown",
        "category":       "",
        "file":           "",
        "line":           None,
        "evidence":       "",
        "recommendation": "",
        "confidence":     "low",
        "raw":            {},
    }


# ---------------------------------------------------------------------------
# Per-tool parsers
# ---------------------------------------------------------------------------

_SEMGREP_LOGIN_NOISE = frozenset({"requires login", "login required", ""})


def _semgrep_source_snippet(path: str, line_num: int | None) -> str:
    """
    Read the actual source line(s) from the file on disk.

    semgrep's ``extra.lines`` field is unreliable when the tool is running
    in a state that shows a login prompt (it returns "requires login" for
    every finding).  We read the source directly instead.

    Returns up to 3 lines centred on ``line_num``, or empty string on error.
    """
    if not path or not line_num:
        return ""
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            src = fh.readlines()
        start = max(0, line_num - 2)
        end   = min(len(src), line_num + 1)
        return "".join(src[start:end]).rstrip()
    except OSError:
        return ""


def _parse_semgrep(data: dict) -> list[dict]:
    findings: list[dict] = []
    for r in data.get("results", []):
        path = r.get("path", "")
        if _is_ignored(path):
            continue
        extra    = r.get("extra", {})
        meta     = extra.get("metadata", {})
        check_id = r.get("check_id", "Semgrep Finding")
        line_num = r.get("start", {}).get("line")
        message  = (extra.get("message") or "").strip()

        # Build evidence: prefer actual source code; fall back to rule message.
        raw_lines = (extra.get("lines") or "").strip()
        if raw_lines and raw_lines.lower() not in _SEMGREP_LOGIN_NOISE:
            snippet = _redact(raw_lines)
        else:
            snippet = _redact(_semgrep_source_snippet(path, line_num))

        if snippet:
            evidence = snippet
            if message:
                evidence += f"\n# {message[:200]}"
        elif message:
            evidence = f"Rule: {check_id}\nMessage: {message[:300]}\nAt: {path}:{line_num}"
        else:
            evidence = f"{check_id} at {path}:{line_num}"

        f = _blank("semgrep")
        f["title"]          = check_id
        f["severity"]       = _norm_sev(extra.get("severity", ""))
        f["category"]       = meta.get("category", "")
        f["file"]           = path
        f["line"]           = line_num
        f["evidence"]       = evidence
        f["recommendation"] = message
        f["confidence"]     = str(meta.get("confidence", "medium")).lower()
        f["raw"]            = _redact_dict(r)
        findings.append(f)
    return findings


def _parse_gitleaks(data: list) -> list[dict]:
    findings: list[dict] = []
    for r in data:
        path = r.get("File", "")
        if _is_ignored(path):
            continue
        f = _blank("gitleaks")
        f["title"]      = r.get("RuleID", "Secret Detected")
        f["severity"]   = "high"
        f["category"]   = "secret"
        f["file"]       = path
        f["line"]       = r.get("StartLine")
        f["evidence"]   = REDACTED          # never store the actual secret value
        f["recommendation"] = (
            "Revoke the exposed credential immediately. "
            "Remove it from git history with git-filter-repo or BFG Repo Cleaner. "
            "Add a pre-commit hook (gitleaks protect --staged) to prevent recurrence."
        )
        f["confidence"] = "high"
        f["raw"]        = _redact_dict(r)
        findings.append(f)
    return findings


def _parse_trivy(data: dict) -> list[dict]:
    findings: list[dict] = []
    for res in data.get("Results", []):
        target = res.get("Target", "")
        if _is_ignored(target):
            continue

        for vuln in res.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "unknown")
            f = _blank("trivy")
            f["title"]    = f"{vuln.get('VulnerabilityID', 'CVE-Unknown')} in {pkg}"
            f["severity"] = _norm_sev(vuln.get("Severity", ""))
            f["category"] = "dependency"
            f["file"]     = target
            f["line"]     = None
            f["evidence"] = (
                f"Package {pkg}=={vuln.get('InstalledVersion', '?')}. "
                f"Fixed in: {vuln.get('FixedVersion', 'no fix available')}. "
                f"{vuln.get('Description', '')[:300]}"
            )
            fix = vuln.get("FixedVersion", "")
            f["recommendation"] = (
                f"Upgrade {pkg} to {fix}."
                if fix
                else f"No patch available for {vuln.get('VulnerabilityID')}; monitor for updates."
            )
            f["confidence"] = "high"
            f["raw"]        = _redact_dict(vuln)
            findings.append(f)

        for secret in res.get("Secrets") or []:
            f = _blank("trivy")
            f["title"]      = secret.get("Title", "Secret Detected")
            f["severity"]   = _norm_sev(secret.get("Severity", "high"))
            f["category"]   = "secret"
            f["file"]       = target
            f["line"]       = secret.get("StartLine")
            f["evidence"]   = REDACTED
            f["recommendation"] = "Revoke and rotate the exposed credential immediately."
            f["confidence"] = "high"
            f["raw"]        = _redact_dict(secret)
            findings.append(f)

    return findings


def _parse_pip_audit(data: Any) -> list[dict]:
    """
    Handles both pip-audit output formats:
      • list of {"name", "version", "vulns": [...]}   (legacy)
      • {"dependencies": [...], "fixes": [...]}        (v2+)
    """
    findings: list[dict] = []

    packages: list[dict]
    if isinstance(data, list):
        packages = data
    elif isinstance(data, dict):
        packages = data.get("dependencies", [])
    else:
        return findings

    for pkg in packages:
        name = pkg.get("name", "unknown")
        ver  = pkg.get("version", "?")
        for vuln in pkg.get("vulns") or []:
            aliases = vuln.get("aliases", [])
            cve = next(
                (a for a in aliases if a.upper().startswith("CVE-")),
                vuln.get("id", "Unknown"),
            )
            f = _blank("pip_audit")
            f["title"]    = f"{cve} in {name}"
            f["severity"] = "high"  # pip-audit does not report severity; default high
            f["category"] = "dependency"
            f["file"]     = "requirements.txt / project dependencies"
            f["line"]     = None
            f["evidence"] = (
                f"Package {name}=={ver} has vulnerability {cve}. "
                f"{vuln.get('description', '')[:300]}"
            )
            fixes = vuln.get("fix_versions", [])
            f["recommendation"] = (
                f"Upgrade {name} to {', '.join(fixes)}."
                if fixes
                else f"No fix available for {cve}; consider alternative packages."
            )
            f["confidence"] = "high"
            f["raw"]        = _redact_dict({**pkg, "vuln": vuln})
            findings.append(f)

    return findings


def _parse_npm_audit(data: dict) -> list[dict]:
    findings: list[dict] = []

    # npm v7+ format
    for pkg_name, info in data.get("vulnerabilities", {}).items():
        severity = _norm_sev(info.get("severity", ""))
        for v in info.get("via") or []:
            if not isinstance(v, dict):
                continue
            f = _blank("npm_audit")
            f["title"]    = v.get("title", f"npm vulnerability in {pkg_name}")
            f["severity"] = _norm_sev(v.get("severity", severity))
            f["category"] = "dependency"
            f["file"]     = f"package.json → {pkg_name}"
            f["line"]     = None
            f["evidence"] = (
                f"Package {pkg_name} (range: {v.get('range', 'unknown')}). "
                f"Ref: {v.get('url', '')}"
            )
            fix_avail = info.get("fixAvailable", False)
            f["recommendation"] = (
                "Run `npm audit fix` to apply the available patch."
                if fix_avail
                else f"No automatic fix available. Review {v.get('url', 'npm advisory')}."
            )
            f["confidence"] = "high"
            f["raw"]        = _redact_dict({"pkg": pkg_name, "via": v, "info": info})
            findings.append(f)

    # npm v6 format
    for adv_id, adv in data.get("advisories", {}).items():
        f = _blank("npm_audit")
        f["title"]    = adv.get("title", f"npm advisory {adv_id}")
        f["severity"] = _norm_sev(adv.get("severity", ""))
        f["category"] = "dependency"
        f["file"]     = f"package.json / {adv.get('module_name', '')}"
        f["line"]     = None
        f["evidence"] = adv.get("overview", "")[:300]
        f["recommendation"] = adv.get("recommendation", "")
        f["confidence"] = "high"
        f["raw"]        = _redact_dict(adv)
        findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_all(run_npm: bool = False, raw_dir: Optional[Path] = None) -> list[dict]:
    """
    Load all raw scanner output files and return a unified finding list.

    Args:
        run_npm:  Whether to include npm_audit output.
        raw_dir:  When provided (web jobs), read scanner JSON from this directory
                  instead of the default config-level RAW_FILES paths.

    Returns:
        List of normalised finding dicts.
    """
    if raw_dir is not None:
        job_raw: dict[str, Path] = {k: raw_dir / v.name for k, v in RAW_FILES.items()}
    else:
        job_raw = RAW_FILES

    parsers: dict[str, tuple[Path, Any]] = {
        "semgrep":   (job_raw["semgrep"],   _parse_semgrep),
        "gitleaks":  (job_raw["gitleaks"],  _parse_gitleaks),
        "trivy":     (job_raw["trivy"],      _parse_trivy),
        "pip_audit": (job_raw["pip_audit"],  _parse_pip_audit),
    }
    if run_npm:
        parsers["npm_audit"] = (job_raw["npm_audit"], _parse_npm_audit)

    all_findings: list[dict] = []
    for tool_name, (raw_file, parser) in parsers.items():
        if not raw_file.exists():
            log.warning("Raw output missing for %s — skipping.", tool_name)
            continue
        try:
            text = raw_file.read_text(encoding="utf-8").strip()
            if not text:
                log.warning("%s output is empty — skipping.", tool_name)
                continue
            data = json.loads(text)
            findings = parser(data)
            log.info("Normalised %d finding(s) from %s.", len(findings), tool_name)
            all_findings.extend(findings)
        except json.JSONDecodeError as exc:
            log.error("Failed to parse %s output: %s", tool_name, exc)
        except Exception as exc:
            log.error("Error normalising %s: %s", tool_name, exc, exc_info=True)

    log.info("Total normalised findings: %d", len(all_findings))
    return all_findings
