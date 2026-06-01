"""
report_writer.py — Generate Markdown vulnerability assessment reports.

Two public entry points:
  write_full_report(...)       → reports/vulnerability_assessment_report.md
  write_incomplete_report(...) → reports/incomplete_assessment.md

Report sections (10):
  1.  Executive Summary
  2.  Scope
  3.  Assessment Mode
  4.  Tools Executed
  5.  System Overview
  6.  Findings Table
  7.  Detailed Findings
  8.  Needs Manual Review
  9.  Limitations
  10. Recommendations
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from config import FINAL_REPORT, INCOMPLETE_REPORT, REPORTS_DIR

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


_SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
    "unknown":  "⚫",
}


def _sev_badge(sev: str) -> str:
    icon = _SEV_ICON.get((sev or "unknown").lower(), "⚫")
    return f"{icon} {(sev or 'unknown').upper()}"


def _sev_order(sev: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}.get(
        (sev or "").lower(), 0
    )


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in ("critical", "high", "medium", "low", "info", "unknown")}
    for f in findings:
        key = (f.get("severity") or "unknown").lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _esc(text: Any) -> str:
    """Escape pipe / newline for Markdown table cells."""
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_executive_summary(
    repo_path: str,
    confirmed: list[dict],
    needs_review: list[dict],
    tool_statuses: list[dict],
    assessment_mode: str,
) -> str:
    counts = _severity_counts(confirmed)
    total  = len(confirmed) + len(needs_review)

    rows = "\n".join(
        f"| {_sev_badge(s)} | {counts[s]} |"
        for s in ("critical", "high", "medium", "low", "info", "unknown")
        if counts[s]
    )
    tools_run = ", ".join(t["name"] for t in tool_statuses if t.get("installed"))

    return (
        "## 1. Executive Summary\n\n"
        f"This vulnerability assessment was conducted against `{repo_path}` "
        f"on {_now()} using automated scanners"
        + (" with LLM-enhanced analysis." if assessment_mode == "llm-enhanced" else ".")
        + "\n\n"
        f"| Metric | Value |\n"
        f"|--------|-------|\n"
        f"| Total findings | {total} |\n"
        f"| Confirmed | {len(confirmed)} |\n"
        f"| Needs Manual Review | {len(needs_review)} |\n"
        f"| Assessment mode | {assessment_mode.replace('-', ' ').title()} |\n"
        f"| Scanners | {tools_run or 'None'} |\n\n"
        "**Severity breakdown (confirmed):**\n\n"
        "| Severity | Count |\n"
        "|----------|-------|\n"
        + rows + "\n"
    )


def _section_scope(repo_path: str, repo_url: Optional[str] = None) -> str:
    url_row = (
        f"| GitHub URL | [{repo_url}]({repo_url}) |\n"
        if repo_url else ""
    )
    return (
        "## 2. Scope\n\n"
        "| Item | Value |\n"
        "|------|-------|\n"
        + url_row
        + f"| Local clone path | `{repo_path}` |\n"
        f"| Assessment date | {_now()} |\n"
        f"| Assessment type | Static analysis · Dependency audit · Secret detection |\n"
        f"| Dynamic testing | Not performed |\n"
        f"| Manual code review | Not performed |\n"
    )


def _section_assessment_mode(
    assessment_mode: str,
    skip_llm: bool,
    provider: str,
    model: str,
) -> str:
    if assessment_mode == "llm-enhanced":
        description = (
            f"Findings were enriched by **{provider}** (`{model}`). "
            "Each finding includes AI-generated impact assessment, likelihood rating, "
            "exploit scenario, and remediation guidance — all grounded in scanner evidence."
        )
    elif assessment_mode == "scanner-only":
        description = (
            "Findings are based entirely on automated scanner output. "
            "No LLM enrichment was applied (`--skip-llm` flag used or provider unavailable). "
            "Impact and likelihood fields were not generated."
        )
    else:
        description = "Assessment could not be completed. See failure details below."

    return (
        "## 3. Assessment Mode\n\n"
        f"**Mode: {assessment_mode.replace('-', ' ').title()}**\n\n"
        f"{description}\n\n"
        "| Field | Value |\n"
        "|-------|-------|\n"
        f"| Mode | {assessment_mode.replace('-', ' ').title()} |\n"
        f"| LLM Provider | {provider or 'N/A'} |\n"
        f"| LLM Model | {model or 'N/A'} |\n"
        f"| --skip-llm | {'Yes' if skip_llm else 'No'} |\n"
    )


def _section_tools_executed(tool_statuses: list[dict]) -> str:
    def _status(t: dict) -> str:
        if not t.get("required", True):
            return "⚪ Not applicable"
        return "✔ Success" if t.get("installed") else "✘ Failed"

    rows = "\n".join(
        f"| {t.get('name','')} | {t.get('version','unknown') or 'unknown'} "
        f"| {_status(t)} |"
        for t in tool_statuses
    )
    return (
        "## 4. Tools Executed\n\n"
        "| Tool | Version | Status |\n"
        "|------|---------|--------|\n"
        + rows + "\n"
    )


def _section_system_overview(repo_path: str, architecture: Optional[dict]) -> str:
    p = Path(repo_path)

    if architecture:
        db  = architecture.get("database",        ["None detected"])
        auth = architecture.get("auth",           ["None detected"])
        dep  = architecture.get("deployment",     ["None detected"])
        pm   = architecture.get("package_manager",["Unknown"])
        eps  = architecture.get("entry_points",   ["None detected"])

        is_monorepo = architecture.get("is_monorepo", False)
        subprojects = architecture.get("subprojects", [])
        mono_str    = f"Yes ({len(subprojects)} subprojects)" if is_monorepo else "No"

        arch_table = (
            "| Attribute | Detected Value |\n"
            "|-----------|----------------|\n"
            f"| Primary language | {architecture.get('language', 'Unknown')} |\n"
            f"| All languages | {', '.join(architecture.get('all_languages', [])) or 'Unknown'} |\n"
            f"| Framework | {architecture.get('framework', 'Unknown')} |\n"
            f"| Monorepo | {mono_str} |\n"
            f"| Database | {', '.join(db) if isinstance(db, list) else db} |\n"
            f"| Authentication | {', '.join(auth) if isinstance(auth, list) else auth} |\n"
            f"| Deployment | {', '.join(dep) if isinstance(dep, list) else dep} |\n"
            f"| Package manager | {', '.join(pm) if isinstance(pm, list) else pm} |\n"
            f"| Entry points | {', '.join(eps) if isinstance(eps, list) else eps} |\n"
        )

        if subprojects:
            arch_table += (
                "\n**Detected Subprojects:**\n\n"
                "| Path | Language | Framework | Package Manager |\n"
                "|------|----------|-----------|----------------|\n"
            )
            for sp in subprojects:
                arch_table += (
                    f"| `{sp['path']}` | {sp['language']} "
                    f"| {sp['framework']} | {sp['package_manager']} |\n"
                )
    else:
        has_py     = bool(list(p.glob("**/*.py")))
        has_js     = (p / "package.json").exists()
        has_docker = (p / "Dockerfile").exists()
        detected = ", ".join(filter(None, [
            "Python" if has_py else "",
            "Node.js" if has_js else "",
            "Docker" if has_docker else "",
        ])) or "Unknown"
        arch_table = (
            "| Attribute | Detected Value |\n"
            "|-----------|----------------|\n"
            f"| Stack | {detected} |\n"
        )

    return (
        "## 5. System Overview\n\n"
        f"**Repository:** `{repo_path}`\n\n"
        + arch_table
        + "\n> Architecture detection is based on static file presence checks only.\n"
    )


def _section_findings_table(confirmed: list[dict]) -> str:
    if not confirmed:
        return "## 6. Findings Table\n\n_No confirmed findings._\n"

    rows = "\n".join(
        f"| {i} | {_esc(f.get('title','')[:80])} | {_sev_badge(f.get('severity','unknown'))} "
        f"| {_esc(f.get('tool',''))} | {_esc(Path(f.get('file','')).name or f.get('file',''))} "
        f"| {f.get('line') or '—'} | {_esc(f.get('confidence',''))} |"
        for i, f in enumerate(confirmed, 1)
    )
    return (
        "## 6. Findings Table\n\n"
        "| # | Title | Severity | Tool | File | Line | Confidence |\n"
        "|---|-------|----------|------|------|------|------------|\n"
        + rows + "\n"
    )


def _section_detailed_findings(confirmed: list[dict]) -> str:
    if not confirmed:
        return "## 7. Detailed Findings\n\n_No confirmed findings._\n"

    blocks = []
    for i, f in enumerate(confirmed, 1):
        title = f.get("title", "Unknown")
        blocks.append(
            f"### Finding {i}: {title}\n\n"
            "| Field | Value |\n"
            "|-------|-------|\n"
            f"| **Severity** | {_sev_badge(f.get('severity','unknown'))} |\n"
            f"| **Tool** | {f.get('tool','')} |\n"
            f"| **Category** | {f.get('category','')} |\n"
            f"| **File** | `{f.get('file','')}` |\n"
            f"| **Line** | {f.get('line') or '—'} |\n"
            f"| **Confidence** | {f.get('confidence','')} |\n\n"
            "**Evidence:**\n"
            f"> {f.get('evidence', '_No evidence recorded._')}\n\n"
            "**Impact:**\n"
            f"{f.get('impact', '_Not analysed._')}\n\n"
            f"**Likelihood:** {f.get('likelihood', 'unknown')}\n\n"
            "**Exploit Scenario:**\n"
            f"{f.get('exploit_scenario', '_Not analysed._')}\n\n"
            "**Recommended Fix:**\n"
            f"{f.get('recommended_fix', f.get('recommendation', '_No recommendation._'))}\n\n"
            "---\n"
        )
    return "## 7. Detailed Findings\n\n" + "\n".join(blocks)


def _section_needs_manual_review(needs_review: list[dict]) -> str:
    if not needs_review:
        return "## 8. Needs Manual Review\n\n_No findings flagged for manual review._\n"

    rows = "\n".join(
        f"| {i} | {_esc(f.get('title','')[:70])} | {_sev_badge(f.get('severity','unknown'))} "
        f"| {_esc(f.get('tool',''))} | {_esc(Path(f.get('file','')).name or f.get('file',''))} "
        f"| {_esc(f.get('notes','Low confidence / insufficient evidence'))} |"
        for i, f in enumerate(needs_review, 1)
    )
    return (
        "## 8. Needs Manual Review\n\n"
        "These findings require human judgement. They may be false positives, "
        "low-confidence detections, or findings in test/example files.\n\n"
        "| # | Title | Severity | Tool | File | Reason |\n"
        "|---|-------|----------|------|------|--------|\n"
        + rows + "\n"
    )


def _section_cleanup(cleanup_status: Optional[dict]) -> Optional[str]:
    if not cleanup_status:
        return None
    deleted = cleanup_status.get("deleted", False)
    status_str = "✔ Deleted" if deleted else (
        f"✘ Failed — {cleanup_status.get('error', 'unknown error')}"
    )
    ts_row = (
        f"| Cleanup timestamp | {cleanup_status['timestamp']} |\n"
        if cleanup_status.get("timestamp") else ""
    )
    path_row = (
        f"| Clone path | `{cleanup_status['path']}` |\n"
        if cleanup_status.get("path") and not deleted else ""
    )
    return (
        "## Scan Infrastructure\n\n"
        "| Item | Status |\n"
        "|------|--------|\n"
        f"| Cloned repository deleted | {status_str} |\n"
        + ts_row
        + path_row
    )


def _section_limitations() -> str:
    return (
        "## 9. Limitations\n\n"
        "- Assessment is based on **static analysis** and **dependency audits** only. "
        "No runtime or dynamic testing was performed.\n"
        "- Scanner rules produce **false positives**. Every finding must be reviewed "
        "in context before remediation.\n"
        "- Secrets flagged by gitleaks / trivy match known secret formats. "
        "Not all matches are live credentials.\n"
        "- Dependency CVEs reflect **published advisories at scan time**. "
        "New CVEs are discovered continuously — schedule periodic re-scans.\n"
        "- Findings in test/fixture files have been **severity-downgraded** but not removed. "
        "Confirm they are not reachable in production.\n"
        "- LLM-generated analysis (when present) is informational. "
        "It is grounded in scanner evidence but must be validated by a security engineer.\n"
    )


def _section_recommendations(confirmed: list[dict]) -> str:
    critical_high = [
        f for f in confirmed if (f.get("severity") or "").lower() in ("critical", "high")
    ]

    immediate = (
        "\n".join(
            f"- **{f.get('title','Unknown')}**: "
            f"{f.get('recommended_fix', f.get('recommendation','See finding detail.'))}"
            for f in critical_high
        )
        if critical_high
        else "_No critical or high severity findings._"
    )

    return (
        "## 10. Recommendations\n\n"
        "### Immediate Actions (Critical & High)\n\n"
        + immediate + "\n\n"
        "### General Recommendations\n\n"
        "1. Integrate these scanners into CI/CD to catch regressions before merge.\n"
        "2. Establish a vulnerability SLA: critical ≤ 24 h, high ≤ 7 days, medium ≤ 30 days.\n"
        "3. Rotate **all** credentials flagged by gitleaks/trivy, regardless of confidence.\n"
        "4. Pin dependencies and adopt a dependency update bot (Dependabot / Renovate).\n"
        "5. Add pre-commit secret scanning: `gitleaks protect --staged`.\n"
        "6. Schedule weekly re-scans — new CVEs are published daily.\n"
        "7. Enforce parameterised queries / prepared statements for all database access.\n"
    )


# ---------------------------------------------------------------------------
# Public API — full report
# ---------------------------------------------------------------------------

def write_full_report(
    repo_path:       str,
    confirmed:       list[dict],
    needs_review:    list[dict],
    tool_statuses:   list[dict],
    assessment_mode: str = "scanner-only",
    skip_llm:        bool = True,
    architecture:    Optional[dict] = None,
    output_dir:      Optional[Path] = None,
    repo_url:        Optional[str]  = None,
    cleanup_status:  Optional[dict] = None,
) -> Path:
    """
    Write the final Markdown vulnerability assessment report.

    Args:
        repo_path:       Path to the scanned repository (string for display).
        confirmed:       Validated, evidence-backed findings.
        needs_review:    Uncertain / low-confidence findings.
        tool_statuses:   List of {name, version, installed, error} dicts.
        assessment_mode: "scanner-only" | "llm-enhanced".
        skip_llm:        Whether --skip-llm was used.
        architecture:    Optional architecture dict from architecture_mapper.
        output_dir:      When provided (web jobs), write report here instead of
                         the default REPORTS_DIR.

    Returns:
        Path to the generated report file.
    """
    reports_dir  = output_dir if output_dir is not None else REPORTS_DIR
    final_report = reports_dir / "vulnerability_assessment_report.md"
    reports_dir.mkdir(parents=True, exist_ok=True)

    provider = os.environ.get("LLM_PROVIDER", "anthropic") if not skip_llm else ""
    model    = os.environ.get("LLM_MODEL",    "claude-sonnet-4-6") if not skip_llm else ""

    cleanup_section = _section_cleanup(cleanup_status)

    sections = [
        f"# Vulnerability Assessment Report\n\n**Generated:** {_now()}\n",
        _section_executive_summary(repo_path, confirmed, needs_review, tool_statuses, assessment_mode),
        _section_scope(repo_path, repo_url=repo_url),
        _section_assessment_mode(assessment_mode, skip_llm, provider, model),
        _section_tools_executed(tool_statuses),
        _section_system_overview(repo_path, architecture),
        _section_findings_table(confirmed),
        _section_detailed_findings(confirmed),
        _section_needs_manual_review(needs_review),
        _section_limitations(),
        _section_recommendations(confirmed),
    ]
    if cleanup_section:
        sections.append(cleanup_section)
    sections.append(
        "---\n_Report generated by **ThreatLens** — "
        "an evidence-based vulnerability assessment tool._\n"
    )

    report_text = "\n".join(sections)
    final_report.write_text(report_text, encoding="utf-8")
    log.info("Full report written to: %s", final_report)
    return final_report


# ---------------------------------------------------------------------------
# Public API — incomplete report
# ---------------------------------------------------------------------------

def write_incomplete_report(
    failed_tool:        str,
    failed_command:     list[str],
    error_output:       str,
    completed_scanners: list[str],
    reason:             str,
    output_dir:         Optional[Path] = None,
) -> Path:
    """
    Write an incomplete-assessment report when any prerequisite step fails.
    The final vulnerability report MUST NOT be created when this is called.

    Args:
        output_dir: When provided (web jobs), write report here instead of
                    the default REPORTS_DIR.
    """
    reports_dir       = output_dir if output_dir is not None else REPORTS_DIR
    incomplete_report = reports_dir / "incomplete_assessment.md"
    reports_dir.mkdir(parents=True, exist_ok=True)

    cmd_str       = " ".join(str(c) for c in failed_command) if failed_command else "N/A"
    completed_str = ", ".join(completed_scanners) if completed_scanners else "None"

    content = (
        f"# Incomplete Vulnerability Assessment\n\n"
        f"**Generated:** {_now()}\n\n"
        f"> ⚠️ This assessment is **INCOMPLETE**. "
        "The final vulnerability report was NOT generated.\n\n"
        "## Why the Assessment Is Incomplete\n\n"
        f"{reason}\n\n"
        "## Failed Component\n\n"
        f"**Component:** `{failed_tool}`\n\n"
        "## Failed Command\n\n"
        f"```\n{cmd_str}\n```\n\n"
        "## Error Output\n\n"
        f"```\n{error_output[:4000]}\n```\n\n"
        "## Scanners That Completed Successfully\n\n"
        f"{completed_str}\n\n"
        "## Next Steps\n\n"
        "1. Review the error above and resolve the underlying issue.\n"
        "2. Check `scan_outputs/errors/` for detailed scanner error logs.\n"
        "3. Re-run: `python main.py <repo_path>`\n"
        "4. Use `--skip-llm` to run without LLM enrichment if the issue is an API key.\n"
    )

    incomplete_report.write_text(content, encoding="utf-8")
    log.info("Incomplete assessment report written to: %s", incomplete_report)
    return incomplete_report
