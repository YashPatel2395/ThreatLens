#!/usr/bin/env python3
"""
main.py — Orchestrate the full vulnerability assessment pipeline.

Usage:
    python main.py /path/to/repo [--skip-llm]

Flags:
    --skip-llm   Produce a scanner-only report without LLM enrichment.
                 No API key is needed.

Exit codes:
    0  Full report generated successfully.
    1  Setup / scanner / LLM-config failure — incomplete report written.
    2  Unexpected unrecoverable error.
"""
import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Step 0a — Load .env before anything reads os.environ
# ---------------------------------------------------------------------------

def _load_dotenv() -> None:
    env_file = Path(__file__).parent / ".env"
    if not env_file.exists():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_file, override=False)
    except ImportError:
        import os
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


# ---------------------------------------------------------------------------
# Step 0b — Logging (before local imports so all modules inherit the config)
# ---------------------------------------------------------------------------

def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


_setup_logging()
log = logging.getLogger("main")


# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------

import architecture_mapper
import config
import llm_analyzer
import normalizer
import report_writer
import scanner_runner
import setup_tools
import validator
from scanner_runner import ScannerError
from setup_tools import ToolStatus


# ---------------------------------------------------------------------------
# AssessmentError
# ---------------------------------------------------------------------------

class AssessmentError(RuntimeError):
    """
    Raised by run_assessment() when a critical pipeline step fails.

    Attributes:
        report_path: Path to the incomplete_assessment.md that was written,
                     or None if report writing also failed.
    """
    def __init__(self, message: str, report_path: Optional[Path] = None):
        super().__init__(message)
        self.report_path = report_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_statuses_to_dicts(statuses: dict[str, ToolStatus]) -> list[dict]:
    return [
        {
            "name":      s.name,
            "version":   s.version,
            "installed": s.installed,
            "required":  s.required,   # False → "Not applicable" in report
            "error":     s.error,
        }
        for s in statuses.values()
    ]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _quick_count(name: str, output_file: Optional[Path]) -> int:
    """Parse a scanner's raw output file and return a rough finding count."""
    if not output_file or not output_file.exists():
        return 0
    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
        if name == "semgrep":
            return len(data.get("results", []))
        if name == "gitleaks":
            return len(data) if isinstance(data, list) else 0
        if name == "trivy":
            return sum(
                len(r.get("Vulnerabilities") or [])
                for r in data.get("Results", [])
            )
        if name == "pip_audit":
            return sum(len(d.get("vulns", [])) for d in data.get("dependencies", []))
        if name == "npm_audit":
            v = data.get("metadata", {}).get("vulnerabilities", {})
            return sum(v.values()) if isinstance(v, dict) else 0
    except Exception:
        pass
    return 0


def run_assessment(
    repo_path:         Path,
    output_dir:        Optional[Path] = None,
    progress_callback: Optional[Callable[[dict], None]] = None,
    skip_llm:          bool = False,
    repo_url:          Optional[str] = None,
) -> Path:
    """
    Run the full vulnerability assessment pipeline programmatically.

    This is the primary entry point for both the CLI (via run()) and the
    web interface (via web/app.py).  It never calls sys.exit(); failures
    raise AssessmentError instead so callers can handle them cleanly.

    Args:
        repo_path:         Absolute path to the repository to assess.
        output_dir:        When provided, write all scan outputs and the final
                           report under this directory (per-job isolation for
                           the web interface).  Uses config-level paths when None.
        progress_callback: Optional callable(event_dict) invoked at each pipeline step.
                           event_dict has keys: stage, status, percent, message,
                           timestamp, details.
        skip_llm:          Skip LLM enrichment; produce a scanner-only report.
        repo_url:          Original GitHub URL (for the report Scope section).

    Returns:
        Path to the generated vulnerability_assessment_report.md.

    Raises:
        AssessmentError: when a critical step fails.  An incomplete_assessment.md
                         is written and its path is stored in exc.report_path.
    """

    def _cb(
        stage:   str,
        percent: int,
        message: str,
        status:  str = "running",
        details: Optional[dict] = None,
    ) -> None:
        log.info("[%s] %d%% — %s", stage, percent, message)
        if progress_callback:
            progress_callback({
                "stage":     stage,
                "status":    status,
                "percent":   percent,
                "message":   message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details":   details or {},
            })

    def _abort(
        failed_tool:        str,
        failed_command:     list,
        error_output:       str,
        completed_scanners: list,
        reason:             str,
    ) -> None:
        path = report_writer.write_incomplete_report(
            failed_tool=failed_tool,
            failed_command=failed_command,
            error_output=error_output,
            completed_scanners=completed_scanners,
            reason=reason,
            output_dir=output_dir,
        )
        log.error("ASSESSMENT INCOMPLETE — see: %s", path)
        raise AssessmentError(reason, report_path=path)

    log.info("=" * 60)
    log.info("ThreatLens starting")
    log.info("Repository : %s", repo_path)
    log.info("Output dir : %s", output_dir or "default (config paths)")
    log.info("LLM        : %s", "disabled (--skip-llm)" if skip_llm else "enabled")
    log.info("=" * 60)

    if not repo_path.exists():
        raise AssessmentError(f"Repository path does not exist: {repo_path}")

    has_package_json = (repo_path / "package.json").exists()

    # ── Step 1: Validate LLM API key ──────────────────────────────────────
    if not skip_llm:
        _cb("checking_llm_config", 2, "Validating LLM configuration...")
        ok, err = config.validate_llm_config()
        if not ok:
            _abort(
                failed_tool="llm_config",
                failed_command=[],
                error_output=err,
                completed_scanners=[],
                reason=f"LLM configuration is invalid — cannot proceed:\n\n{err}",
            )
        log.info("✔ LLM configuration valid.")
        _cb("checking_llm_config", 3, "LLM configuration validated", "completed")
    else:
        _cb("checking_llm_config", 3, "LLM validation skipped (--skip-llm)", "skipped")

    # ── Step 2: Tool setup ─────────────────────────────────────────────────
    _cb("checking_tools", 5, "Checking required security tools...")
    try:
        tool_statuses = setup_tools.check_and_install(repo_path)
    except RuntimeError as exc:
        _abort(
            failed_tool="setup_tools",
            failed_command=[],
            error_output=str(exc),
            completed_scanners=[],
            reason=f"Tool setup failed:\n\n{exc}",
        )

    tool_status_dicts = _tool_statuses_to_dicts(tool_statuses)
    installed_names   = [s.name for s in tool_statuses.values() if s.installed]
    _cb("checking_tools", 8,
        f"Tools verified: {', '.join(installed_names)}",
        "completed",
        {"tools": tool_status_dicts})

    # ── Step 3: Architecture mapping ──────────────────────────────────────
    _cb("architecture_mapping", 10, "Mapping repository architecture...")
    arch = architecture_mapper.map_architecture(repo_path)
    arch_summary = arch.get("language", "Unknown")
    if arch.get("framework") not in (None, "None detected", "unknown"):
        arch_summary += f" · {arch['framework']}"
    if arch.get("is_monorepo"):
        arch_summary += f" · monorepo ({len(arch.get('subprojects', []))} subprojects)"
    _cb("architecture_mapping", 13, f"Architecture: {arch_summary}", "completed", arch)

    # ── Step 4: Run scanners ───────────────────────────────────────────────
    completed_scanners: list[str] = []

    # (stage_name, start_pct, end_pct, human_name)
    _SCANNER_STAGES: dict[str, tuple[str, int, int, str]] = {
        "semgrep":   ("scanning_semgrep",   20, 33, "semgrep (static analysis)"),
        "gitleaks":  ("scanning_gitleaks",  35, 45, "gitleaks (secret detection)"),
        "trivy":     ("scanning_trivy",     47, 57, "trivy (CVE scanning)"),
        "pip_audit": ("scanning_pip_audit", 59, 63, "pip-audit (dependency audit)"),
        "npm_audit": ("scanning_npm_audit", 65, 69, "npm audit"),
    }

    def _on_scanner_start(name: str) -> None:
        if name in _SCANNER_STAGES:
            stage, pct, _, human = _SCANNER_STAGES[name]
            _cb(stage, pct, f"Running {human}...", "running")

    def _on_scanner_complete(name: str, result) -> None:
        if name in _SCANNER_STAGES:
            stage, _, end_pct, human = _SCANNER_STAGES[name]
            if result.success:
                count = _quick_count(name, result.output_file)
                _cb(stage, end_pct,
                    f"{human} completed: {count} finding(s)",
                    "completed", {"count": count})
            else:
                _cb(stage, end_pct, f"{human} failed", "failed",
                    {"error": result.error})

    try:
        scan_results = scanner_runner.run_all(
            repo_path,
            run_npm=has_package_json,
            output_dir=output_dir,
            on_scanner_start=_on_scanner_start,
            on_scanner_complete=_on_scanner_complete,
        )
        completed_scanners = [r.name for r in scan_results if r.success]
        log.info("All scanners completed: %s", ", ".join(completed_scanners))
    except ScannerError as exc:
        completed_scanners = [r.name for r in exc.results if r.success]
        first_fail = next(r for r in exc.results if not r.success)
        _abort(
            failed_tool=first_fail.name,
            failed_command=first_fail.command,
            error_output=(
                f"{first_fail.error}\n\nSTDERR:\n{first_fail.stderr}"
                f"\n\nSTDOUT:\n{first_fail.stdout}"
            ),
            completed_scanners=completed_scanners,
            reason=(
                f"Scanner '{first_fail.name}' failed (exit {first_fail.returncode}). "
                "All scanners must succeed before a report can be generated."
            ),
        )

    # ── Step 5: Normalise ──────────────────────────────────────────────────
    _cb("normalizing", 70, "Normalising scanner findings...")
    raw_dir_override = (output_dir / "raw") if output_dir else None
    findings = normalizer.normalize_all(run_npm=has_package_json, raw_dir=raw_dir_override)

    if not findings:
        log.info("No findings from any scanner — report will reflect a clean scan.")

    tool_counts    = Counter(f.get("tool", "unknown") for f in findings)
    counts_summary = ", ".join(f"{v} from {k}" for k, v in tool_counts.items()) or "none"
    _cb("normalizing", 72,
        f"Normalized {len(findings)} finding(s) ({counts_summary})",
        "completed",
        {"total": len(findings), "by_tool": dict(tool_counts)})

    # ── Step 6: LLM enrichment ─────────────────────────────────────────────
    assessment_mode: str
    if not skip_llm and findings:
        _cb("llm_enrichment", 73,
            "Enriching findings with LLM analysis (this may take a few minutes)...")
        findings = llm_analyzer.analyze(findings, architecture=arch)
        enriched = sum(1 for f in findings if not f.get("enrichment_failed"))
        _cb("llm_enrichment", 88,
            f"LLM enrichment complete: {enriched}/{len(findings)} finding(s) enriched",
            "completed",
            {"enriched": enriched, "total": len(findings)})
        assessment_mode = "llm-enhanced"
    else:
        skip_reason = "--skip-llm flag" if skip_llm else "no findings"
        _cb("llm_enrichment", 88, f"LLM enrichment skipped ({skip_reason})", "skipped")
        assessment_mode = "scanner-only"

    # ── Step 7: Validate ───────────────────────────────────────────────────
    _cb("validation", 90, "Validating and deduplicating findings...")
    validated    = validator.validate(findings)
    confirmed    = validated["confirmed"]
    needs_review = validated["needs_review"]

    sev_counts = {
        s: sum(1 for f in confirmed if (f.get("severity") or "").lower() == s)
        for s in ("critical", "high", "medium", "low")
    }
    _cb("validation", 92,
        f"Validation: {len(confirmed)} confirmed, {len(needs_review)} need review",
        "completed",
        {
            "confirmed":    len(confirmed),
            "needs_review": len(needs_review),
            **sev_counts,
        })

    # ── Step 7b: Quality gate (LLM-enhanced mode only) ─────────────────────
    if assessment_mode == "llm-enhanced":
        failed_enrichment = [f for f in confirmed if f.get("enrichment_failed")]
        if failed_enrichment:
            titles = ", ".join(
                f"'{f.get('title', 'unknown')}' ({f.get('file', '')})"
                for f in failed_enrichment
            )
            _abort(
                failed_tool="llm_analyzer",
                failed_command=[],
                error_output=f"Enrichment failed for: {titles}",
                completed_scanners=completed_scanners,
                reason=(
                    f"LLM enrichment is incomplete — {len(failed_enrichment)} confirmed "
                    f"finding(s) could not be enriched after retry:\n\n{titles}\n\n"
                    "Re-run to retry, or use --skip-llm to produce a scanner-only report."
                ),
            )

    # ── Step 8: Write report ───────────────────────────────────────────────
    _cb("report_generation", 95, "Writing final report...")
    report_path = report_writer.write_full_report(
        repo_path=str(repo_path),
        confirmed=confirmed,
        needs_review=needs_review,
        tool_statuses=tool_status_dicts,
        assessment_mode=assessment_mode,
        skip_llm=skip_llm,
        architecture=arch,
        output_dir=output_dir,
        repo_url=repo_url,
    )
    _cb("report_generation", 97,
        f"Report written: {report_path.name}",
        "completed",
        {"report_name": report_path.name})

    log.info("")
    log.info("=" * 60)
    log.info("ASSESSMENT COMPLETE")
    log.info("Mode       : %s", assessment_mode)
    log.info("Report     : %s", report_path)
    log.info("Confirmed  : %d finding(s)", len(confirmed))
    log.info("Review     : %d finding(s) need manual review", len(needs_review))
    log.info("=" * 60)

    return report_path


def run(repo_path: Path, skip_llm: bool = False) -> None:
    """CLI entry point — thin wrapper around run_assessment()."""
    if not repo_path.exists():
        log.error("Repository path does not exist: %s", repo_path)
        sys.exit(2)

    try:
        run_assessment(repo_path, skip_llm=skip_llm)
    except AssessmentError as exc:
        log.error("")
        log.error("=" * 60)
        log.error("ASSESSMENT INCOMPLETE")
        if exc.report_path:
            log.error("See: %s", exc.report_path)
        log.error("=" * 60)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ThreatLens — evidence-based vulnerability assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py /path/to/repo\n"
            "  python main.py /path/to/repo --skip-llm\n\n"
            "Environment variables (set in .env):\n"
            "  LLM_PROVIDER      anthropic (default) | openai\n"
            "  LLM_MODEL         claude-sonnet-4-6 (default)\n"
            "  ANTHROPIC_API_KEY Required when LLM_PROVIDER=anthropic\n"
            "  OPENAI_API_KEY    Required when LLM_PROVIDER=openai\n"
        ),
    )
    parser.add_argument("repo_path", help="Path to the repository to assess.")
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        default=False,
        help="Skip LLM enrichment; produce a scanner-only report.",
    )
    args = parser.parse_args()

    try:
        run(Path(args.repo_path).resolve(), skip_llm=args.skip_llm)
    except SystemExit:
        raise
    except Exception as exc:
        log.exception("Unexpected error: %s", exc)
        sys.exit(2)


if __name__ == "__main__":
    main()
