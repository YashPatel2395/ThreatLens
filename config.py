"""
config.py — Central configuration for ThreatLens.

All paths, constants, and environment-driven settings live here.
Call load_env() once at startup (main.py does this automatically).
"""
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Base paths
# ---------------------------------------------------------------------------

BASE_DIR        = Path(__file__).parent.resolve()
SCAN_OUTPUTS_DIR = BASE_DIR / "scan_outputs"
RAW_DIR         = SCAN_OUTPUTS_DIR / "raw"
ERRORS_DIR      = SCAN_OUTPUTS_DIR / "errors"
REPORTS_DIR     = BASE_DIR / "reports"

FINAL_REPORT      = REPORTS_DIR / "vulnerability_assessment_report.md"
INCOMPLETE_REPORT = REPORTS_DIR / "incomplete_assessment.md"

# Per-job directories created by the web interface
JOBS_DIR       = BASE_DIR / "jobs"        # output_dir per web scan job
TEMP_REPOS_DIR = BASE_DIR / "temp_repos"  # cloned repos (deleted after scan)

# Per-scanner output files
RAW_FILES: dict[str, Path] = {
    "semgrep":   RAW_DIR / "semgrep.json",
    "gitleaks":  RAW_DIR / "gitleaks.json",
    "trivy":     RAW_DIR / "trivy.json",
    "pip_audit": RAW_DIR / "pip_audit.json",
    "npm_audit": RAW_DIR / "npm_audit.json",
}

ERROR_FILES: dict[str, Path] = {
    "semgrep":   ERRORS_DIR / "semgrep.txt",
    "gitleaks":  ERRORS_DIR / "gitleaks.txt",
    "trivy":     ERRORS_DIR / "trivy.txt",
    "pip_audit": ERRORS_DIR / "pip_audit.txt",
    "npm_audit": ERRORS_DIR / "npm_audit.txt",
}

# ---------------------------------------------------------------------------
# Directories to skip during normalization
# ---------------------------------------------------------------------------

IGNORED_DIRS: set[str] = {
    "node_modules", "venv", ".venv", "dist", "build", ".git",
}

# ---------------------------------------------------------------------------
# Test-file patterns — ONLY match the file itself, not the repo root name.
# A file is considered a test file when its own path component (not an
# ancestor directory that happens to be the repo root) identifies it as
# a test, fixture, mock, or example.
# ---------------------------------------------------------------------------

# Directory names that, when appearing in a path *below* the repo root,
# signal the file is a test artifact.
TEST_DIR_NAMES: set[str] = {
    "tests", "test", "fixtures", "fixture",
    "examples", "example", "mocks", "mock",
    "spec", "specs", "fakes", "stubs",
}

# Filename prefixes / suffixes for test files.
TEST_FILENAME_PREFIXES = ("test_",)
TEST_FILENAME_SUFFIXES = ("_test.py", "_spec.py")
TEST_FILENAMES_EXACT   = {"conftest.py"}

# ---------------------------------------------------------------------------
# Scanner timeout (seconds)
# ---------------------------------------------------------------------------

SCANNER_TIMEOUT = 300  # 5 minutes per scanner

# ---------------------------------------------------------------------------
# LLM configuration (read from environment after load_env() is called)
# ---------------------------------------------------------------------------

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)

LLM_PROVIDER: str = _env("LLM_PROVIDER", "anthropic")
LLM_MODEL:    str = _env("LLM_MODEL",    "claude-sonnet-4-6")

LLM_BATCH_SIZE = 10  # max findings per LLM call (keep responses within token budget)

# ---------------------------------------------------------------------------
# LLM key validation
# ---------------------------------------------------------------------------

def validate_llm_config() -> tuple[bool, str]:
    """
    Verify that the required API key is present for the configured provider.

    Returns:
        (True, "")            — key present, safe to proceed.
        (False, error_msg)    — key missing; caller must abort.
    """
    provider = _env("LLM_PROVIDER", "anthropic").lower()
    if provider == "anthropic":
        key = _env("ANTHROPIC_API_KEY")
        if not key:
            return False, (
                "LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set.\n"
                "Either set ANTHROPIC_API_KEY in your .env file, "
                "or re-run with --skip-llm to produce a scanner-only report."
            )
    elif provider == "openai":
        key = _env("OPENAI_API_KEY")
        if not key:
            return False, (
                "LLM_PROVIDER=openai but OPENAI_API_KEY is not set.\n"
                "Either set OPENAI_API_KEY in your .env file, "
                "or re-run with --skip-llm to produce a scanner-only report."
            )
    else:
        return False, (
            f"Unknown LLM_PROVIDER='{provider}'. Supported values: anthropic, openai.\n"
            "Check your .env file."
        )
    return True, ""
