"""
conftest.py — Shared fixtures and session-level setup.

Session setup:
  • Loads .env so API keys are available in test processes.
  • Ensures test_vulnerable_repo/ is a committed git repository so
    gitleaks detect --source can scan git history.

Per-test cleanup:
  • Wipes scan_outputs/raw/ and reports/ before every test function
    so each test runs from a clean state.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Canonical paths
# ---------------------------------------------------------------------------

AGENT_DIR    = Path(__file__).parent.parent
REPO         = AGENT_DIR / "test_vulnerable_repo"
RAW_DIR      = AGENT_DIR / "scan_outputs" / "raw"
ERRORS_DIR   = AGENT_DIR / "scan_outputs" / "errors"
REPORTS_DIR  = AGENT_DIR / "reports"
FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# .env loader (mirrors main.py so tests also have API keys)
# ---------------------------------------------------------------------------

def _load_dotenv() -> None:
    env_file = AGENT_DIR / ".env"
    if not env_file.exists():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_file, override=False)
    except ImportError:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


# ---------------------------------------------------------------------------
# Tool-availability helpers (re-exported for test modules)
# ---------------------------------------------------------------------------

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


skip_no_semgrep   = pytest.mark.skipif(not tool_available("semgrep"),   reason="semgrep not installed")
skip_no_gitleaks  = pytest.mark.skipif(not tool_available("gitleaks"),  reason="gitleaks not installed")
skip_no_trivy     = pytest.mark.skipif(not tool_available("trivy"),     reason="trivy not installed")
skip_no_pip_audit = pytest.mark.skipif(not tool_available("pip-audit"), reason="pip-audit not installed")


# ---------------------------------------------------------------------------
# Session fixture: git-init the vulnerable repo
# ---------------------------------------------------------------------------

def _git(args: list[str], cwd: Path = REPO, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, **kw)


@pytest.fixture(scope="session", autouse=True)
def init_vulnerable_repo():
    """
    Ensure test_vulnerable_repo/ is a committed git repository.
    gitleaks detect --source requires git history to scan.
    """
    if not (REPO / ".git").exists():
        _git(["init"],                                            check=True)
        _git(["config", "user.email", "test@vuln-agent.local"],  check=True)
        _git(["config", "user.name",  "vuln-agent-test"],         check=True)

    _git(["add", "-A"])
    status = _git(["status", "--porcelain"])
    if status.stdout.strip():
        _git(
            ["commit", "-m", "chore: add/update intentionally vulnerable test fixtures"],
            check=True,
        )
    yield


# ---------------------------------------------------------------------------
# Function fixture: clean output directories before each test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_output_dirs():
    """Reset scan outputs and reports before every test function."""
    for d in (RAW_DIR, ERRORS_DIR, REPORTS_DIR):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
    yield


# ---------------------------------------------------------------------------
# Convenience session fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def repo_path() -> Path:
    return REPO


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def agent_dir() -> Path:
    return AGENT_DIR
