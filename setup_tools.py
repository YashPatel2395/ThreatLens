"""
setup_tools.py — Verify and auto-install required scanning tools.

Returns a ToolStatus dict for each required tool. Stops the workflow
(raises RuntimeError) when a mandatory tool cannot be installed.
"""
import logging
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ToolStatus:
    name: str
    required: bool = True
    installed: bool = False
    version: str = ""
    install_attempted: bool = False
    install_success: Optional[bool] = None
    error: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _get_version(cmd: list[str]) -> str:
    """Return version string or empty string on failure."""
    try:
        r = _run(cmd)
        output = (r.stdout + r.stderr).strip()
        return output.splitlines()[0] if output else ""
    except Exception:
        return ""


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _brew_install(package: str) -> tuple[bool, str]:
    """Install via Homebrew. Returns (success, error_message)."""
    log.info("brew install %s …", package)
    try:
        r = _run(["brew", "install", package], timeout=300)
        if r.returncode == 0:
            return True, ""
        return False, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return False, "Homebrew (brew) is not installed."
    except Exception as exc:
        return False, str(exc)


def _pip_install(package: str) -> tuple[bool, str]:
    """Install via pip. Returns (success, error_message)."""
    log.info("pip install %s …", package)
    try:
        r = _run([sys.executable, "-m", "pip", "install", package], timeout=180)
        if r.returncode == 0:
            return True, ""
        return False, (r.stdout + r.stderr).strip()
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Per-tool install strategies
# ---------------------------------------------------------------------------

_BREW_TOOLS = {
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "trivy": "trivy",
}

_VERSION_CMDS = {
    "semgrep":   ["semgrep", "--version"],
    "gitleaks":  ["gitleaks", "version"],
    "trivy":     ["trivy", "--version"],
    "pip-audit": ["pip-audit", "--version"],
    "npm":       ["npm", "--version"],
}


def _install_tool(name: str) -> tuple[bool, str]:
    """Attempt to install *name*. Returns (success, error)."""
    if name in _BREW_TOOLS and _is_macos():
        return _brew_install(_BREW_TOOLS[name])

    if name == "pip-audit":
        return _pip_install("pip-audit")

    if name == "npm":
        # npm ships with Node.js — we cannot auto-install it.
        return (
            False,
            "npm is not installed. Please install Node.js (https://nodejs.org/) "
            "which includes npm, then re-run this tool.",
        )

    return False, f"No auto-install strategy defined for '{name}' on this platform."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_and_install(repo_path: Path) -> dict[str, ToolStatus]:
    """
    Verify all required tools are present; install missing ones.

    Args:
        repo_path: Path to the repository being scanned.

    Returns:
        Mapping of tool-name → ToolStatus.

    Raises:
        RuntimeError: If any required tool cannot be installed.
    """
    has_package_json = (repo_path / "package.json").exists()

    # Build the list of tools we need
    tools = ["semgrep", "gitleaks", "trivy", "pip-audit"]
    npm_status = ToolStatus(name="npm", required=has_package_json)

    statuses: dict[str, ToolStatus] = {t: ToolStatus(name=t) for t in tools}
    statuses["npm"] = npm_status

    errors: list[str] = []

    for name, status in statuses.items():
        if not status.required:
            log.info("Tool '%s' not required (package.json absent) — skipping.", name)
            continue

        binary = name
        # pip-audit binary is exactly 'pip-audit'
        if shutil.which(binary) is not None:
            status.installed = True
            status.version = _get_version(_VERSION_CMDS.get(name, [name, "--version"]))
            log.info("✔ %s found  (%s)", name, status.version or "version unknown")
            continue

        # Tool missing — attempt install
        log.warning("✘ %s not found — attempting install …", name)
        status.install_attempted = True

        success, err = _install_tool(name)
        status.install_success = success

        if success:
            # Re-check after install
            if shutil.which(binary) is not None:
                status.installed = True
                status.version = _get_version(_VERSION_CMDS.get(name, [name, "--version"]))
                log.info("✔ %s installed successfully (%s)", name, status.version)
            else:
                status.error = "Installed without error but binary still not found in PATH."
                status.installed = False
                errors.append(f"{name}: {status.error}")
        else:
            status.error = err
            log.error("✘ Failed to install %s: %s", name, err)
            errors.append(f"{name}: {err}")

    if errors:
        raise RuntimeError(
            "One or more required tools could not be installed:\n"
            + "\n".join(f"  • {e}" for e in errors)
        )

    return statuses
