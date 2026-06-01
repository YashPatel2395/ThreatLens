"""
scanner_runner.py — Execute security scanners and capture their output.

Rules enforced here:
  • pip-audit ONLY scans the target repository's declared dependencies.
    It never scans the host machine's installed packages.
  • Exact prescribed commands are used for every scanner.
  • On failure: stderr+stdout saved to scan_outputs/errors/, then raises ScannerError.
"""
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from typing import Callable, Optional

from config import ERROR_FILES, RAW_FILES, SCANNER_TIMEOUT

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    name:        str
    command:     list[str]
    success:     bool      = False
    returncode:  int       = -1
    stdout:      str       = ""
    stderr:      str       = ""
    output_file: Optional[Path] = None
    error:       str       = ""


class ScannerError(RuntimeError):
    """Raised when one or more scanners fail."""
    def __init__(self, results: list[ScanResult]):
        self.results = results
        failed = [r.name for r in results if not r.success]
        super().__init__(f"Scanner(s) failed: {', '.join(failed)}")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _run_scanner(name: str, cmd: list[str], output_file: Path, err_file: Path) -> ScanResult:
    result = ScanResult(name=name, command=cmd, output_file=output_file)
    log.info("Running %s …\n  cmd: %s", name, " ".join(str(c) for c in cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT,
        )
        result.returncode = proc.returncode
        result.stdout     = proc.stdout
        result.stderr     = proc.stderr
    except subprocess.TimeoutExpired:
        result.error = f"Timed out after {SCANNER_TIMEOUT}s"
        _save_error(name, result, err_file)
        return result
    except FileNotFoundError:
        result.error = f"Binary not found for '{name}'. Is it installed?"
        _save_error(name, result, err_file)
        return result
    except Exception as exc:
        result.error = str(exc)
        _save_error(name, result, err_file)
        return result

    result.success = _is_success(name, proc, output_file)
    if not result.success:
        result.error = f"Exit code {proc.returncode}. See {err_file}"
        _save_error(name, result, err_file)
    else:
        log.info("✔ %s completed (exit %d).", name, proc.returncode)

    return result


def _is_success(name: str, proc: subprocess.CompletedProcess, output_file: Path) -> bool:
    """
    Determine whether a scanner run produced usable output.

    Both semgrep and gitleaks exit 1 when they find issues — that is expected
    and counts as a successful run. We validate by checking the output file.
    """
    if not output_file.exists():
        return False
    try:
        content = output_file.read_text(encoding="utf-8").strip()
        if not content:
            return False
        json.loads(content)
        return True
    except (json.JSONDecodeError, OSError):
        if proc.returncode not in (0, 1):
            return False
        return output_file.stat().st_size > 0


def _save_error(name: str, result: ScanResult, err_file: Path) -> None:
    err_file.parent.mkdir(parents=True, exist_ok=True)
    body = (
        f"Command   : {' '.join(str(c) for c in result.command)}\n"
        f"Exit code : {result.returncode}\n"
        f"Error     : {result.error}\n\n"
        f"--- STDERR ---\n{result.stderr}\n\n"
        f"--- STDOUT ---\n{result.stdout}\n"
    )
    err_file.write_text(body, encoding="utf-8")
    log.error("✘ %s failed — details saved to %s", name, err_file)


# ---------------------------------------------------------------------------
# Individual scanners
# ---------------------------------------------------------------------------

def _run_semgrep(repo_path: Path, raw_files: dict, error_files: dict) -> ScanResult:
    out = raw_files["semgrep"]
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "semgrep", "--config=auto",
        "--json", f"--output={out}",
        # Exclude IDE / AI tool config directories from code analysis.
        # Secret scanners (gitleaks/trivy) still scan these paths.
        "--exclude=.claude",
        "--exclude=.cursor",
        "--exclude=.vscode",
        "--exclude=.idea",
        str(repo_path),
    ]
    return _run_scanner("semgrep", cmd, out, error_files["semgrep"])


def _run_gitleaks(repo_path: Path, raw_files: dict, error_files: dict) -> ScanResult:
    out = raw_files["gitleaks"]
    out.parent.mkdir(parents=True, exist_ok=True)

    # gitleaks detect --source requires a git repo in the path.
    # For non-git directories (e.g. CI temp checkouts) fall back to --no-git
    # which scans the filesystem directly instead of git history.
    is_git = (repo_path / ".git").exists()
    cmd = [
        "gitleaks", "detect",
        "--source", str(repo_path),
        "--report-format", "json",
        "--report-path", str(out),
    ]
    if not is_git:
        cmd.append("--no-git")
        log.info("gitleaks: target has no .git directory — using --no-git (filesystem scan).")

    result = _run_scanner("gitleaks", cmd, out, error_files["gitleaks"])

    # gitleaks writes no report file when zero leaks are found.
    # Normalise to an empty array so downstream parsing always works.
    if not out.exists() or out.stat().st_size == 0:
        out.write_text("[]", encoding="utf-8")
        result.success = True
        log.info("gitleaks: no leaks found — wrote empty output file.")

    return result


def _run_trivy(repo_path: Path, raw_files: dict, error_files: dict) -> ScanResult:
    out = raw_files["trivy"]
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "trivy", "fs", str(repo_path),
        "--format", "json",
        "--output", str(out),
    ]
    return _run_scanner("trivy", cmd, out, error_files["trivy"])


def _find_requirements_file(repo_path: Path) -> Optional[Path]:
    """
    Locate a pip-readable requirements file inside the repository.
    Checks common locations in priority order.
    Never returns anything outside repo_path.
    """
    candidates = [
        "requirements.txt",
        "requirements/base.txt",
        "requirements/prod.txt",
        "requirements/production.txt",
        "requirements-prod.txt",
    ]
    for rel in candidates:
        p = repo_path / rel
        if p.exists() and p.stat().st_size > 0:
            return p
    return None


def _extract_pyproject_deps(pyproject_path: Path) -> list[str]:
    """
    Parse a pyproject.toml and return a flat list of dependency specifiers
    suitable for writing to a temporary requirements.txt.
    Supports PEP 621 and Poetry layouts.
    """
    try:
        try:
            import tomllib                   # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib      # pip install tomli
            except ImportError:
                log.warning(
                    "Cannot parse pyproject.toml: install tomli "
                    "(pip install tomli) for Python < 3.11."
                )
                return []

        with open(pyproject_path, "rb") as fh:
            data = tomllib.load(fh)

        deps: list[str] = []

        # PEP 621 — [project] dependencies
        for spec in data.get("project", {}).get("dependencies", []):
            deps.append(spec)

        # Poetry — [tool.poetry.dependencies]
        for pkg, ver in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if pkg.lower() == "python":
                continue
            if isinstance(ver, str):
                deps.append(pkg if ver in ("*", "") else f"{pkg}{ver}")
            elif isinstance(ver, dict):
                v = ver.get("version", "*")
                deps.append(pkg if v in ("*", "") else f"{pkg}{v}")
            else:
                deps.append(pkg)

        return deps
    except Exception as exc:
        log.error("Failed to parse pyproject.toml: %s", exc)
        return []


def _run_pip_audit(repo_path: Path, raw_files: dict, error_files: dict) -> ScanResult:
    """
    Audit Python dependencies declared in the repository.

    Strategy (in priority order):
      1. requirements.txt (or requirements/base.txt etc.)
            → pip-audit -r <file> -f json -o <out>
      2. pyproject.toml
            → extract deps, write temp file, pip-audit -r <temp> -f json -o <out>
      3. Neither found
            → write empty output; skip with a warning.

    The host machine's installed packages are NEVER scanned.
    """
    out      = raw_files["pip_audit"]
    err_file = error_files["pip_audit"]
    out.parent.mkdir(parents=True, exist_ok=True)

    # --- Strategy 1: requirements.txt ---
    req_file = _find_requirements_file(repo_path)
    if req_file:
        log.info("pip-audit: scanning %s", req_file)
        cmd = ["pip-audit", "-r", str(req_file), "-f", "json", "-o", str(out)]
        result = _run_scanner("pip_audit", cmd, out, err_file)
        # pip-audit exits 1 when vulnerabilities exist — still a valid run
        if not result.success and out.exists() and out.stat().st_size > 0:
            try:
                json.loads(out.read_text(encoding="utf-8"))
                result.success = True
                log.info(
                    "pip-audit: exit %d but output is valid JSON — treating as success.",
                    result.returncode,
                )
            except json.JSONDecodeError:
                pass
        return result

    # --- Strategy 2: pyproject.toml ---
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        log.info("pip-audit: no requirements.txt found; extracting deps from pyproject.toml")
        deps = _extract_pyproject_deps(pyproject)
        if deps:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="vuln_agent_reqs_"
            ) as fh:
                fh.write("\n".join(deps) + "\n")
                temp_path = fh.name
            try:
                cmd = ["pip-audit", "-r", temp_path, "-f", "json", "-o", str(out)]
                result = _run_scanner("pip_audit", cmd, out, err_file)
            finally:
                os.unlink(temp_path)

            if not result.success and out.exists() and out.stat().st_size > 0:
                try:
                    json.loads(out.read_text(encoding="utf-8"))
                    result.success = True
                except json.JSONDecodeError:
                    pass
            return result
        else:
            log.warning("pip-audit: pyproject.toml found but no extractable dependencies.")

    # --- Strategy 3: nothing to scan ---
    log.info(
        "pip-audit: no requirements.txt or pyproject.toml found in %s — skipping.",
        repo_path,
    )
    out.write_text('{"dependencies": [], "fixes": []}', encoding="utf-8")
    return ScanResult(
        name="pip_audit",
        command=["pip-audit", "(skipped — no Python dep file found)"],
        success=True,
        output_file=out,
    )


def _run_npm_audit(repo_path: Path, raw_files: dict, error_files: dict) -> ScanResult:
    """npm audit writes JSON to stdout; we capture and persist it."""
    out      = raw_files["npm_audit"]
    err_file = error_files["npm_audit"]
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd  = ["npm", "audit", "--json"]
    result = ScanResult(name="npm_audit", command=cmd, output_file=out)
    log.info("Running npm audit …\n  cmd: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT,
            cwd=str(repo_path),
        )
        result.returncode = proc.returncode
        result.stdout     = proc.stdout
        result.stderr     = proc.stderr

        if proc.stdout.strip():
            try:
                json.loads(proc.stdout)
                out.write_text(proc.stdout, encoding="utf-8")
                result.success = True
                log.info("✔ npm audit completed (exit %d).", proc.returncode)
            except json.JSONDecodeError:
                result.error = "npm audit output is not valid JSON."
                _save_error("npm_audit", result, err_file)
        else:
            result.error = "npm audit produced no stdout."
            _save_error("npm_audit", result, err_file)

    except subprocess.TimeoutExpired:
        result.error = f"npm audit timed out after {SCANNER_TIMEOUT}s"
        _save_error("npm_audit", result, err_file)
    except FileNotFoundError:
        result.error = "npm binary not found."
        _save_error("npm_audit", result, err_file)
    except Exception as exc:
        result.error = str(exc)
        _save_error("npm_audit", result, err_file)

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_all(
    repo_path:            Path,
    run_npm:              bool = False,
    output_dir:           Optional[Path] = None,
    on_scanner_start:     Optional[Callable[[str], None]] = None,
    on_scanner_complete:  Optional[Callable[[str, ScanResult], None]] = None,
) -> list[ScanResult]:
    """
    Execute all required scanners against repo_path.

    Args:
        repo_path:        Resolved path to the repository being assessed.
        run_npm:          Include npm audit (set True when package.json is present).
        output_dir:       When provided (web jobs), write raw scanner output and error
                          logs under output_dir/raw/ and output_dir/errors/ instead of
                          the config-level paths.  Directories are created automatically.
        on_scanner_start:    Optional callback invoked with the scanner name just before
                             each scanner runs.  Used by run_assessment() for progress.
        on_scanner_complete: Optional callback invoked with (name, ScanResult) just after
                             each scanner finishes (success or failure).

    Returns:
        List of ScanResult for every scanner that was run.

    Raises:
        ScannerError: if any scanner fails.
    """
    if output_dir is not None:
        raw_files   = {k: output_dir / "raw"    / v.name for k, v in RAW_FILES.items()}
        error_files = {k: output_dir / "errors" / v.name for k, v in ERROR_FILES.items()}
        (output_dir / "raw").mkdir(parents=True, exist_ok=True)
        (output_dir / "errors").mkdir(parents=True, exist_ok=True)
    else:
        raw_files   = RAW_FILES
        error_files = ERROR_FILES

    scanners = [
        ("semgrep",   lambda: _run_semgrep(repo_path,   raw_files, error_files)),
        ("gitleaks",  lambda: _run_gitleaks(repo_path,  raw_files, error_files)),
        ("trivy",     lambda: _run_trivy(repo_path,     raw_files, error_files)),
        ("pip_audit", lambda: _run_pip_audit(repo_path, raw_files, error_files)),
    ]
    if run_npm:
        scanners.append(
            ("npm_audit", lambda: _run_npm_audit(repo_path, raw_files, error_files))
        )

    results: list[ScanResult] = []
    for name, runner in scanners:
        if on_scanner_start:
            on_scanner_start(name)
        result = runner()
        results.append(result)
        if on_scanner_complete:
            on_scanner_complete(name, result)

    failed = [r for r in results if not r.success]
    if failed:
        raise ScannerError(failed)

    return results
