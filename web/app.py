"""
web/app.py — FastAPI web interface for ThreatLens.

Endpoints
---------
GET  /                         Show the scan form.
POST /scan                     Start a background scan job.
GET  /status/{job_id}          Return JSON job progress / events / summary.
GET  /report/{job_id}          Render the final report as HTML.
GET  /report/{job_id}/markdown Download the raw Markdown report.

Security controls
-----------------
- Only public GitHub HTTPS URLs accepted (strict regex + shell-metachar reject).
- git clone uses an argument list, never shell=True.
- GIT_TERMINAL_PROMPT=0 prevents git from hanging on auth prompts.
- Repo working-tree size is checked after clone; >500 MB aborts the job.
- Scan outputs are isolated per-job under jobs/{job_id}/.
- Cloned repos are always deleted in a finally block (cleanup_status recorded).
- Raw scanner JSON is never served publicly.

Limitations (MVP)
-----------------
- Job state is in-memory only; it resets when the server restarts.
- Max 3 concurrent scans (threading.Semaphore).
- No authentication / private repo support.
"""
import json as _json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import markdown as _md
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Bootstrap — add agent root to sys.path so we can import main.*
# ---------------------------------------------------------------------------

AGENT_DIR = Path(__file__).parent.parent.resolve()
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from main import AssessmentError, run_assessment  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

JOBS_DIR       = AGENT_DIR / "jobs"
TEMP_REPOS_DIR = AGENT_DIR / "temp_repos"
DB_PATH        = AGENT_DIR / "threatlens.db"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_REPO_SIZE_BYTES  = 500 * 1024 * 1024   # 500 MB (working tree, excl. .git)
MAX_CONCURRENT_SCANS = 3
CLONE_TIMEOUT_SECS   = 120                  # 2 minutes

_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(\.git)?/?$"
)
# Characters that have meaning in a POSIX shell — reject on sight
_SHELL_META_RE = re.compile(r"[;&|`$<>\\\'\"!()\[\]{}]")

# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_scan_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update_job(job_id: str, status: str, percent: int, message: str) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["status"]  = status
        job["percent"] = percent
        job["message"] = message
    _persist_job(job_id)


def _add_event(job_id: str, event: dict) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        if "events" not in job:
            job["events"] = []
        job["events"].append(event)


def _persist_job(job_id: str) -> None:
    """Write a status.json snapshot to disk for debugging / recovery."""
    import json
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        snapshot = dict(job)

    job_dir = JOBS_DIR / job_id
    try:
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "status.json").write_text(
            json.dumps(snapshot, default=str, indent=2), encoding="utf-8"
        )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------

def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _db_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                job_id       TEXT PRIMARY KEY,
                repo_url     TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                completed_at TEXT,
                status       TEXT NOT NULL DEFAULT 'running',
                duration_s   INTEGER,
                total        INTEGER DEFAULT 0,
                confirmed    INTEGER DEFAULT 0,
                needs_review INTEGER DEFAULT 0,
                critical     INTEGER DEFAULT 0,
                high         INTEGER DEFAULT 0,
                medium       INTEGER DEFAULT 0,
                low          INTEGER DEFAULT 0,
                risk_score   INTEGER,
                report_path  TEXT,
                error_msg    TEXT,
                architecture TEXT
            )
        """)


def _compute_risk(c: int, h: int, m: int, l: int) -> int:
    raw = min(c * 12, 55) + min(h * 2.5, 33) + min(m * 0.8, 14) + min(l * 0.2, 5)
    return min(100, round(raw))


def _db_start_scan(job_id: str, repo_url: str, created_at: str) -> None:
    try:
        with _db_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scans (job_id, repo_url, created_at) VALUES (?,?,?)",
                (job_id, repo_url, created_at),
            )
    except Exception as exc:
        log.warning("DB insert failed: %s", exc)


def _db_finish_scan(job_id: str) -> None:
    """Read from in-memory job and write final state to SQLite."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        snapshot = dict(job) if job else None
    if snapshot is None:
        return

    status   = snapshot.get("status", "failed")
    summary  = snapshot.get("summary") or {}
    c        = int(summary.get("critical") or 0)
    h        = int(summary.get("high") or 0)
    m        = int(summary.get("medium") or 0)
    l        = int(summary.get("low") or 0)
    total    = int(summary.get("findings_total") or 0)
    confirmed    = int(summary.get("confirmed") or 0)
    needs_review = int(summary.get("needs_review") or 0)
    risk     = _compute_risk(c, h, m, l) if (c or h or m or l) else None

    # Extract architecture from events
    arch_json = None
    for ev in (snapshot.get("events") or []):
        if ev.get("stage") == "architecture_mapping" and ev.get("status") == "completed":
            arch_json = _json.dumps(ev.get("details", {}))
            break

    # Approximate duration
    created_ts = snapshot.get("created_at")
    try:
        from datetime import datetime, timezone
        start = datetime.fromisoformat(created_ts.replace("Z", "+00:00"))
        dur_s = int((datetime.now(timezone.utc) - start).total_seconds())
    except Exception:
        dur_s = None

    try:
        with _db_conn() as conn:
            conn.execute("""
                UPDATE scans SET
                    status=?, completed_at=?, duration_s=?,
                    total=?, confirmed=?, needs_review=?,
                    critical=?, high=?, medium=?, low=?,
                    risk_score=?, report_path=?, error_msg=?, architecture=?
                WHERE job_id=?
            """, (
                status, _now_iso(), dur_s,
                total, confirmed, needs_review,
                c, h, m, l,
                risk, snapshot.get("report_path"), snapshot.get("error"),
                arch_json, job_id,
            ))
    except Exception as exc:
        log.warning("DB update failed: %s", exc)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_REPOS_DIR.mkdir(parents=True, exist_ok=True)
    _init_db()
    yield


app = FastAPI(
    title="ThreatLens",
    description="Evidence-based vulnerability assessment for public GitHub repositories",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def _validate_github_url(url: str) -> tuple[bool, str]:
    """
    Return (True, "") for safe GitHub HTTPS URLs,
    or (False, reason) for anything else.
    """
    url = (url or "").strip()
    if not url:
        return False, "URL is required."
    if _SHELL_META_RE.search(url):
        return False, "URL contains invalid characters."
    if not _GITHUB_URL_RE.match(url):
        return False, (
            "Only public GitHub repository URLs are accepted. "
            "Expected format: https://github.com/owner/repo"
        )
    return True, ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _repo_size_bytes(path: Path) -> int:
    """Sum file sizes under path, skipping .git to measure working-tree size."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fname in filenames:
            try:
                total += (Path(dirpath) / fname).stat().st_size
            except OSError:
                pass
    return total


def _clone_repo(repo_url: str, dest: Path) -> None:
    """
    Shallow-clone a public GitHub repo.
    Raises RuntimeError on failure or timeout.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth=1", "--", repo_url, str(dest)]
    clone_env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",   # fail immediately instead of prompting
        "GIT_ASKPASS":         "echo",
    }
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECS,
            env=clone_env,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"git clone timed out after {CLONE_TIMEOUT_SECS}s. "
            "The repository may be too large or unavailable."
        )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()[:800]
        raise RuntimeError(
            f"git clone failed (exit {proc.returncode}):\n{stderr}"
        )


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

def _scan_worker(job_id: str, repo_url: str, skip_llm: bool) -> None:
    repo_dir = TEMP_REPOS_DIR / job_id
    job_dir  = JOBS_DIR / job_id
    acquired = False

    # Persist scan start to SQLite
    with _jobs_lock:
        job = _jobs.get(job_id)
        created_at = job.get("created_at", _now_iso()) if job else _now_iso()
    _db_start_scan(job_id, repo_url, created_at)

    def _evt(stage: str, status: str, percent: int, message: str, details: dict | None = None) -> dict:
        return {
            "stage":     stage,
            "status":    status,
            "percent":   percent,
            "message":   message,
            "timestamp": _now_iso(),
            "details":   details or {},
        }

    def _progress_cb(event: dict) -> None:
        """Receive a rich event dict from run_assessment and persist it."""
        stage   = event["stage"]
        percent = event["percent"]
        message = event["message"]
        status  = event.get("status", "running")

        # Only advance the top-level job status for "running" events
        # (completed/skipped/failed just add events without overwriting the stage)
        if status == "running":
            _update_job(job_id, stage, percent, message)

        _add_event(job_id, event)

        # Extract summary counts from the validation-completed event
        if stage == "validation" and status == "completed":
            details = event.get("details", {})
            confirmed_n    = details.get("confirmed", 0)
            needs_review_n = details.get("needs_review", 0)
            with _jobs_lock:
                job = _jobs.get(job_id)
                if job:
                    if "summary" not in job:
                        job["summary"] = {}
                    job["summary"].update({
                        "findings_total": confirmed_n + needs_review_n,
                        "confirmed":      confirmed_n,
                        "needs_review":   needs_review_n,
                        "critical":       details.get("critical", 0),
                        "high":           details.get("high", 0),
                        "medium":         details.get("medium", 0),
                        "low":            details.get("low", 0),
                    })

    try:
        # ── Clone ──────────────────────────────────────────────────────────
        _update_job(job_id, "cloning", 2, f"Cloning {repo_url}...")
        _add_event(job_id, _evt("cloning", "running", 2,
                                f"Cloning {repo_url} with depth=1..."))

        _clone_repo(repo_url, repo_dir)

        _add_event(job_id, _evt("cloning", "completed", 4,
                                "Repository cloned successfully",
                                {"path": str(repo_dir)}))

        # ── Size guard ─────────────────────────────────────────────────────
        size = _repo_size_bytes(repo_dir)
        if size > MAX_REPO_SIZE_BYTES:
            mb       = size // (1024 * 1024)
            limit_mb = MAX_REPO_SIZE_BYTES // (1024 * 1024)
            raise RuntimeError(
                f"Repository working tree is {mb} MB, "
                f"which exceeds the {limit_mb} MB limit."
            )

        # ── Wait for a scan slot ───────────────────────────────────────────
        _update_job(job_id, "queued", 4, "Waiting for a scan slot...")
        _scan_semaphore.acquire()
        acquired = True

        # ── Run assessment ─────────────────────────────────────────────────
        report_path = run_assessment(
            repo_path=repo_dir,
            output_dir=job_dir,
            progress_callback=_progress_cb,
            skip_llm=skip_llm,
            repo_url=repo_url,
        )

        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                if "summary" not in job:
                    job["summary"] = {}
                job["summary"]["report_url"] = f"/report/{job_id}"
                job.update(
                    status="completed",
                    percent=100,
                    message="Assessment complete!",
                    report_path=str(report_path),
                )
        _add_event(job_id, _evt("completed", "completed", 100,
                                "Scan complete — report is ready",
                                {"report_url": f"/report/{job_id}"}))
        _persist_job(job_id)

    except AssessmentError as exc:
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                job.update(
                    status="failed",
                    message="Assessment failed — incomplete report written.",
                    error=str(exc),
                    report_path=str(exc.report_path) if exc.report_path else None,
                )
        _persist_job(job_id)
        log.error("Assessment failed for job %s: %s", job_id, exc)

    except Exception as exc:
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                job.update(
                    status="failed",
                    message=f"Unexpected error: {type(exc).__name__}",
                    error=str(exc),
                )
        _persist_job(job_id)
        log.exception("Unexpected error in scan worker for job %s", job_id)

    finally:
        if acquired:
            _scan_semaphore.release()

        # ── Cleanup: always delete the cloned repo ──────────────────────────
        _add_event(job_id, _evt("cleanup", "running", 98,
                                "Deleting cloned repository..."))

        cleanup_deleted = False
        cleanup_error: Optional[str] = None
        if repo_dir.exists():
            try:
                shutil.rmtree(repo_dir)
                cleanup_deleted = True
                log.info("Deleted cloned repo for job %s", job_id)
            except Exception as exc:
                cleanup_error = str(exc)
                log.warning("Could not delete repo dir for job %s: %s", job_id, exc)
        else:
            cleanup_deleted = True  # already gone

        cleanup_ts     = _now_iso()
        cleanup_status = {
            "deleted":   cleanup_deleted,
            "timestamp": cleanup_ts,
            "error":     cleanup_error,
        }
        if not cleanup_deleted and repo_dir.exists():
            cleanup_status["path"] = str(repo_dir)

        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                job["cleanup_status"] = cleanup_status

        _add_event(job_id, _evt(
            "cleanup",
            "completed" if cleanup_deleted else "failed",
            99,
            "Repository deleted" if cleanup_deleted else f"Cleanup failed: {cleanup_error}",
            cleanup_status,
        ))

        # Safety net: mark still-running job as failed (shouldn't happen)
        with _jobs_lock:
            job = _jobs.get(job_id, {})
            if job.get("status") not in ("completed", "failed"):
                job["status"]  = "failed"
                job["message"] = "Worker exited unexpectedly."
        _persist_job(job_id)

        # Write final state to SQLite
        _db_finish_scan(job_id)


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    repo_url: str
    skip_llm: bool = False


# ---------------------------------------------------------------------------
# HTML — index page (served from template file)
# ---------------------------------------------------------------------------

def _read_index() -> str:
    return (Path(__file__).parent / "templates" / "index.html").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# HTML — report page wrapper
# ---------------------------------------------------------------------------

_REPORT_WRAPPER = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vulnerability Report — {job_short}</title>
  <style>
    :root {{
      --bg:#f9fafb; --card:#fff; --border:#e5e7eb;
      --text:#111827; --muted:#6b7280; --accent:#4f46e5;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background:var(--bg); color:var(--text); line-height:1.7;
      max-width:1100px; margin:0 auto; padding:1.5rem 1rem;
    }}
    .topbar {{
      position:sticky; top:0; background:#fff;
      border-bottom:1px solid var(--border);
      padding:.6rem 1rem; display:flex; gap:1.5rem; align-items:center;
      font-size:.875rem; margin-bottom:2rem;
      box-shadow:0 1px 3px rgba(0,0,0,.07);
    }}
    .topbar a {{color:var(--accent); text-decoration:none;}}
    .topbar a:hover {{text-decoration:underline;}}
    .badge {{
      background:#eef2ff; color:var(--accent); padding:.2rem .6rem;
      border-radius:999px; font-size:.75rem; font-weight:600;
    }}
    h1 {{font-size:1.875rem; margin:.5rem 0 1.5rem;}}
    h2 {{font-size:1.4rem; border-bottom:2px solid var(--border);
         padding-bottom:.4rem; margin-top:2.5rem;}}
    h3 {{font-size:1.1rem; color:var(--accent); margin-top:1.8rem;}}
    table {{width:100%; border-collapse:collapse; margin:1rem 0; font-size:.875rem;}}
    th, td {{padding:.55rem .9rem; border:1px solid var(--border); text-align:left;}}
    th {{background:#f3f4f6; font-weight:600;}}
    tr:nth-child(even) td {{background:#fafafa;}}
    code {{
      background:#f3f4f6; padding:.15rem .4rem; border-radius:.25rem;
      font-family:"SFMono-Regular",Consolas,monospace; font-size:.85em;
    }}
    pre {{
      background:#1e293b; color:#e2e8f0; padding:1rem;
      border-radius:.5rem; overflow-x:auto; font-size:.85rem;
    }}
    pre code {{background:transparent; color:inherit; padding:0;}}
    blockquote {{
      border-left:4px solid var(--accent); margin:.75rem 0;
      padding:.5rem 1rem; background:#f0f4ff;
      font-family:"SFMono-Regular",Consolas,monospace;
      font-size:.85rem; white-space:pre-wrap;
    }}
    hr {{border:none; border-top:2px solid var(--border); margin:2rem 0;}}
    a {{color:var(--accent);}}
    ul, ol {{padding-left:1.5rem;}}
  </style>
</head>
<body>
  <div class="topbar">
    <span class="badge">ThreatLens</span>
    <a href="/">← New Scan</a>
    <a href="/report/{job_id}/markdown">⬇ Download Markdown</a>
    <span style="margin-left:auto;color:var(--muted);font-size:.8rem;">Job: {job_short}</span>
  </div>
  {body}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    return _read_index()


@app.post("/scan")
async def start_scan(request: ScanRequest):
    ok, err = _validate_github_url(request.repo_url)
    if not ok:
        raise HTTPException(status_code=400, detail=err)

    job_id = str(uuid.uuid4())
    now_ts = _now_iso()

    initial_events = [
        {
            "stage":     "url_validation",
            "status":    "completed",
            "percent":   0,
            "message":   "GitHub URL validated",
            "timestamp": now_ts,
            "details":   {"url": request.repo_url},
        },
        {
            "stage":     "job_created",
            "status":    "completed",
            "percent":   1,
            "message":   "Scan job created",
            "timestamp": now_ts,
            "details":   {"job_id": job_id},
        },
    ]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":         "queued",
            "percent":        1,
            "message":        "Job queued...",
            "error":          None,
            "report_path":    None,
            "repo_url":       request.repo_url,
            "created_at":     now_ts,
            "events":         initial_events,
            "summary": {
                "repo_url":       request.repo_url,
                "findings_total": None,
                "confirmed":      None,
                "needs_review":   None,
                "critical":       None,
                "high":           None,
                "medium":         None,
                "low":            None,
                "report_url":     None,
            },
            "cleanup_status": None,
        }
    _persist_job(job_id)

    t = threading.Thread(
        target=_scan_worker,
        args=(job_id, request.repo_url, request.skip_llm),
        daemon=True,
        name=f"scan-{job_id[:8]}",
    )
    t.start()

    return {"job_id": job_id}


@app.get("/status/{job_id}")
async def get_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        snapshot = dict(job) if job else None

    if snapshot is None:
        raise HTTPException(status_code=404, detail="Job not found.")

    return {
        "job_id":         job_id,
        "status":         snapshot["status"],
        "percent":        snapshot["percent"],
        "message":        snapshot["message"],
        "error":          snapshot.get("error"),
        # top-level report_url kept for backward compat
        "report_url":     f"/report/{job_id}" if snapshot.get("report_path") else None,
        "created_at":     snapshot.get("created_at"),
        "events":         snapshot.get("events", []),
        "summary":        snapshot.get("summary", {}),
        "cleanup_status": snapshot.get("cleanup_status"),
    }


@app.get("/report/{job_id}", response_class=HTMLResponse)
async def get_report(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        snapshot = dict(job) if job else None

    if snapshot is None:
        raise HTTPException(status_code=404, detail="Job not found.")

    report_path_str = snapshot.get("report_path")
    if not report_path_str:
        raise HTTPException(status_code=404, detail="Report is not yet available.")

    report_file = Path(report_path_str)
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk.")

    md_text   = report_file.read_text(encoding="utf-8")
    converter = _md.Markdown(extensions=["tables", "fenced_code", "nl2br"])
    html_body = converter.convert(md_text)

    return _REPORT_WRAPPER.format(
        job_id=job_id,
        job_short=job_id[:8],
        body=html_body,
    )


@app.get("/report/{job_id}/markdown")
async def get_report_markdown(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        snapshot = dict(job) if job else None

    if snapshot is None:
        raise HTTPException(status_code=404, detail="Job not found.")

    report_path_str = snapshot.get("report_path")
    if not report_path_str:
        raise HTTPException(status_code=404, detail="Report is not yet available.")

    report_file = Path(report_path_str)
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk.")

    return FileResponse(
        path=report_file,
        media_type="text/markdown; charset=utf-8",
        filename="vulnerability_report.md",
    )


# ---------------------------------------------------------------------------
# API — scan history + findings (dashboard data)
# ---------------------------------------------------------------------------

@app.get("/api/scans")
async def api_list_scans():
    """Return recent scans from SQLite, merged with any in-memory running jobs."""
    # Collect DB records
    try:
        with _db_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
        db_records = {r["job_id"]: dict(r) for r in rows}
    except Exception as exc:
        log.warning("DB read failed: %s", exc)
        db_records = {}

    # Overlay live in-memory state for running/recent jobs
    with _jobs_lock:
        live_snapshot = {jid: dict(j) for jid, j in _jobs.items()}

    merged = dict(db_records)
    for jid, job in live_snapshot.items():
        if jid not in merged:
            # New job not in DB yet (or DB write pending)
            summary = job.get("summary") or {}
            c = int(summary.get("critical") or 0)
            h = int(summary.get("high") or 0)
            m = int(summary.get("medium") or 0)
            l = int(summary.get("low") or 0)
            merged[jid] = {
                "job_id":       jid,
                "repo_url":     job.get("repo_url", ""),
                "created_at":   job.get("created_at", ""),
                "completed_at": None,
                "status":       job.get("status", "running"),
                "duration_s":   None,
                "total":        int(summary.get("findings_total") or 0),
                "confirmed":    int(summary.get("confirmed") or 0),
                "needs_review": int(summary.get("needs_review") or 0),
                "critical":     c, "high": h, "medium": m, "low": l,
                "risk_score":   _compute_risk(c, h, m, l) if (c or h or m or l) else None,
                "report_path":  job.get("report_path"),
                "error_msg":    job.get("error"),
                "architecture": None,
            }
        elif job.get("status") in ("running", "queued"):
            # Update DB record with live status
            merged[jid]["status"] = job.get("status", merged[jid]["status"])

    # Sort by created_at desc
    result = sorted(merged.values(), key=lambda r: r.get("created_at") or "", reverse=True)
    return result[:100]


@app.get("/api/scans/{job_id}/findings")
async def api_scan_findings(job_id: str):
    """Return top findings for a completed scan by parsing raw scanner output."""
    if not re.match(r"^[0-9a-f\-]{36}$", job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID.")

    raw_dir  = JOBS_DIR / job_id / "raw"
    findings = []

    # ── Gitleaks ──────────────────────────────────────────────────────────
    gl_file = raw_dir / "gitleaks.json"
    if gl_file.exists():
        try:
            items = _json.loads(gl_file.read_text(encoding="utf-8")) or []
            for item in items[:5]:
                findings.append({
                    "source":   "secrets",
                    "severity": "HIGH",
                    "title":    item.get("Description", "Secret Detected")[:90],
                    "rule":     item.get("RuleID", ""),
                    "file":     Path(item.get("File", "")).name or item.get("File", ""),
                    "line":     item.get("StartLine", 0),
                })
        except Exception as exc:
            log.debug("gitleaks parse error for %s: %s", job_id, exc)

    # ── Semgrep ───────────────────────────────────────────────────────────
    sg_file = raw_dir / "semgrep.json"
    if sg_file.exists():
        try:
            data    = _json.loads(sg_file.read_text(encoding="utf-8"))
            results = data.get("results", [])
            _sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
            results.sort(key=lambda r: _sev_rank.get(r.get("extra", {}).get("severity", "INFO"), 2))
            for item in results[:6]:
                extra = item.get("extra", {})
                raw_sev = extra.get("severity", "INFO")
                sev = "CRITICAL" if raw_sev == "ERROR" else ("HIGH" if raw_sev == "WARNING" else "LOW")
                msg = extra.get("message", "Code finding")
                findings.append({
                    "source":   "code",
                    "severity": sev,
                    "title":    msg[:90],
                    "rule":     item.get("check_id", "").split(".")[-1],
                    "file":     Path(item.get("path", "")).name or item.get("path", ""),
                    "line":     item.get("start", {}).get("line", 0),
                })
        except Exception as exc:
            log.debug("semgrep parse error for %s: %s", job_id, exc)

    # Sort by severity and deduplicate titles
    _rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: _rank.get(f["severity"], 3))
    seen: set = set()
    deduped = []
    for f in findings:
        key = (f["source"], f["rule"] or f["title"][:40])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped[:8]
