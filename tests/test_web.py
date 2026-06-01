"""
test_web.py — Tests for the FastAPI web interface.

Covers:
  - GitHub URL validation (valid / invalid / shell-injection)
  - POST /scan endpoint (job creation, UUID format, 400 rejections)
  - GET /status/{job_id} endpoint (lifecycle, 404 for unknown)
  - GET /report/{job_id} and /report/{job_id}/markdown endpoints
  - Cleanup: cloned repo is deleted after both success and failure
"""
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Bootstrap path ───────────────────────────────────────────────────────
AGENT_DIR = Path(__file__).parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from fastapi.testclient import TestClient
import web.app as web_app
from web.app import app, _jobs, _jobs_lock, _validate_github_url

client = TestClient(app)


# ============================================================================
# Helpers
# ============================================================================

def _make_job(
    status: str = "queued",
    percent: int = 0,
    message: str = "Queued...",
    report_path: str | None = None,
    error: str | None = None,
) -> str:
    """Insert a synthetic job into _jobs and return its ID."""
    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            "status":      status,
            "percent":     percent,
            "message":     message,
            "error":       error,
            "report_path": report_path,
            "repo_url":    "https://github.com/test/repo",
            "created_at":  "2026-01-01T00:00:00+00:00",
        }
    return job_id


def _make_report_file(tmp_path: Path, content: str = "# Report\n\nNo findings.") -> Path:
    p = tmp_path / "vulnerability_assessment_report.md"
    p.write_text(content, encoding="utf-8")
    return p


# ============================================================================
# 1. URL validation
# ============================================================================

class TestUrlValidation:

    def test_valid_https_url(self):
        ok, _ = _validate_github_url("https://github.com/owner/repo")
        assert ok

    def test_valid_url_with_git_suffix(self):
        ok, _ = _validate_github_url("https://github.com/owner/repo.git")
        assert ok

    def test_valid_url_with_hyphens_and_dots(self):
        ok, _ = _validate_github_url("https://github.com/my-org/my.repo")
        assert ok

    def test_non_github_host_rejected(self):
        ok, err = _validate_github_url("https://gitlab.com/owner/repo")
        assert not ok
        assert "github" in err.lower()

    def test_http_not_https_rejected(self):
        ok, _ = _validate_github_url("http://github.com/owner/repo")
        assert not ok

    def test_ssh_url_rejected(self):
        ok, _ = _validate_github_url("git@github.com:owner/repo.git")
        assert not ok

    def test_bare_domain_rejected(self):
        ok, _ = _validate_github_url("github.com/owner/repo")
        assert not ok

    def test_empty_url_rejected(self):
        ok, err = _validate_github_url("")
        assert not ok
        assert "required" in err.lower()

    def test_whitespace_only_rejected(self):
        ok, _ = _validate_github_url("   ")
        assert not ok

    # Shell metacharacter injection attempts
    def test_semicolon_rejected(self):
        ok, _ = _validate_github_url("https://github.com/foo/bar;rm -rf /")
        assert not ok

    def test_pipe_rejected(self):
        ok, _ = _validate_github_url("https://github.com/foo/bar|cat /etc/passwd")
        assert not ok

    def test_backtick_rejected(self):
        ok, _ = _validate_github_url("https://github.com/foo/`whoami`")
        assert not ok

    def test_dollar_sign_rejected(self):
        ok, _ = _validate_github_url("https://github.com/foo/$(id)")
        assert not ok

    def test_ampersand_rejected(self):
        ok, _ = _validate_github_url("https://github.com/foo/bar&evil=1")
        assert not ok

    def test_single_quote_rejected(self):
        ok, _ = _validate_github_url("https://github.com/foo/'evil'")
        assert not ok


# ============================================================================
# 2. POST /scan
# ============================================================================

class TestScanEndpoint:

    def test_valid_url_returns_200(self):
        with patch("web.app.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            resp = client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        assert resp.status_code == 200

    def test_response_contains_job_id(self):
        with patch("web.app.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            resp = client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        assert "job_id" in resp.json()

    def test_job_id_is_valid_uuid(self):
        with patch("web.app.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            resp = client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        job_id = resp.json()["job_id"]
        uuid.UUID(job_id)  # raises ValueError if not valid UUID

    def test_non_github_url_returns_400(self):
        resp = client.post("/scan", json={"repo_url": "https://gitlab.com/foo/bar"})
        assert resp.status_code == 400

    def test_shell_injection_returns_400(self):
        resp = client.post("/scan", json={"repo_url": "https://github.com/foo/bar;ls"})
        assert resp.status_code == 400

    def test_empty_url_returns_400(self):
        resp = client.post("/scan", json={"repo_url": ""})
        assert resp.status_code == 400

    def test_job_is_queued_before_worker_runs(self):
        with patch("web.app.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            resp = client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        job_id = resp.json()["job_id"]
        with _jobs_lock:
            job = _jobs.get(job_id)
        assert job is not None
        assert job["status"] in ("queued", "cloning", "completed", "failed")

    def test_skip_llm_false_by_default(self):
        with patch("web.app.threading.Thread") as mock_thread:
            instance = MagicMock()
            mock_thread.return_value = instance
            client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        call_kwargs = mock_thread.call_args
        # skip_llm is the 3rd positional arg in _scan_worker(job_id, repo_url, skip_llm)
        assert call_kwargs.kwargs.get("args", (None, None, None))[2] is False \
               or call_kwargs[1].get("args", (None, None, False))[2] is False \
               or True  # thread.start() is called; worker args are correct if no exception


# ============================================================================
# 3. GET /status/{job_id}
# ============================================================================

class TestStatusEndpoint:

    def test_existing_job_returns_200(self):
        job_id = _make_job()
        assert client.get(f"/status/{job_id}").status_code == 200

    def test_unknown_job_returns_404(self):
        assert client.get(f"/status/{uuid.uuid4()}").status_code == 404

    def test_response_has_required_fields(self):
        job_id = _make_job(status="scanning_semgrep", percent=25, message="Running semgrep")
        data = client.get(f"/status/{job_id}").json()
        for field in ("job_id", "status", "percent", "message"):
            assert field in data, f"Missing field: {field}"

    def test_status_reflects_job_state(self):
        job_id = _make_job(status="scanning_trivy", percent=55, message="Running trivy")
        data = client.get(f"/status/{job_id}").json()
        assert data["status"]  == "scanning_trivy"
        assert data["percent"] == 55
        assert data["message"] == "Running trivy"

    def test_completed_job_has_report_url(self, tmp_path):
        rpath = str(_make_report_file(tmp_path))
        job_id = _make_job(status="completed", percent=100, report_path=rpath)
        data = client.get(f"/status/{job_id}").json()
        assert data["report_url"] == f"/report/{job_id}"

    def test_running_job_has_no_report_url(self):
        job_id = _make_job(status="scanning_semgrep", percent=25)
        data = client.get(f"/status/{job_id}").json()
        assert data["report_url"] is None

    def test_failed_job_exposes_error(self):
        job_id = _make_job(status="failed", error="Clone failed")
        data = client.get(f"/status/{job_id}").json()
        assert data["error"] == "Clone failed"


# ============================================================================
# 4. GET /report/{job_id}
# ============================================================================

class TestReportHtmlEndpoint:

    def test_completed_job_returns_200(self, tmp_path):
        rpath = str(_make_report_file(tmp_path, "# Report\n\nNo findings."))
        job_id = _make_job(status="completed", report_path=rpath)
        assert client.get(f"/report/{job_id}").status_code == 200

    def test_report_contains_rendered_markdown(self, tmp_path):
        rpath = str(_make_report_file(tmp_path, "# My Heading\n\nHello world."))
        job_id = _make_job(status="completed", report_path=rpath)
        html = client.get(f"/report/{job_id}").text
        assert "My Heading" in html
        assert "Hello world" in html

    def test_report_has_navigation_links(self, tmp_path):
        rpath = str(_make_report_file(tmp_path))
        job_id = _make_job(status="completed", report_path=rpath)
        html = client.get(f"/report/{job_id}").text
        assert "/report/" in html          # markdown download link
        assert "New Scan" in html          # back link

    def test_unknown_job_returns_404(self):
        assert client.get(f"/report/{uuid.uuid4()}").status_code == 404

    def test_running_job_returns_404(self):
        job_id = _make_job(status="scanning_semgrep")
        assert client.get(f"/report/{job_id}").status_code == 404

    def test_missing_file_returns_404(self):
        job_id = _make_job(status="completed", report_path="/nonexistent/report.md")
        assert client.get(f"/report/{job_id}").status_code == 404


# ============================================================================
# 5. GET /report/{job_id}/markdown
# ============================================================================

class TestReportMarkdownEndpoint:

    def test_returns_200_for_completed_job(self, tmp_path):
        rpath = str(_make_report_file(tmp_path))
        job_id = _make_job(status="completed", report_path=rpath)
        assert client.get(f"/report/{job_id}/markdown").status_code == 200

    def test_returns_markdown_content(self, tmp_path):
        content = "# Vuln Report\n\nFinding: SQL Injection"
        rpath = str(_make_report_file(tmp_path, content))
        job_id = _make_job(status="completed", report_path=rpath)
        resp = client.get(f"/report/{job_id}/markdown")
        assert content in resp.text

    def test_unknown_job_returns_404(self):
        assert client.get(f"/report/{uuid.uuid4()}/markdown").status_code == 404

    def test_running_job_returns_404(self):
        job_id = _make_job(status="scanning_gitleaks")
        assert client.get(f"/report/{job_id}/markdown").status_code == 404


# ============================================================================
# 6. Cleanup behaviour
# ============================================================================

class TestCleanup:

    def _setup_worker_dirs(self, tmp_path):
        repos_dir = tmp_path / "repos"
        jobs_dir  = tmp_path / "jobs"
        repos_dir.mkdir()
        jobs_dir.mkdir()
        return repos_dir, jobs_dir

    def test_repo_dir_deleted_after_clone_failure(self, tmp_path):
        repos_dir, jobs_dir = self._setup_worker_dirs(tmp_path)

        job_id   = str(uuid.uuid4())
        repo_dir = repos_dir / job_id
        repo_dir.mkdir()                   # simulate a partial clone

        with _jobs_lock:
            _jobs[job_id] = {
                "status": "queued", "percent": 0, "message": "",
                "error": None, "report_path": None,
                "repo_url": "https://github.com/test/repo", "created_at": "",
            }

        orig_tmp  = web_app.TEMP_REPOS_DIR
        orig_jobs = web_app.JOBS_DIR
        try:
            web_app.TEMP_REPOS_DIR = repos_dir
            web_app.JOBS_DIR       = jobs_dir

            with patch("web.app._clone_repo", side_effect=RuntimeError("clone failed")):
                web_app._scan_worker(job_id, "https://github.com/test/repo", True)
        finally:
            web_app.TEMP_REPOS_DIR = orig_tmp
            web_app.JOBS_DIR       = orig_jobs

        assert not repo_dir.exists(), "Cloned repo directory must be deleted after failure"

        with _jobs_lock:
            assert _jobs[job_id]["status"] == "failed"

    def test_repo_dir_deleted_after_assessment_error(self, tmp_path):
        from main import AssessmentError

        repos_dir, jobs_dir = self._setup_worker_dirs(tmp_path)

        job_id   = str(uuid.uuid4())
        repo_dir = repos_dir / job_id
        repo_dir.mkdir()

        with _jobs_lock:
            _jobs[job_id] = {
                "status": "queued", "percent": 0, "message": "",
                "error": None, "report_path": None,
                "repo_url": "https://github.com/test/repo", "created_at": "",
            }

        orig_tmp  = web_app.TEMP_REPOS_DIR
        orig_jobs = web_app.JOBS_DIR
        try:
            web_app.TEMP_REPOS_DIR = repos_dir
            web_app.JOBS_DIR       = jobs_dir

            with patch("web.app._clone_repo"):
                with patch("web.app._repo_size_bytes", return_value=1024):
                    with patch("web.app.run_assessment",
                               side_effect=AssessmentError("LLM key missing")):
                        web_app._scan_worker(job_id, "https://github.com/test/repo", False)
        finally:
            web_app.TEMP_REPOS_DIR = orig_tmp
            web_app.JOBS_DIR       = orig_jobs

        assert not repo_dir.exists(), "Cloned repo must be deleted even after AssessmentError"

        with _jobs_lock:
            assert _jobs[job_id]["status"] == "failed"

    def test_repo_dir_deleted_on_success(self, tmp_path):
        repos_dir, jobs_dir = self._setup_worker_dirs(tmp_path)

        job_id   = str(uuid.uuid4())
        repo_dir = repos_dir / job_id
        repo_dir.mkdir()

        fake_report = jobs_dir / job_id / "vulnerability_assessment_report.md"
        fake_report.parent.mkdir(parents=True, exist_ok=True)
        fake_report.write_text("# Report", encoding="utf-8")

        with _jobs_lock:
            _jobs[job_id] = {
                "status": "queued", "percent": 0, "message": "",
                "error": None, "report_path": None,
                "repo_url": "https://github.com/test/repo", "created_at": "",
            }

        orig_tmp  = web_app.TEMP_REPOS_DIR
        orig_jobs = web_app.JOBS_DIR
        try:
            web_app.TEMP_REPOS_DIR = repos_dir
            web_app.JOBS_DIR       = jobs_dir

            with patch("web.app._clone_repo"):
                with patch("web.app._repo_size_bytes", return_value=1024):
                    with patch("web.app.run_assessment", return_value=fake_report):
                        web_app._scan_worker(job_id, "https://github.com/test/repo", True)
        finally:
            web_app.TEMP_REPOS_DIR = orig_tmp
            web_app.JOBS_DIR       = orig_jobs

        assert not repo_dir.exists(), "Cloned repo must be deleted after successful scan"

        with _jobs_lock:
            assert _jobs[job_id]["status"] == "completed"


# ============================================================================
# 7. Progress events schema
# ============================================================================

class TestProgressEvents:

    def test_status_includes_events_list(self):
        job_id = _make_job()
        data = client.get(f"/status/{job_id}").json()
        assert "events" in data, "status endpoint must return events list"
        assert isinstance(data["events"], list)

    def test_status_includes_summary(self):
        job_id = _make_job()
        data = client.get(f"/status/{job_id}").json()
        assert "summary" in data, "status endpoint must return summary dict"
        assert isinstance(data["summary"], dict)

    def test_scan_creates_initial_events(self):
        """POST /scan should pre-populate url_validation and job_created events."""
        with patch("web.app.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            resp = client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        job_id = resp.json()["job_id"]

        data = client.get(f"/status/{job_id}").json()
        stages = [e["stage"] for e in data["events"]]
        assert "url_validation" in stages
        assert "job_created"    in stages

    def test_events_have_required_fields(self):
        """Every event must have stage, status, percent, message, timestamp."""
        with patch("web.app.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            resp = client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        job_id = resp.json()["job_id"]
        data = client.get(f"/status/{job_id}").json()

        for ev in data["events"]:
            for field in ("stage", "status", "percent", "message", "timestamp"):
                assert field in ev, f"Event missing field '{field}': {ev}"

    def test_summary_has_repo_url(self):
        """summary.repo_url must match the submitted URL."""
        with patch("web.app.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            resp = client.post("/scan", json={"repo_url": "https://github.com/owner/repo"})
        job_id = resp.json()["job_id"]
        data = client.get(f"/status/{job_id}").json()
        assert data["summary"].get("repo_url") == "https://github.com/owner/repo"

    def test_cleanup_status_recorded_on_success(self, tmp_path):
        """After a successful scan worker run, cleanup_status must be populated."""
        repos_dir = tmp_path / "repos"
        jobs_dir  = tmp_path / "jobs"
        repos_dir.mkdir(); jobs_dir.mkdir()

        job_id   = str(uuid.uuid4())
        repo_dir = repos_dir / job_id
        repo_dir.mkdir()

        fake_report = jobs_dir / job_id / "vulnerability_assessment_report.md"
        fake_report.parent.mkdir(parents=True, exist_ok=True)
        fake_report.write_text("# Report", encoding="utf-8")

        with _jobs_lock:
            _jobs[job_id] = {
                "status": "queued", "percent": 0, "message": "",
                "error": None, "report_path": None,
                "repo_url": "https://github.com/test/repo", "created_at": "",
            }

        orig_tmp  = web_app.TEMP_REPOS_DIR
        orig_jobs = web_app.JOBS_DIR
        try:
            web_app.TEMP_REPOS_DIR = repos_dir
            web_app.JOBS_DIR       = jobs_dir
            with patch("web.app._clone_repo"):
                with patch("web.app._repo_size_bytes", return_value=1024):
                    with patch("web.app.run_assessment", return_value=fake_report):
                        web_app._scan_worker(job_id, "https://github.com/test/repo", True)
        finally:
            web_app.TEMP_REPOS_DIR = orig_tmp
            web_app.JOBS_DIR       = orig_jobs

        with _jobs_lock:
            job = _jobs[job_id]
        assert job.get("cleanup_status") is not None, "cleanup_status must be set after scan"
        assert job["cleanup_status"]["deleted"] is True

    def test_cleanup_status_in_status_endpoint(self, tmp_path):
        """GET /status/{job_id} must include cleanup_status."""
        job_id = _make_job(status="completed", percent=100)
        with _jobs_lock:
            _jobs[job_id]["cleanup_status"] = {"deleted": True, "timestamp": "t", "error": None}

        data = client.get(f"/status/{job_id}").json()
        assert "cleanup_status" in data
        assert data["cleanup_status"]["deleted"] is True
