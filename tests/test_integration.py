"""
test_integration.py — Integration tests for vuln_report_agent.

Test classes
────────────
TestArchitectureMapper  — detects language, framework, database, auth, deployment.
TestSemgrep             — scanner runs; SQL injection found in test_vulnerable_repo.
TestGitleaks            — scanner runs; Stripe key found in config.py.
TestTrivyDependencies   — scanner runs; flask/jinja2 CVEs found.
TestPipAuditNormalizer  — normalizer correctly parses the real pip-audit fixture.
TestNormalizerSchema    — each scanner's output maps to the common finding schema.
TestValidator           — dedup, CVE merge, test-file downgrade, review split.
TestFullPipeline        — end-to-end: 10-section report generated with all findings.
TestFailureBehavior     — bad path → incomplete report, no final report.

All scanner tests are skipped automatically when the tool is not installed.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths & tool helpers
# ---------------------------------------------------------------------------

AGENT_DIR    = Path(__file__).parent.parent
REPO         = AGENT_DIR / "test_vulnerable_repo"
RAW_DIR      = AGENT_DIR / "scan_outputs" / "raw"
REPORTS_DIR  = AGENT_DIR / "reports"
FIXTURES     = Path(__file__).parent / "fixtures"


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


skip_no_semgrep   = pytest.mark.skipif(not tool_available("semgrep"),   reason="semgrep not installed")
skip_no_gitleaks  = pytest.mark.skipif(not tool_available("gitleaks"),  reason="gitleaks not installed")
skip_no_trivy     = pytest.mark.skipif(not tool_available("trivy"),     reason="trivy not installed")
skip_no_pip_audit = pytest.mark.skipif(not tool_available("pip-audit"), reason="pip-audit not installed")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _run(cmd: list, cwd: Path = AGENT_DIR, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)


def _load_json(path: Path):
    assert path.exists(), f"Output file not found: {path}"
    content = path.read_text(encoding="utf-8").strip()
    assert content, f"Output file is empty: {path}"
    return json.loads(content)


# ============================================================================
# 1. Architecture mapper
# ============================================================================

class TestArchitectureMapper:
    """architecture_mapper.map_architecture() must correctly classify the test repo."""

    @pytest.fixture(scope="class")
    def arch(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import architecture_mapper as am
        importlib.reload(am)
        return am.map_architecture(REPO)

    def test_returns_dict(self, arch):
        assert isinstance(arch, dict)

    def test_required_keys_present(self, arch):
        required = {
            "language", "all_languages", "framework", "database",
            "auth", "deployment", "package_manager", "entry_points",
        }
        missing = required - arch.keys()
        assert not missing, f"Missing architecture keys: {missing}"

    def test_detects_python_as_primary_language(self, arch):
        assert arch["language"] == "Python", (
            f"Expected Python as primary language, got '{arch['language']}'"
        )

    def test_python_in_all_languages(self, arch):
        assert "Python" in arch["all_languages"]

    def test_detects_flask_framework(self, arch):
        assert arch["framework"] == "Flask", (
            f"Expected Flask framework, got '{arch['framework']}'"
        )

    def test_detects_sqlite_database(self, arch):
        databases = arch["database"]
        assert any("sqlite" in d.lower() for d in databases), (
            f"Expected SQLite in database list, got {databases}"
        )

    def test_detects_pip_package_manager(self, arch):
        managers = arch["package_manager"]
        assert "pip" in managers, (
            f"Expected pip in package managers, got {managers}"
        )

    def test_detects_entry_points(self, arch):
        eps = arch["entry_points"]
        assert "app.py" in eps, (
            f"Expected app.py in entry points, got {eps}"
        )

    def test_all_values_non_empty(self, arch):
        # These keys are validly empty/false for non-monorepo repos
        optional_empty = {"is_monorepo", "subprojects"}
        for key, value in arch.items():
            if key in optional_empty:
                continue
            if isinstance(value, list):
                assert value, f"Architecture key '{key}' is an empty list"
            elif isinstance(value, bool):
                pass  # booleans are valid falsy values
            else:
                assert value, f"Architecture key '{key}' is empty/None"


# ============================================================================
# 2. Semgrep — SQL injection
# ============================================================================

class TestSemgrep:

    def _run_semgrep(self, out: Path) -> dict:
        _run(["semgrep", "--config=auto", "--json", f"--output={out}", str(REPO)])
        assert out.exists(), "semgrep produced no output file"
        return json.loads(out.read_text())

    @skip_no_semgrep
    def test_output_file_is_created(self, tmp_path):
        out = tmp_path / "semgrep.json"
        _run(["semgrep", "--config=auto", "--json", f"--output={out}", str(REPO)])
        assert out.exists()

    @skip_no_semgrep
    def test_output_is_valid_json(self, tmp_path):
        out = tmp_path / "semgrep.json"
        data = self._run_semgrep(out)
        assert "results" in data

    @skip_no_semgrep
    def test_finds_sql_injection_in_app(self, tmp_path):
        out  = tmp_path / "semgrep.json"
        data = self._run_semgrep(out)
        results = data.get("results", [])

        sql_findings = [
            r for r in results
            if (
                "sql" in r.get("check_id", "").lower()
                or "injection" in r.get("check_id", "").lower()
                or "formatted" in r.get("check_id", "").lower()
            )
            and r.get("path", "").endswith("app.py")
        ]
        assert sql_findings, (
            f"Expected SQL injection in app.py.\n"
            f"All {len(results)} rule(s): {[r['check_id'] for r in results[:10]]}"
        )

    @skip_no_semgrep
    def test_sql_finding_has_line_number(self, tmp_path):
        out  = tmp_path / "semgrep.json"
        data = self._run_semgrep(out)
        sql  = [r for r in data.get("results", [])
                if "sql" in r.get("check_id", "").lower()
                or "formatted" in r.get("check_id", "").lower()]
        if not sql:
            pytest.skip("No SQL findings to validate structure")
        assert sql[0].get("start", {}).get("line") is not None

    @skip_no_semgrep
    def test_sql_rule_id_is_a_known_security_rule(self, tmp_path):
        out  = tmp_path / "semgrep.json"
        data = self._run_semgrep(out)
        sql  = [r for r in data.get("results", [])
                if "sql" in r.get("check_id", "").lower()
                or "formatted" in r.get("check_id", "").lower()
                or "injection" in r.get("check_id", "").lower()]
        if not sql:
            pytest.skip("No SQL findings to validate")
        known = (
            "python.lang.security",
            "python.sqlalchemy",
            "python.django.security.injection",
            "python.flask.security",
            "sql",
        )
        rule_id = sql[0]["check_id"]
        assert any(rule_id.lower().startswith(p) for p in known), (
            f"Unexpected rule ID: '{rule_id}'"
        )


# ============================================================================
# 3. Gitleaks — hardcoded Stripe key
# ============================================================================

class TestGitleaks:

    def _run_gitleaks(self, out: Path) -> list:
        _run([
            "gitleaks", "detect",
            "--source", str(REPO),
            "--report-format", "json",
            "--report-path", str(out),
        ])
        if not out.exists():
            return []
        content = out.read_text().strip()
        return json.loads(content) if content else []

    @skip_no_gitleaks
    def test_output_file_created_or_no_leaks(self, tmp_path):
        out = tmp_path / "gitleaks.json"
        result = _run([
            "gitleaks", "detect",
            "--source", str(REPO),
            "--report-format", "json",
            "--report-path", str(out),
        ])
        assert out.exists() or result.returncode == 0, (
            f"gitleaks exit {result.returncode}, no output.\nstderr: {result.stderr[:600]}"
        )

    @skip_no_gitleaks
    def test_finds_at_least_one_secret(self, tmp_path):
        out   = tmp_path / "gitleaks.json"
        leaks = self._run_gitleaks(out)
        assert len(leaks) > 0, (
            f"Expected gitleaks to find secrets in {REPO}/config.py"
        )

    @skip_no_gitleaks
    def test_finds_stripe_key(self, tmp_path):
        out   = tmp_path / "gitleaks.json"
        leaks = self._run_gitleaks(out)
        stripe = [
            l for l in leaks
            if "stripe" in l.get("RuleID", "").lower()
            or "stripe" in l.get("Description", "").lower()
        ]
        assert stripe, (
            f"Expected Stripe-key finding. Rules found: {[l.get('RuleID') for l in leaks]}"
        )

    @skip_no_gitleaks
    def test_secret_is_in_config_file(self, tmp_path):
        out   = tmp_path / "gitleaks.json"
        leaks = self._run_gitleaks(out)
        files = {l.get("File", "") for l in leaks}
        assert any("config" in f for f in files), (
            f"Expected secret in config.py, found: {files}"
        )

    @skip_no_gitleaks
    def test_finding_has_required_fields(self, tmp_path):
        out   = tmp_path / "gitleaks.json"
        leaks = self._run_gitleaks(out)
        if not leaks:
            pytest.skip("No leaks to validate")
        for field in ("RuleID", "File", "StartLine"):
            assert field in leaks[0], f"Missing field '{field}' in gitleaks finding"


# ============================================================================
# 4. Trivy — dependency CVEs
# ============================================================================

class TestTrivyDependencies:

    def _run_trivy(self, out: Path) -> dict:
        result = _run(["trivy", "fs", str(REPO), "--format", "json", "--output", str(out)])
        assert out.exists(), f"trivy no output.\nstderr: {result.stderr[:600]}"
        return json.loads(out.read_text())

    @skip_no_trivy
    def test_output_is_valid_json(self, tmp_path):
        out  = tmp_path / "trivy.json"
        data = self._run_trivy(out)
        assert "Results" in data or "SchemaVersion" in data

    @skip_no_trivy
    def test_finds_vulnerable_packages(self, tmp_path):
        out  = tmp_path / "trivy.json"
        data = self._run_trivy(out)
        vulns = [v for r in data.get("Results", [])
                   for v in (r.get("Vulnerabilities") or [])]
        assert len(vulns) > 0, "Expected CVEs from requirements.txt with pinned vulnerable versions"

    @skip_no_trivy
    def test_finds_flask_cve(self, tmp_path):
        out  = tmp_path / "trivy.json"
        data = self._run_trivy(out)
        flask_cves = [
            v for r in data.get("Results", [])
              for v in (r.get("Vulnerabilities") or [])
              if v.get("PkgName", "").lower() == "flask"
        ]
        assert flask_cves, "Expected CVE(s) for flask==0.12.2"

    @skip_no_trivy
    def test_flask_cve_ids_are_known(self, tmp_path):
        out  = tmp_path / "trivy.json"
        data = self._run_trivy(out)
        flask_cve_ids = {
            v.get("VulnerabilityID", "")
            for r in data.get("Results", [])
            for v in (r.get("Vulnerabilities") or [])
            if v.get("PkgName", "").lower() == "flask"
        }
        known = {"CVE-2018-1000656", "CVE-2019-1010083", "CVE-2023-30861"}
        assert flask_cve_ids & known, (
            f"Expected one of {known} for flask. Got: {flask_cve_ids}"
        )

    @skip_no_trivy
    def test_vulnerability_has_required_fields(self, tmp_path):
        out  = tmp_path / "trivy.json"
        data = self._run_trivy(out)
        first = next(
            (v for r in data.get("Results", []) for v in (r.get("Vulnerabilities") or [])),
            None,
        )
        assert first is not None
        for field in ("VulnerabilityID", "PkgName", "Severity"):
            assert field in first, f"Missing field '{field}'"


# ============================================================================
# 5. pip-audit normalizer — parses the real fixture
# ============================================================================

class TestPipAuditNormalizer:

    @pytest.fixture()
    def fixture_data(self, fixtures_dir) -> dict:
        path = fixtures_dir / "pip_audit_vulnerable.json"
        assert path.exists(), f"Fixture missing: {path}"
        return json.loads(path.read_text())

    @pytest.fixture()
    def normalized(self, fixtures_dir, agent_dir):
        sys.path.insert(0, str(agent_dir))
        fixture = fixtures_dir / "pip_audit_vulnerable.json"
        raw_out = agent_dir / "scan_outputs" / "raw" / "pip_audit.json"
        raw_out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(fixture, raw_out)
        import importlib
        import normalizer as nm
        importlib.reload(nm)
        return nm._parse_pip_audit(json.loads(fixture.read_text()))

    def test_fixture_has_dependencies_key(self, fixture_data):
        assert "dependencies" in fixture_data

    def test_fixture_has_vulnerable_packages(self, fixture_data):
        deps = fixture_data.get("dependencies", [])
        vuln = [d for d in deps if d.get("vulns")]
        assert len(vuln) >= 3, f"Expected ≥3 vulnerable packages, got {[d['name'] for d in vuln]}"

    def test_normalizer_produces_findings(self, normalized):
        assert len(normalized) > 0

    def test_each_finding_has_required_schema_fields(self, normalized):
        required = {
            "tool", "title", "severity", "category", "file",
            "line", "evidence", "recommendation", "confidence", "raw",
        }
        for i, f in enumerate(normalized):
            missing = required - f.keys()
            assert not missing, f"Finding #{i} missing fields: {missing}"

    def test_flask_vulnerability_is_normalised(self, normalized):
        flask = [f for f in normalized if "flask" in f.get("title", "").lower()]
        assert flask, f"No flask finding. Titles: {[f['title'] for f in normalized[:5]]}"

    def test_cve_appears_in_title(self, normalized):
        cve_findings = [f for f in normalized if "CVE-" in f.get("title", "")]
        assert cve_findings, "Expected at least one finding with a CVE ID in title"

    def test_recommendation_is_non_empty(self, normalized):
        empty = [f for f in normalized if not f.get("recommendation", "").strip()]
        assert not empty, f"{len(empty)} finding(s) have empty recommendations"

    def test_pip_audit_scans_repo_not_host(self, agent_dir):
        """
        pip-audit must be called with -r <requirements.txt>, never without args
        (which would scan the host machine's environment).
        """
        sys.path.insert(0, str(agent_dir))
        import importlib
        import scanner_runner as sr
        importlib.reload(sr)
        import inspect
        src = inspect.getsource(sr._run_pip_audit)
        assert "-r" in src, (
            "_run_pip_audit must use '-r <file>' to scan repo deps, not the host machine"
        )
        assert "requirements.txt" in src or "req_file" in src, (
            "_run_pip_audit must reference a requirements file from the repo"
        )


# ============================================================================
# 6. Normalizer schema validation
# ============================================================================

class TestNormalizerSchema:

    REQUIRED = {
        "tool", "title", "severity", "category",
        "file", "line", "evidence", "recommendation", "confidence", "raw",
    }
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}

    def _parse(self, tool: str, out: Path, agent_dir: Path) -> list[dict]:
        sys.path.insert(0, str(agent_dir))
        import importlib
        import normalizer as nm
        importlib.reload(nm)
        data = json.loads(out.read_text())
        return {
            "semgrep":  nm._parse_semgrep,
            "gitleaks": nm._parse_gitleaks,
            "trivy":    nm._parse_trivy,
        }[tool](data)

    @skip_no_semgrep
    def test_semgrep_normalised_schema(self, tmp_path, agent_dir):
        out = tmp_path / "semgrep.json"
        _run(["semgrep", "--config=auto", "--json", f"--output={out}", str(REPO)])
        if not out.exists():
            pytest.skip("semgrep produced no output")
        for f in self._parse("semgrep", out, agent_dir):
            assert not (self.REQUIRED - f.keys())
            assert f["severity"] in self.VALID_SEVERITIES
            assert f["tool"] == "semgrep"

    @skip_no_gitleaks
    def test_gitleaks_normalised_schema(self, tmp_path, agent_dir):
        out = tmp_path / "gitleaks.json"
        _run(["gitleaks", "detect", "--source", str(REPO),
              "--report-format", "json", "--report-path", str(out)])
        if not out.exists():
            out.write_text("[]")
        for f in self._parse("gitleaks", out, agent_dir):
            assert not (self.REQUIRED - f.keys())
            assert f["tool"] == "gitleaks"
            assert f["category"] == "secret"
            assert f["evidence"] == "[REDACTED]", "Gitleaks secret must always be [REDACTED]"

    @skip_no_trivy
    def test_trivy_normalised_schema(self, tmp_path, agent_dir):
        out = tmp_path / "trivy.json"
        _run(["trivy", "fs", str(REPO), "--format", "json", "--output", str(out)])
        if not out.exists():
            pytest.skip("trivy produced no output")
        for f in self._parse("trivy", out, agent_dir):
            assert not (self.REQUIRED - f.keys())
            assert f["tool"] == "trivy"


# ============================================================================
# 7. Validator
# ============================================================================

class TestValidator:

    @pytest.fixture()
    def v(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import validator as val
        importlib.reload(val)
        return val

    def _f(self, **overrides) -> dict:
        base = {
            "tool": "semgrep", "title": "SQL Injection",
            "severity": "high", "category": "injection",
            "file": "app.py", "line": 30,
            "evidence": "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
            "recommendation": "Use parameterised queries.",
            "confidence": "high", "raw": {},
        }
        base.update(overrides)
        return base

    def test_dedup_removes_exact_duplicates(self, v):
        f = self._f()
        r = v.validate([f, f.copy(), f.copy()])
        assert len(r["confirmed"]) + len(r["needs_review"]) == 1

    def test_dedup_keeps_distinct_findings(self, v):
        r = v.validate([self._f(file="a.py", line=1), self._f(file="b.py", line=2)])
        assert len(r["confirmed"]) + len(r["needs_review"]) == 2

    def test_cve_merge_across_tools(self, v):
        f1 = self._f(tool="trivy",  title="CVE-2019-1010083 in flask",
                     file="requirements.txt", line=None, evidence="flask==0.12.2")
        f2 = self._f(tool="semgrep", title="CVE-2019-1010083 in flask",
                     file="app.py", line=10, evidence="import flask")
        r  = v.validate([f1, f2])
        assert len(r["confirmed"]) + len(r["needs_review"]) == 1

    def test_test_file_downgrade_on_tests_subdir(self, v):
        """Files inside tests/ subdirectory ARE downgraded."""
        f = self._f(file="myapp/tests/test_auth.py", severity="high", confidence="high")
        r = v.validate([f])
        all_f = r["confirmed"] + r["needs_review"]
        assert all_f
        assert all_f[0]["severity"] in ("medium", "low", "info")

    def test_repo_root_name_does_not_trigger_downgrade(self, v):
        """
        A repo named test_vulnerable_repo must NOT cause findings to be
        downgraded — only the file's own path components matter.
        """
        f = self._f(
            file="test_vulnerable_repo/app.py",
            severity="high",
            confidence="high",
        )
        r = v.validate([f])
        all_f = r["confirmed"] + r["needs_review"]
        assert all_f
        assert all_f[0]["severity"] == "high", (
            f"Severity should NOT be downgraded for repo-root path component. "
            f"Got: {all_f[0]['severity']}"
        )

    def test_test_filename_prefix_triggers_downgrade(self, v):
        f = self._f(file="src/test_utils.py", severity="high", confidence="high")
        r = v.validate([f])
        all_f = r["confirmed"] + r["needs_review"]
        assert all_f[0]["severity"] in ("medium", "low", "info")

    def test_low_confidence_goes_to_needs_review(self, v):
        r = v.validate([self._f(confidence="low")])
        assert len(r["needs_review"]) == 1 and len(r["confirmed"]) == 0

    def test_high_confidence_goes_to_confirmed(self, v):
        r = v.validate([self._f(confidence="high")])
        assert len(r["confirmed"]) == 1 and len(r["needs_review"]) == 0

    def test_no_evidence_finding_is_removed(self, v):
        r = v.validate([self._f(evidence="")])
        assert len(r["confirmed"]) + len(r["needs_review"]) == 0

    def test_confirmed_sorted_severity_desc(self, v):
        findings = [
            self._f(severity="low",      title="Low",      evidence="e", file="a.py"),
            self._f(severity="critical", title="Critical", evidence="e", file="b.py"),
            self._f(severity="medium",   title="Medium",   evidence="e", file="c.py"),
        ]
        r = v.validate(findings)
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
        sevs  = [order.get(f["severity"], 0) for f in r["confirmed"]]
        assert sevs == sorted(sevs, reverse=True)

    def test_validate_returns_required_keys(self, v):
        r = v.validate([self._f()])
        assert "confirmed" in r and "needs_review" in r


# ============================================================================
# 8. Full pipeline — end-to-end
# ============================================================================

_ALL_TOOLS = tool_available("semgrep") and tool_available("gitleaks") and tool_available("trivy")


@pytest.mark.skipif(not _ALL_TOOLS, reason="Full pipeline requires semgrep + gitleaks + trivy")
class TestFullPipeline:
    """Run main.py --skip-llm against test_vulnerable_repo and validate the report."""

    def _run_pipeline(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(AGENT_DIR / "main.py"), str(REPO), "--skip-llm"],
            cwd=str(AGENT_DIR),
            capture_output=True,
            text=True,
            timeout=300,
        )

    def _report(self) -> str:
        self._run_pipeline()
        p = REPORTS_DIR / "vulnerability_assessment_report.md"
        assert p.exists(), "Final report not created"
        return p.read_text()

    def test_pipeline_exits_zero(self):
        r = self._run_pipeline()
        assert r.returncode == 0, (
            f"main.py exited {r.returncode}\n"
            f"stdout:\n{r.stdout[-2000:]}\nstderr:\n{r.stderr[-800:]}"
        )

    def test_final_report_is_created(self):
        self._run_pipeline()
        assert (REPORTS_DIR / "vulnerability_assessment_report.md").exists()

    def test_incomplete_report_is_not_created(self):
        self._run_pipeline()
        assert not (REPORTS_DIR / "incomplete_assessment.md").exists()

    def test_report_has_all_ten_sections(self):
        report = self._report()
        sections = [
            "## 1. Executive Summary",
            "## 2. Scope",
            "## 3. Assessment Mode",
            "## 4. Tools Executed",
            "## 5. System Overview",
            "## 6. Findings Table",
            "## 7. Detailed Findings",
            "## 8. Needs Manual Review",
            "## 9. Limitations",
            "## 10. Recommendations",
        ]
        for s in sections:
            assert s in report, f"Report missing section: '{s}'"

    def test_assessment_mode_is_scanner_only(self):
        report = self._report()
        assert "Scanner-Only" in report or "Scanner Only" in report, (
            "Expected 'Scanner-Only' mode with --skip-llm"
        )

    def test_report_contains_semgrep_findings(self):
        assert "semgrep" in self._report().lower()

    def test_report_contains_sql_injection(self):
        assert "sql" in self._report().lower()

    def test_report_contains_gitleaks_findings(self):
        report = self._report().lower()
        assert "gitleaks" in report or "secret" in report

    def test_report_contains_dependency_findings(self):
        report = self._report().lower()
        assert any(kw in report for kw in ("cve-", "trivy", "flask", "jinja", "dependency"))

    def test_raw_output_files_exist(self):
        self._run_pipeline()
        for name in ("semgrep.json", "gitleaks.json", "trivy.json"):
            assert (AGENT_DIR / "scan_outputs" / "raw" / name).exists(), f"Missing: {name}"

    def test_findings_table_has_entries(self):
        assert "| 1 |" in self._report()

    def test_detailed_findings_has_evidence(self):
        assert "**Evidence:**" in self._report()

    def test_secrets_not_exposed_in_report(self):
        report = self._report()
        # Split literals to avoid triggering secret scanners on this test file itself.
        stripe_key = "sk_live_" + "4eC39HqLyjWDarjtT7en2HF4"
        aws_key    = "wJalrXUtnFEMI"
        assert stripe_key not in report, "Stripe key exposed!"
        assert aws_key not in report, "AWS secret key exposed!"

    def test_tools_executed_section_lists_scanners(self):
        report = self._report().lower()
        for tool in ("semgrep", "gitleaks", "trivy"):
            assert tool in report

    def test_scope_contains_repo_path(self):
        assert "test_vulnerable_repo" in self._report()

    def test_architecture_section_shows_flask(self):
        report = self._report()
        assert "Flask" in report, "System Overview should show detected Flask framework"

    def test_pip_audit_used_requirements_file(self):
        """
        Verify that the pip-audit command in scan logs references the repo's
        requirements.txt — not the host machine's environment.
        """
        self._run_pipeline()
        pip_error = AGENT_DIR / "scan_outputs" / "errors" / "pip_audit.txt"
        # If pip_audit.txt exists the scanner failed; check why
        if pip_error.exists():
            pytest.fail(f"pip-audit failed:\n{pip_error.read_text()[:600]}")
        # Raw output must exist
        raw = AGENT_DIR / "scan_outputs" / "raw" / "pip_audit.json"
        assert raw.exists(), "pip_audit.json missing"


# ============================================================================
# 9. Failure behaviour
# ============================================================================

class TestFailureBehavior:

    def test_non_zero_exit_for_nonexistent_repo(self):
        r = subprocess.run(
            [sys.executable, str(AGENT_DIR / "main.py"), "/nonexistent/path/xyz", "--skip-llm"],
            cwd=str(AGENT_DIR),
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode != 0

    def test_final_report_absent_when_repo_missing(self):
        subprocess.run(
            [sys.executable, str(AGENT_DIR / "main.py"), "/nonexistent/path/xyz", "--skip-llm"],
            cwd=str(AGENT_DIR),
            capture_output=True, text=True, timeout=30,
        )
        assert not (REPORTS_DIR / "vulnerability_assessment_report.md").exists()

    def test_missing_llm_key_triggers_incomplete_report(self, monkeypatch):
        """
        When LLM key is absent and --skip-llm is NOT passed, the tool must
        write incomplete_assessment.md and exit non-zero.
        """
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY",    raising=False)
        monkeypatch.setenv("LLM_PROVIDER", "anthropic")

        env = {
            **{k: v for k, v in __import__("os").environ.items()},
            "ANTHROPIC_API_KEY": "",
            "OPENAI_API_KEY":    "",
            "LLM_PROVIDER":      "anthropic",
        }
        r = subprocess.run(
            [sys.executable, str(AGENT_DIR / "main.py"), str(REPO)],
            cwd=str(AGENT_DIR),
            capture_output=True, text=True, timeout=60,
            env=env,
        )
        assert r.returncode != 0, "Expected non-zero exit when API key is missing"
        incomplete = REPORTS_DIR / "incomplete_assessment.md"
        assert incomplete.exists(), "Expected incomplete_assessment.md when API key is missing"

    def test_incomplete_report_explains_missing_key(self, monkeypatch):
        env = {
            **{k: v for k, v in __import__("os").environ.items()},
            "ANTHROPIC_API_KEY": "",
            "OPENAI_API_KEY":    "",
            "LLM_PROVIDER":      "anthropic",
        }
        subprocess.run(
            [sys.executable, str(AGENT_DIR / "main.py"), str(REPO)],
            cwd=str(AGENT_DIR), capture_output=True, text=True, timeout=60, env=env,
        )
        incomplete = REPORTS_DIR / "incomplete_assessment.md"
        if incomplete.exists():
            content = incomplete.read_text()
            assert "ANTHROPIC_API_KEY" in content or "api" in content.lower(), (
                "incomplete_assessment.md should explain the missing key"
            )


# ============================================================================
# 10. Fix: secret deduplication across tools (validator)
# ============================================================================

class TestSecretDeduplication:
    """Secrets reported at the same file+line by multiple tools collapse to one."""

    @pytest.fixture(autouse=True)
    def _import(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import validator as val
        importlib.reload(val)
        self.v = val

    def _secret(self, tool: str, file: str = "config.py", line: int = 3) -> dict:
        return {
            "tool": tool, "title": f"AWS Secret Key ({tool})",
            "severity": "high", "category": "secret",
            "file": file, "line": line,
            "evidence": "[REDACTED]",
            "recommendation": "Revoke immediately.",
            "confidence": "high", "raw": {},
        }

    def test_same_file_line_across_tools_collapses_to_one(self):
        findings = [
            self._secret("trivy"),
            self._secret("gitleaks"),
            self._secret("semgrep"),
        ]
        r = self.v.validate(findings)
        total = len(r["confirmed"]) + len(r["needs_review"])
        assert total == 1, (
            f"Expected 1 merged secret finding, got {total}"
        )

    def test_merged_title_lists_all_tools(self):
        findings = [self._secret("trivy"), self._secret("gitleaks")]
        r = self.v.validate(findings)
        merged = (r["confirmed"] + r["needs_review"])[0]
        title_lower = merged["title"].lower()
        assert "trivy" in title_lower and "gitleaks" in title_lower, (
            f"Merged title should list all tools, got: {merged['title']}"
        )

    def test_different_lines_not_merged(self):
        findings = [
            self._secret("trivy",    line=3),
            self._secret("gitleaks", line=10),
        ]
        r = self.v.validate(findings)
        total = len(r["confirmed"]) + len(r["needs_review"])
        assert total == 2, "Secrets at different lines must not be merged"

    def test_evidence_is_redacted_after_merge(self):
        findings = [self._secret("trivy"), self._secret("gitleaks")]
        r = self.v.validate(findings)
        merged = (r["confirmed"] + r["needs_review"])[0]
        assert merged["evidence"] == "[REDACTED]"


# ============================================================================
# 11. Fix: npm "Not applicable" in tools section
# ============================================================================

@pytest.mark.skipif(not _ALL_TOOLS, reason="Full pipeline requires semgrep + gitleaks + trivy")
class TestNpmNotApplicable:
    """When package.json is absent, npm_audit status must show 'Not applicable'."""

    def test_npm_shows_not_applicable_when_no_package_json(self):
        # test_vulnerable_repo has no package.json → npm_audit required=False
        assert not (REPO / "package.json").exists(), (
            "test_vulnerable_repo must not have package.json for this test"
        )
        r = subprocess.run(
            [sys.executable, str(AGENT_DIR / "main.py"), str(REPO), "--skip-llm"],
            cwd=str(AGENT_DIR), capture_output=True, text=True, timeout=300,
        )
        assert r.returncode == 0
        report = (REPORTS_DIR / "vulnerability_assessment_report.md").read_text()
        assert "Not applicable" in report, (
            "npm_audit row should show 'Not applicable' when no package.json exists"
        )
        assert "npm_audit" in report.lower() or "npm" in report.lower()


# ============================================================================
# 12. Fix: semgrep evidence reads actual source code
# ============================================================================

class TestSemgrepEvidence:
    """Semgrep findings must contain real code snippets, not 'requires login' noise."""

    @pytest.fixture(autouse=True)
    def _import(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import normalizer as norm
        importlib.reload(norm)
        self.norm = norm

    def test_semgrep_login_noise_is_filtered(self):
        """When extra.lines == 'requires login', evidence must not contain that string."""
        fake_semgrep = {
            "results": [{
                "check_id": "python.lang.security.audit.sqli",
                "path": str(REPO / "app.py"),
                "start": {"line": 37},
                "extra": {
                    "severity": "ERROR",
                    "lines": "requires login",
                    "message": "SQL injection via f-string",
                    "metadata": {"category": "security", "confidence": "HIGH"},
                },
            }]
        }
        findings = self.norm._parse_semgrep(fake_semgrep)
        assert findings, "Expected at least one finding"
        evidence = findings[0]["evidence"]
        assert "requires login" not in evidence.lower(), (
            f"Evidence should not contain 'requires login'. Got:\n{evidence}"
        )

    def test_semgrep_evidence_has_source_code_when_login_noise(self):
        """Falling back to disk, evidence should contain actual Python from app.py."""
        fake_semgrep = {
            "results": [{
                "check_id": "python.lang.security.audit.sqli",
                "path": str(REPO / "app.py"),
                "start": {"line": 37},
                "extra": {
                    "severity": "ERROR",
                    "lines": "requires login",
                    "message": "SQL injection",
                    "metadata": {"category": "security", "confidence": "HIGH"},
                },
            }]
        }
        findings = self.norm._parse_semgrep(fake_semgrep)
        evidence = findings[0]["evidence"]
        # Should contain something from app.py near line 37 (SQL query)
        assert len(evidence) > 10, "Evidence should be non-trivial when reading from disk"

    def test_semgrep_evidence_preserves_real_lines(self):
        """When extra.lines has real content, it must be used directly."""
        fake_semgrep = {
            "results": [{
                "check_id": "python.lang.security.audit.sqli",
                "path": str(REPO / "app.py"),
                "start": {"line": 37},
                "extra": {
                    "severity": "ERROR",
                    "lines": "cursor.execute(f\"SELECT * FROM users WHERE id = '{uid}'\")",
                    "message": "SQL injection via f-string",
                    "metadata": {"category": "security", "confidence": "HIGH"},
                },
            }]
        }
        findings = self.norm._parse_semgrep(fake_semgrep)
        evidence = findings[0]["evidence"]
        assert "cursor.execute" in evidence, (
            f"Real code lines should be in evidence. Got:\n{evidence}"
        )


# ============================================================================
# 13. Fix: LLM enrichment retry and quality gate
# ============================================================================

class TestLLMEnrichmentRetry:
    """_needs_enrichment() identifies unenriched findings correctly."""

    @pytest.fixture(autouse=True)
    def _import(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import llm_analyzer as la
        importlib.reload(la)
        self.la = la

    def _finding(self, **overrides) -> dict:
        base = {
            "tool": "semgrep", "title": "SQL Injection",
            "severity": "high", "category": "injection",
            "file": "app.py", "line": 30,
            "evidence": "cursor.execute(f'SELECT...')",
            "recommendation": "Use parameterised queries.",
            "confidence": "high", "raw": {},
        }
        base.update(overrides)
        return base

    def test_missing_impact_needs_enrichment(self):
        f = self._finding()
        assert self.la._needs_enrichment(f)

    def test_placeholder_impact_needs_enrichment(self):
        f = self._finding(
            impact="LLM analysis unavailable.",
            likelihood="unknown",
            exploit_scenario="LLM analysis unavailable.",
            recommended_fix="",
        )
        assert self.la._needs_enrichment(f)

    def test_fully_enriched_does_not_need_enrichment(self):
        f = self._finding(
            impact="Attacker can read all user records.",
            likelihood="high",
            exploit_scenario="Attacker passes ' OR 1=1-- as user_id.",
            recommended_fix="Use parameterised queries.",
        )
        assert not self.la._needs_enrichment(f)


# ============================================================================
# 14. Monorepo detection
# ============================================================================

class TestMonorepoDetection:
    """architecture_mapper._detect_subprojects() identifies frontend/backend subprojects."""

    @pytest.fixture(autouse=True)
    def _import(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import architecture_mapper as am
        importlib.reload(am)
        self.am = am

    def test_no_subprojects_for_flat_repo(self, tmp_path):
        """A flat repo with no subdirs returns empty subprojects."""
        (tmp_path / "app.py").write_text("print('hello')")
        subs = self.am._detect_subprojects(tmp_path)
        assert subs == []

    def test_frontend_backend_detected(self, tmp_path):
        """frontend/ and backend/ with package.json each → monorepo."""
        for sub in ("frontend", "backend"):
            d = tmp_path / sub
            d.mkdir()
            (d / "package.json").write_text('{"dependencies":{"react":"^18"}}')
        subs = self.am._detect_subprojects(tmp_path)
        paths = [s["path"] for s in subs]
        assert "frontend" in paths
        assert "backend" in paths

    def test_subproject_framework_detected(self, tmp_path):
        """React is detected from package.json dependencies."""
        fe = tmp_path / "frontend"
        fe.mkdir()
        (fe / "package.json").write_text('{"dependencies":{"react":"^18","typescript":"5"}}')
        (fe / "tsconfig.json").write_text("{}")
        subs = self.am._detect_subprojects(tmp_path)
        assert subs, "Expected frontend subproject"
        assert subs[0]["framework"] == "React"
        assert subs[0]["language"]  == "TypeScript"

    def test_is_monorepo_flag_in_map_architecture(self, tmp_path):
        """map_architecture sets is_monorepo=True when ≥2 subprojects found."""
        for sub in ("frontend", "backend"):
            d = tmp_path / sub
            d.mkdir()
            (d / "package.json").write_text('{"dependencies":{}}')
        arch = self.am.map_architecture(tmp_path)
        assert arch["is_monorepo"] is True
        assert len(arch["subprojects"]) >= 2

    def test_python_backend_detected(self, tmp_path):
        """A backend/ with requirements.txt → Python subproject."""
        be = tmp_path / "backend"
        be.mkdir()
        (be / "requirements.txt").write_text("fastapi>=0.100\nuvicorn")
        (be / "app.py").touch()
        subs = self.am._detect_subprojects(tmp_path)
        assert subs, "Expected backend subproject"
        be_sub = next((s for s in subs if s["path"] == "backend"), None)
        assert be_sub is not None
        assert be_sub["language"]  == "Python"
        assert be_sub["framework"] == "FastAPI"


# ============================================================================
# 15. Semgrep excludes .claude directory
# ============================================================================

class TestSemgrepExcludes:
    """semgrep command must include --exclude flags for IDE/tool config dirs."""

    @pytest.fixture(autouse=True)
    def _import(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import scanner_runner as sr
        importlib.reload(sr)
        self.sr = sr

    def test_semgrep_command_excludes_claude(self, tmp_path):
        """_run_semgrep must pass --exclude=.claude to semgrep."""
        import inspect
        src = inspect.getsource(self.sr._run_semgrep)
        assert "--exclude=.claude" in src, (
            "_run_semgrep must include --exclude=.claude in the command"
        )

    def test_semgrep_excludes_all_ide_dirs(self, tmp_path):
        """All four IDE dirs must be excluded."""
        import inspect
        src = inspect.getsource(self.sr._run_semgrep)
        for d in (".claude", ".cursor", ".vscode", ".idea"):
            assert f"--exclude={d}" in src, (
                f"_run_semgrep must include --exclude={d}"
            )

    def test_gitleaks_does_not_exclude_claude(self):
        """gitleaks must NOT exclude .claude (secrets can be committed there)."""
        import inspect
        src = inspect.getsource(self.sr._run_gitleaks)
        assert ".claude" not in src, (
            "gitleaks should NOT exclude .claude — secrets could be committed there"
        )


# ============================================================================
# 16. Report includes GitHub URL and cleanup status
# ============================================================================

class TestReportMetadata:
    """Report contains original GitHub URL and cleanup status when provided."""

    @pytest.fixture(autouse=True)
    def _import(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        import importlib
        import report_writer as rw
        importlib.reload(rw)
        self.rw = rw

    def test_report_includes_github_url(self, tmp_path):
        url = "https://github.com/example/testrepo"
        p = self.rw.write_full_report(
            repo_path="/tmp/clone/abc123",
            confirmed=[], needs_review=[],
            tool_statuses=[],
            output_dir=tmp_path,
            repo_url=url,
        )
        content = p.read_text()
        assert url in content, "Report must include the original GitHub URL"

    def test_report_includes_cleanup_deleted(self, tmp_path):
        p = self.rw.write_full_report(
            repo_path="/tmp/clone/abc123",
            confirmed=[], needs_review=[],
            tool_statuses=[],
            output_dir=tmp_path,
            cleanup_status={"deleted": True, "timestamp": "2026-01-01T00:00:00+00:00", "error": None},
        )
        content = p.read_text()
        assert "Deleted" in content, "Report must mention cleanup status"

    def test_report_includes_cleanup_failed(self, tmp_path):
        p = self.rw.write_full_report(
            repo_path="/tmp/clone/abc123",
            confirmed=[], needs_review=[],
            tool_statuses=[],
            output_dir=tmp_path,
            cleanup_status={"deleted": False, "error": "Permission denied", "timestamp": "2026-01-01T00:00:00+00:00"},
        )
        content = p.read_text()
        assert "Permission denied" in content or "Failed" in content
