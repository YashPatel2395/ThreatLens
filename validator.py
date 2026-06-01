"""
validator.py — Quality-gate the normalised finding list.

Pipeline:
  1. Deduplicate exact matches (tool + file + line + title).
  2. Merge findings that share the same CVE ID across different tools.
  3. Downgrade severity for findings whose SOURCE FILE is a test / fixture.
     ─ This is per-file, never per-repo-name. ─
     A file in test_vulnerable_repo/app.py is NOT a test file.
     A file in test_vulnerable_repo/tests/test_app.py IS a test file.
  4. Flag low-evidence findings as "Needs Manual Review".
  5. Remove findings with no evidence at all.

Returns {"confirmed": [...], "needs_review": [...]}, each sorted
by severity descending.
"""
import hashlib
import logging
import re
from copy import deepcopy
from pathlib import Path
from typing import Optional

from config import (
    TEST_DIR_NAMES,
    TEST_FILENAME_PREFIXES,
    TEST_FILENAME_SUFFIXES,
    TEST_FILENAMES_EXACT,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def _sev_order(sev: str) -> int:
    return _SEV_ORDER.get((sev or "").lower(), 0)


def _downgrade_severity(sev: str) -> str:
    ladder = ["unknown", "info", "low", "medium", "high", "critical"]
    try:
        idx = ladder.index(sev.lower())
        return ladder[max(0, idx - 1)]
    except ValueError:
        return sev


# ---------------------------------------------------------------------------
# Test-file detection
#
# IMPORTANT: we only check path components BELOW the repository root.
# The strategy: inspect every directory name in the path EXCEPT the first
# component (which is the repo root / drive root), so a repo named
# "test_vulnerable_repo" is never mistaken for a test directory.
# ---------------------------------------------------------------------------

def _is_test_file(file_path: str) -> bool:
    """
    Return True only when the specific file is a test / fixture / example.

    Rules:
      • A directory component below the repo root matches TEST_DIR_NAMES.
      • The filename starts with "test_", ends with "_test.py" / "_spec.py",
        or is an exact match in TEST_FILENAMES_EXACT.

    NOT triggered by:
      • The repository root directory name (e.g. "test_vulnerable_repo").
      • Any path that only contains "test" as a substring of a longer name.
    """
    p = Path(file_path)
    parts = p.parts

    # Check directory names — skip the very first component (repo root / drive).
    # Only flag directories with names that are unambiguously test containers.
    for part in parts[1:-1]:   # skip first (repo root) and last (filename)
        if part.lower() in TEST_DIR_NAMES:
            return True

    # Check filename
    name = p.name.lower()
    if any(name.startswith(pfx) for pfx in TEST_FILENAME_PREFIXES):
        return True
    if any(name.endswith(sfx) for sfx in TEST_FILENAME_SUFFIXES):
        return True
    if name in TEST_FILENAMES_EXACT:
        return True

    return False


# ---------------------------------------------------------------------------
# Step 1: Deduplicate
# ---------------------------------------------------------------------------

def _finding_key(f: dict) -> str:
    parts = [
        f.get("tool",  ""),
        f.get("file",  ""),
        str(f.get("line", "")),
        f.get("title", ""),
    ]
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        k = _finding_key(f)
        if k not in seen:
            seen.add(k)
            unique.append(f)
    removed = len(findings) - len(unique)
    if removed:
        log.info("Deduplication removed %d duplicate(s).", removed)
    return unique


# ---------------------------------------------------------------------------
# Step 2: Merge same CVE from different tools
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _extract_cve(title: str) -> Optional[str]:
    m = _CVE_RE.search(title or "")
    return m.group(0).upper() if m else None


def _merge_related(findings: list[dict]) -> list[dict]:
    """
    Merge findings that reference the same CVE across different tools.
    Keep the highest-severity instance; annotate with other tools that agreed.
    """
    cve_index: dict[str, list[int]] = {}
    for idx, f in enumerate(findings):
        cve = _extract_cve(f.get("title", ""))
        if cve:
            cve_index.setdefault(cve, []).append(idx)

    drop: set[int] = set()
    result = list(findings)

    for cve, indices in cve_index.items():
        if len(indices) < 2:
            continue
        # Keep the one with the highest severity
        primary_idx = max(indices, key=lambda i: _sev_order(findings[i].get("severity", "")))
        other_tools = [findings[i]["tool"] for i in indices if i != primary_idx]
        result[primary_idx]["evidence"] += (
            f" [Corroborated by: {', '.join(other_tools)}]"
        )
        for i in indices:
            if i != primary_idx:
                drop.add(i)
        log.info("Merged %d duplicate(s) of %s.", len(other_tools), cve)

    return [f for i, f in enumerate(result) if i not in drop]


# ---------------------------------------------------------------------------
# Step 2b: Merge duplicate secret findings across tools (same file + line)
# ---------------------------------------------------------------------------

def _merge_duplicate_secrets(findings: list[dict]) -> list[dict]:
    """
    When trivy, gitleaks, and semgrep all flag the same secret at the
    same file and line, collapse them into one finding that lists every
    contributing tool.

    Matching key: (normalised filename, line).  We normalise to the
    basename so that full-path vs relative-path differences don't prevent
    a match.
    """
    from collections import defaultdict

    # Index secrets by (basename, line)
    groups: dict[tuple, list[int]] = defaultdict(list)
    for idx, f in enumerate(findings):
        if f.get("category") == "secret":
            key = (Path(f.get("file", "")).name, str(f.get("line", "")))
            groups[key].append(idx)

    drop: set[int] = set()
    result = list(findings)

    for key, indices in groups.items():
        if len(indices) < 2:
            continue
        # Keep the highest-severity instance
        primary_idx = max(indices, key=lambda i: _sev_order(findings[i].get("severity", "")))
        all_tools   = list(dict.fromkeys(                      # dedup, preserve order
            findings[i]["tool"] for i in indices
        ))
        result[primary_idx]["tool"]     = " + ".join(all_tools)
        result[primary_idx]["evidence"] = "[REDACTED]"         # always safe
        result[primary_idx]["title"]    = (
            f"{result[primary_idx].get('title', 'Secret Detected')} "
            f"[detected by: {', '.join(all_tools)}]"
        )
        for i in indices:
            if i != primary_idx:
                drop.add(i)
        log.info(
            "Merged secret at %s:%s from tools: %s",
            key[0], key[1], ", ".join(all_tools),
        )

    return [f for i, f in enumerate(result) if i not in drop]


# ---------------------------------------------------------------------------
# Step 2c: Merge repeated curl-auth-header findings (same file, nearby lines)
# ---------------------------------------------------------------------------

def _merge_curl_auth_headers(findings: list[dict]) -> list[dict]:
    """
    Collapse repeated curl-auth-header / Authorization-header findings from
    the same file that appear within WINDOW lines of each other.

    These commonly arise when semgrep flags every HTTP call in the same file.
    The merged finding shows the first affected line and lists all others.
    """
    from collections import defaultdict

    WINDOW = 60

    def _is_curl_auth(f: dict) -> bool:
        title   = (f.get("title")   or "").lower()
        rule_id = (f.get("rule_id") or "").lower()
        return (
            ("curl" in title and ("auth" in title or "header" in title))
            or "curl-auth-header" in rule_id
            or "curl_auth_header" in rule_id
            or ("authorization" in title and "header" in title)
        )

    # Group curl-auth-header findings by file
    curl_by_file: dict[str, list[int]] = defaultdict(list)
    for idx, f in enumerate(findings):
        if _is_curl_auth(f):
            curl_by_file[f.get("file", "")].append(idx)

    drop: set[int] = set()
    result = list(findings)

    for file_path, indices in curl_by_file.items():
        if len(indices) < 2:
            continue

        # Sort by line number
        sorted_idx = sorted(indices, key=lambda i: (findings[i].get("line") or 0))

        # Cluster into groups within WINDOW lines
        clusters: list[list[int]] = []
        current: list[int] = [sorted_idx[0]]
        for i in sorted_idx[1:]:
            prev_line = findings[current[-1]].get("line") or 0
            curr_line = findings[i].get("line") or 0
            if abs(curr_line - prev_line) <= WINDOW:
                current.append(i)
            else:
                clusters.append(current)
                current = [i]
        clusters.append(current)

        for cluster in clusters:
            if len(cluster) < 2:
                continue
            # Keep the lowest-line (first occurring) instance as primary
            primary_idx = min(cluster, key=lambda i: (findings[i].get("line") or 0))
            all_lines   = sorted({findings[i].get("line") or 0 for i in cluster})
            all_tools   = list(dict.fromkeys(findings[i]["tool"] for i in cluster))

            if len(cluster) > 1:
                result[primary_idx]["title"] = (
                    result[primary_idx].get("title", "curl-auth-header")
                    + f" ({len(cluster)} occurrences)"
                )
            result[primary_idx]["evidence"] = (
                "[REDACTED] — Affected lines: " + ", ".join(str(l) for l in all_lines if l)
            )
            result[primary_idx]["tool"] = (
                " + ".join(all_tools) if len(set(all_tools)) > 1 else all_tools[0]
            )

            for i in cluster:
                if i != primary_idx:
                    drop.add(i)

            log.info(
                "Merged %d curl-auth-header finding(s) in %s (lines %s)",
                len(cluster), Path(file_path).name, all_lines,
            )

    return [f for i, f in enumerate(result) if i not in drop]


# ---------------------------------------------------------------------------
# Step 3: Downgrade test-file findings
# ---------------------------------------------------------------------------

def _apply_test_file_downgrade(findings: list[dict]) -> list[dict]:
    for f in findings:
        if _is_test_file(f.get("file", "")):
            original = f["severity"]
            downgraded = _downgrade_severity(original)
            if downgraded != original:
                f["severity"]   = downgraded
                f["confidence"] = "low"
                note = (
                    f"Severity downgraded {original}→{downgraded} because "
                    "finding is in a test/fixture/example file."
                )
                f["notes"] = (f.get("notes", "") + " " + note).strip()
                log.info(
                    "Downgraded '%s' in '%s': %s → %s",
                    f["title"], f["file"], original, downgraded,
                )
    return findings


# ---------------------------------------------------------------------------
# Step 4: Flag uncertain findings for manual review
# ---------------------------------------------------------------------------

def _flag_uncertain(findings: list[dict]) -> list[dict]:
    for f in findings:
        confidence = (f.get("confidence") or "low").lower()
        likelihood = (f.get("likelihood") or "").lower()
        has_evidence = bool((f.get("evidence") or "").strip())

        f["needs_manual_review"] = (
            confidence == "low"
            or likelihood == "low"
            or not has_evidence
        )
    return findings


# ---------------------------------------------------------------------------
# Step 5: Remove no-evidence findings
# ---------------------------------------------------------------------------

def _remove_no_evidence(findings: list[dict]) -> list[dict]:
    before   = len(findings)
    filtered = [f for f in findings if (f.get("evidence") or "").strip()]
    removed  = before - len(filtered)
    if removed:
        log.info("Removed %d finding(s) with no evidence.", removed)
    return filtered


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate(findings: list[dict]) -> dict[str, list[dict]]:
    """
    Run the full validation pipeline.

    Args:
        findings: Enriched, normalised findings.

    Returns:
        {
            "confirmed":    list of fully validated findings,
            "needs_review": list of uncertain / low-confidence findings,
        }
        Both lists are sorted by severity descending.
    """
    if not findings:
        return {"confirmed": [], "needs_review": []}

    log.info("Validator: starting with %d finding(s).", len(findings))

    result = deepcopy(findings)
    for step in (
        _deduplicate,
        _merge_duplicate_secrets,   # collapse same-file/line secrets across tools
        _merge_curl_auth_headers,   # collapse repeated curl-auth-header findings
        _merge_related,             # collapse same-CVE findings across tools
        _apply_test_file_downgrade,
        _flag_uncertain,
        _remove_no_evidence,
    ):
        result = step(result)

    confirmed    = [f for f in result if not f.get("needs_manual_review")]
    needs_review = [f for f in result if f.get("needs_manual_review")]

    for lst in (confirmed, needs_review):
        lst.sort(key=lambda f: _sev_order(f.get("severity", "")), reverse=True)

    log.info(
        "Validator: %d confirmed, %d needs manual review.",
        len(confirmed), len(needs_review),
    )
    return {"confirmed": confirmed, "needs_review": needs_review}
