"""
llm_analyzer.py — Enrich scanner findings with LLM-generated analysis.

For each finding the LLM adds:
  impact, likelihood, exploit_scenario, recommended_fix, confidence

Provider is selected via LLM_PROVIDER env var.
Architecture context from architecture_mapper is passed to the LLM so it
can produce application-specific (not generic) analysis.

Hard rule: the LLM must NOT invent findings. It only reasons about
evidence already present in the scanner output.
"""
import json
import logging
import os
from typing import Any, Optional

from config import LLM_BATCH_SIZE

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_BASE = """You are a senior application security engineer writing a \
vulnerability assessment report.

You will receive a JSON array of security findings from automated scanners \
(semgrep, gitleaks, trivy, pip-audit, npm audit). Each finding includes \
scanner-generated evidence.

{arch_section}

Your task — for EACH finding, add exactly four new fields:
  "impact"           — concrete harm if exploited (2–4 sentences)
  "likelihood"       — low | medium | high  (one word + 1-sentence justification)
  "exploit_scenario" — brief realistic scenario grounded in the evidence (2–4 sentences)
  "recommended_fix"  — specific, actionable remediation step (2–4 sentences)

Mandatory rules:
  1. Do NOT invent new findings. Enrich ONLY what is already in the list.
  2. Ground every explanation in the "evidence" field of the finding.
  3. If evidence is weak, say so and set likelihood to "low".
  4. Return ONLY a valid JSON array in the same order as the input.
     Each element is the original finding object with the four fields added.
     Do NOT wrap in markdown fences or add any prose outside the JSON.
"""

_ARCH_SECTION_TEMPLATE = """\
Application context (detected by static analysis):
  Language   : {language}
  Framework  : {framework}
  Database   : {database}
  Auth       : {auth}
  Deployment : {deployment}

Use this context to tailor your impact and exploit scenario to the actual
technology stack rather than giving generic advice.
"""

_USER_TEMPLATE = "Enrich these findings:\n\n{findings_json}"

# Minimal retry prompt — only asks for the four fields we need, on a stripped
# representation.  Used when a finding comes back with placeholder values.
_RETRY_SYSTEM = """You are a senior application security engineer.

You will receive a JSON array where each element has:
  "id"       — integer index (preserve it in output)
  "title"    — finding title
  "severity" — critical | high | medium | low | info
  "file"     — source file path
  "line"     — line number or null
  "evidence" — scanner-extracted evidence

For EACH element output exactly:
  "id"               — same integer, unchanged
  "impact"           — concrete harm if exploited (2-4 sentences)
  "likelihood"       — low | medium | high  (one word + 1-sentence justification)
  "exploit_scenario" — realistic scenario grounded in the evidence (2-4 sentences)
  "recommended_fix"  — specific actionable remediation (2-4 sentences)
  "confidence"       — high | medium | low

Rules:
  1. Do NOT invent findings. Only reason about what is in the evidence.
  2. Return ONLY a valid JSON array, same length as input, no prose, no markdown fences.
"""

_RETRY_USER_TEMPLATE = "Enrich these stripped findings:\n\n{findings_json}"


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

def _call_anthropic(system: str, messages: list[dict], model: str) -> str:
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=8192,   # large batches of dependency CVEs need more room
        system=system,
        messages=messages,
    )
    return response.content[0].text


def _call_openai(system: str, messages: list[dict], model: str) -> str:
    try:
        import openai
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")

    client = openai.OpenAI(api_key=api_key)
    full_messages = [{"role": "system", "content": system}] + messages
    response = client.chat.completions.create(
        model=model,
        messages=full_messages,
        max_tokens=8192,
        temperature=0.2,
    )
    return response.choices[0].message.content


_PROVIDERS = {
    "anthropic": _call_anthropic,
    "openai":    _call_openai,
}


# ---------------------------------------------------------------------------
# Build system prompt with optional architecture context
# ---------------------------------------------------------------------------

def _build_system_prompt(architecture: Optional[dict]) -> str:
    if architecture:
        db   = architecture.get("database", ["Unknown"])
        auth = architecture.get("auth",     ["Unknown"])
        dep  = architecture.get("deployment", ["Unknown"])
        arch_section = _ARCH_SECTION_TEMPLATE.format(
            language   = architecture.get("language",  "Unknown"),
            framework  = architecture.get("framework", "Unknown"),
            database   = ", ".join(db)  if isinstance(db, list)  else str(db),
            auth       = ", ".join(auth) if isinstance(auth, list) else str(auth),
            deployment = ", ".join(dep)  if isinstance(dep, list)  else str(dep),
        )
    else:
        arch_section = ""
    return _SYSTEM_BASE.format(arch_section=arch_section)


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def _enrich_batch(
    batch: list[dict],
    system: str,
    provider: str,
    model: str,
) -> list[dict]:
    findings_json = json.dumps(batch, indent=2)
    messages = [{"role": "user", "content": _USER_TEMPLATE.format(findings_json=findings_json)}]

    try:
        raw = _PROVIDERS[provider](system, messages, model)
    except Exception as exc:
        log.error("LLM call failed for batch (%d findings): %s", len(batch), exc)
        for f in batch:
            f.setdefault("impact",           "LLM analysis unavailable.")
            f.setdefault("likelihood",       "unknown")
            f.setdefault("exploit_scenario", "LLM analysis unavailable.")
            f.setdefault("recommended_fix",  f.get("recommendation", ""))
        return batch

    # Strip accidental markdown fences
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        enriched = json.loads(text)
        if isinstance(enriched, list) and len(enriched) == len(batch):
            return enriched
        log.warning(
            "LLM returned %d items for a batch of %d — using originals.",
            len(enriched) if isinstance(enriched, list) else -1,
            len(batch),
        )
        return batch
    except json.JSONDecodeError as exc:
        log.error("LLM response is not valid JSON: %s\nResponse preview: %.400s", exc, text)
        return batch


# ---------------------------------------------------------------------------
# Retry helpers
# ---------------------------------------------------------------------------

_PLACEHOLDER = {"llm analysis unavailable.", "not analysed.", ""}


def _needs_enrichment(f: dict) -> bool:
    """Return True if the finding was not successfully enriched by the LLM."""
    for field in ("impact", "likelihood", "exploit_scenario", "recommended_fix"):
        val = (f.get(field) or "").strip().lower()
        if val in _PLACEHOLDER or val == "unknown":
            return True
    return False


def _enrich_batch_minimal(
    indexed: list[tuple[int, dict]],
    provider: str,
    model: str,
) -> dict[int, dict]:
    """
    Send a stripped-down representation of findings to the LLM for retry.

    Args:
        indexed: list of (original_index, finding_dict)
        provider: "anthropic" | "openai"
        model: model name string

    Returns:
        Mapping of original_index → enrichment dict (4 fields + confidence).
        On failure returns empty dict.
    """
    stripped = [
        {
            "id":       idx,
            "title":    f.get("title", ""),
            "severity": f.get("severity", ""),
            "file":     f.get("file", ""),
            "line":     f.get("line"),
            "evidence": (f.get("evidence") or "")[:400],
        }
        for idx, f in indexed
    ]
    messages = [{"role": "user", "content": _RETRY_USER_TEMPLATE.format(
        findings_json=json.dumps(stripped, indent=2)
    )}]
    try:
        raw = _PROVIDERS[provider](_RETRY_SYSTEM, messages, model)
    except Exception as exc:
        log.error("Retry LLM call failed: %s", exc)
        return {}

    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        parsed = json.loads(text)
        if not isinstance(parsed, list):
            return {}
        return {item["id"]: item for item in parsed if "id" in item}
    except (json.JSONDecodeError, KeyError) as exc:
        log.error("Retry LLM response is not valid JSON: %s\nPreview: %.400s", exc, text)
        return {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(
    findings: list[dict],
    architecture: Optional[dict] = None,
) -> list[dict]:
    """
    Enrich each finding with LLM-generated impact / likelihood / exploit / fix.

    Args:
        findings:     Normalised findings from normalizer.py.
        architecture: Optional dict from architecture_mapper.map_architecture().

    Returns:
        The same list with added fields (in-place + returned).
    """
    if not findings:
        log.info("No findings to analyse.")
        return findings

    provider = os.environ.get("LLM_PROVIDER", "anthropic").lower()
    model    = os.environ.get("LLM_MODEL",    "claude-sonnet-4-6")

    if provider not in _PROVIDERS:
        raise RuntimeError(
            f"Unsupported LLM_PROVIDER='{provider}'. Supported: {list(_PROVIDERS)}"
        )

    system = _build_system_prompt(architecture)
    log.info(
        "LLM enrichment — provider=%s model=%s findings=%d",
        provider, model, len(findings),
    )

    enriched_all: list[dict] = []
    total = len(findings)
    num_batches = (total + LLM_BATCH_SIZE - 1) // LLM_BATCH_SIZE

    for i in range(0, total, LLM_BATCH_SIZE):
        batch = findings[i : i + LLM_BATCH_SIZE]
        batch_num = i // LLM_BATCH_SIZE + 1
        log.info("Enriching batch %d/%d (%d findings) …", batch_num, num_batches, len(batch))
        enriched_all.extend(_enrich_batch(batch, system, provider, model))

    # ── Retry pass ─────────────────────────────────────────────────────────
    RETRY_BATCH = 5
    unenriched = [(i, f) for i, f in enumerate(enriched_all) if _needs_enrichment(f)]
    if unenriched:
        log.info(
            "Retry pass: %d finding(s) still need enrichment.", len(unenriched)
        )
        for j in range(0, len(unenriched), RETRY_BATCH):
            sub = unenriched[j : j + RETRY_BATCH]
            results = _enrich_batch_minimal(sub, provider, model)
            for orig_idx, f in sub:
                if orig_idx in results:
                    patch = results[orig_idx]
                    for field in ("impact", "likelihood", "exploit_scenario",
                                  "recommended_fix", "confidence"):
                        if patch.get(field):
                            enriched_all[orig_idx][field] = patch[field]
                    log.info("Retry succeeded for finding index %d.", orig_idx)
                else:
                    log.warning(
                        "Retry failed for finding '%s' — marking enrichment_failed.",
                        f.get("title", "unknown"),
                    )
                    enriched_all[orig_idx]["enrichment_failed"] = True

    log.info("LLM enrichment complete for %d findings.", len(enriched_all))
    return enriched_all
