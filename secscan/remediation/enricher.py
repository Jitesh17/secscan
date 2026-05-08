"""AI-powered remediation enricher.

Uses the Anthropic API to produce specific, context-aware fixes for findings.
Falls back gracefully if no API key, network error, or quota.
"""
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

from ..scanners import Finding
from .code_context import extract_snippet, find_config_files
from .static_db import lookup_static_fix


ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-5"
MAX_TOKENS = 800


SYSTEM_PROMPT = """You are a security remediation assistant. Given a security finding from \
an automated scanner, produce a concrete, actionable fix.

Your output must be valid JSON with these fields:
- "fix": specific steps to remediate, formatted as numbered steps. Reference exact files, \
config keys, or commands when context allows. Keep under 200 words.
- "rationale": 1-2 sentences on why this matters and what attack it prevents.
- "example": optional code/config snippet showing the fix. Empty string if not applicable.
- "confidence": "high" if you have enough context for a specific fix, "medium" if generic, \
"low" if the finding is ambiguous.

Return only the JSON object, no preamble or markdown fences."""


@dataclass
class EnrichmentConfig:
    enabled: bool = False
    model: str = DEFAULT_MODEL
    api_key: str | None = None
    include_code: bool = True
    repo: str | None = None
    max_findings: int = 50
    timeout: int = 30
    parallel: int = 4


def _finding_hash(f: Finding) -> str:
    key = f"{f.scanner}|{f.title}|{f.target}|{f.severity}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _build_prompt(f: Finding, config: EnrichmentConfig) -> str:
    parts = [
        f"# Security Finding",
        f"",
        f"**Scanner:** {f.scanner}",
        f"**Severity:** {f.severity}",
        f"**Title:** {f.title}",
        f"**Target:** {f.target}",
        f"",
        f"**Description:** {f.description or '(none)'}",
    ]
    if f.evidence:
        parts.extend(["", "**Evidence:**", "```", f.evidence[:1500], "```"])
    if f.remediation:
        parts.extend(["", f"**Generic remediation from scanner:** {f.remediation}"])
    if f.references:
        refs = "\n".join(f"- {r}" for r in f.references[:5] if r)
        if refs:
            parts.extend(["", "**References:**", refs])

    if config.include_code and f.scanner.startswith("code-"):
        snippet = extract_snippet(f.target, config.repo)
        if snippet:
            parts.extend(["", "**Code context:**", "```", snippet, "```"])

    if config.include_code and f.scanner == "headers" and config.repo:
        configs = find_config_files(config.repo)
        if configs:
            parts.append("")
            parts.append("**Detected config files in repo:**")
            for name, content in list(configs.items())[:3]:
                parts.extend([f"`{name}`:", "```", content[:600], "```"])

    parts.extend([
        "",
        "Produce a JSON remediation per the system prompt instructions.",
    ])
    return "\n".join(parts)


def _call_claude(prompt: str, config: EnrichmentConfig) -> dict | None:
    headers = {
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": config.model,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        r = requests.post(
            ANTHROPIC_API_URL,
            headers=headers,
            json=payload,
            timeout=config.timeout,
        )
        if r.status_code != 200:
            return {"_error": f"API {r.status_code}: {r.text[:200]}"}
        data = r.json()
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_error": "could not parse JSON from model response",
                    "_raw": text[:500]}
    except requests.RequestException as e:
        return {"_error": str(e)}


def enrich_finding(f: Finding, config: EnrichmentConfig, cache: dict) -> Finding:
    """Enrich a single finding. Static lookup first, then AI if enabled."""
    static = lookup_static_fix(f.scanner, f.title)
    if static:
        f.raw["static_fix"] = static.fix
        f.raw["static_rationale"] = static.rationale
        if static.example:
            f.raw["static_example"] = static.example
        if not f.remediation:
            f.remediation = static.fix

    if not config.enabled:
        return f

    cache_key = _finding_hash(f)
    if cache_key in cache:
        ai = cache[cache_key]
    else:
        prompt = _build_prompt(f, config)
        ai = _call_claude(prompt, config)
        if ai:
            cache[cache_key] = ai

    if ai and "_error" not in ai:
        f.raw["ai_fix"] = ai.get("fix", "")
        f.raw["ai_rationale"] = ai.get("rationale", "")
        f.raw["ai_example"] = ai.get("example", "")
        f.raw["ai_confidence"] = ai.get("confidence", "")
    elif ai:
        f.raw["ai_error"] = ai.get("_error", "unknown")
    return f


def enrich_findings(
    findings: list[Finding],
    config: EnrichmentConfig,
    cache_path: str | None = None,
    on_progress=None,
) -> list[Finding]:
    """Enrich all findings in parallel. Returns the same list with raw fields populated."""
    cache: dict = {}
    if cache_path and os.path.isfile(cache_path):
        try:
            with open(cache_path) as fh:
                cache = json.load(fh)
        except (json.JSONDecodeError, OSError):
            cache = {}

    targets = findings[: config.max_findings]

    if config.enabled and not config.api_key:
        for f in targets:
            enrich_finding(f, EnrichmentConfig(enabled=False), cache)
        return findings

    if not config.enabled:
        for f in targets:
            enrich_finding(f, config, cache)
        return findings

    completed = 0
    with ThreadPoolExecutor(max_workers=config.parallel) as ex:
        futures = {ex.submit(enrich_finding, f, config, cache): f for f in targets}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                f = futures[fut]
                f.raw["ai_error"] = f"enrichment failed: {e}"
            completed += 1
            if on_progress:
                on_progress(completed, len(targets))

    if cache_path:
        try:
            with open(cache_path, "w") as fh:
                json.dump(cache, fh)
        except OSError:
            pass

    return findings


def build_config_from_env(
    enable_ai: bool,
    include_code: bool,
    repo: str | None,
) -> EnrichmentConfig:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    return EnrichmentConfig(
        enabled=enable_ai and bool(api_key),
        api_key=api_key,
        include_code=include_code,
        repo=repo,
        model=os.environ.get("SECSCAN_MODEL", DEFAULT_MODEL),
    )
