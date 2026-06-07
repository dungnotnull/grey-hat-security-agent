"""LLM provider with automatic fallback chain and SQLite-backed caching.

Provider priority:
1. Claude API (claude-opus-4-8) - primary
2. OpenAI GPT-4o - fallback
3. Ollama Mistral-7B-Instruct - offline fallback

All calls go through async_llm_call(prompt, context).
Responses cached in SQLite (SHA-256 of prompt -> response, 7-day TTL).
API keys never logged; redacted from all output.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from config.settings import settings

logger = logging.getLogger(__name__)


class LLMResponse:
    """Response from an LLM provider."""

    def __init__(self, text: str, provider: str, model: str, tokens_used: int = 0, cost_usd: float = 0.0):
        self.text = text
        self.provider = provider
        self.model = model
        self.tokens_used = tokens_used
        self.cost_usd = cost_usd


class LLMProvider:
    """LLM provider with automatic fallback chain and caching."""

    # Provider configuration
    PROVIDERS = [
        {
            "name": "claude",
            "model": "claude-opus-4-8",
            "max_tokens": 4096,
        },
        {
            "name": "openai",
            "model": "gpt-4o",
            "max_tokens": 4096,
        },
        {
            "name": "ollama",
            "model": "mistral:7b-instruct",
            "max_tokens": 2048,
        },
    ]

    def __init__(self):
        self._cache: dict[str, tuple[str, datetime]] = {}
        self._cache_ttl = timedelta(days=7)
        self._db_cache_enabled = True

    def _cache_key(self, prompt: str, context: str = "") -> str:
        """Generate cache key from prompt SHA-256."""
        content = f"{prompt}|||{context}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[str]:
        """Get cached response — checks in-memory first, then SQLite."""
        # In-memory cache (fastest)
        if key in self._cache:
            response, expiry = self._cache[key]
            if datetime.now(timezone.utc) < expiry:
                return response
            del self._cache[key]

        # SQLite cache (persistent)
        if self._db_cache_enabled:
            try:
                from db.session import get_sync_session
                from db.models import LLMCache
                from sqlalchemy import select

                session = get_sync_session()
                try:
                    result = session.execute(
                        select(LLMCache).where(LLMCache.prompt_hash == key)
                    ).scalar_one_or_none()
                    if result and result.expires_at:
                        expires = result.expires_at
                        if expires.tzinfo is None:
                            expires = expires.replace(tzinfo=timezone.utc)
                        if datetime.now(timezone.utc) < expires:
                            # Found in DB — also cache in memory for next time
                            self._cache[key] = (result.response, expires)
                            return result.response
                        else:
                            # Expired — delete from DB
                            session.delete(result)
                            session.commit()
                finally:
                    session.close()
            except Exception as e:
                logger.debug(f"DB cache read failed (non-critical): {e}")

        return None

    def _set_cached(self, key: str, response: str, provider: str = "", model: str = "", tokens_used: int = 0):
        """Cache a response with 7-day TTL — stores in both memory and SQLite."""
        expiry = datetime.now(timezone.utc) + self._cache_ttl
        self._cache[key] = (response, expiry)

        # Also store in SQLite for persistence across restarts
        if self._db_cache_enabled:
            try:
                from db.session import get_sync_session
                from db.models import LLMCache
                from sqlalchemy import select

                session = get_sync_session()
                try:
                    existing = session.execute(
                        select(LLMCache).where(LLMCache.prompt_hash == key)
                    ).scalar_one_or_none()

                    if existing:
                        existing.response = response
                        existing.provider = provider
                        existing.model = model
                        existing.tokens_used = tokens_used
                        existing.expires_at = expiry
                    else:
                        cache_entry = LLMCache(
                            prompt_hash=key,
                            provider=provider,
                            model=model,
                            prompt=key[:500],  # Truncate for storage
                            response=response,
                            tokens_used=tokens_used,
                            expires_at=expiry,
                        )
                        session.add(cache_entry)
                    session.commit()
                finally:
                    session.close()
            except Exception as e:
                logger.debug(f"DB cache write failed (non-critical): {e}")

    async def call(self, prompt: str, context: str = "", max_tokens: int = 4096) -> LLMResponse:
        """Call LLM with automatic fallback chain.

        Tries providers in order: Claude -> OpenAI -> Ollama.
        Returns the first successful response.

        Args:
            prompt: The prompt to send to the LLM.
            context: Additional context (appended to prompt).
            max_tokens: Maximum tokens in response.

        Returns:
            LLMResponse with generated text and provider info.
        """
        # Check cache first
        cache_key = self._cache_key(prompt, context)
        cached = self._get_cached(cache_key)
        if cached:
            logger.info("LLM response served from cache")
            return LLMResponse(text=cached, provider="cache", model="cached")

        full_prompt = f"{prompt}\n\n{context}" if context else prompt

        # Try each provider in fallback order
        errors = []
        for provider_config in self.PROVIDERS:
            try:
                if provider_config["name"] == "claude" and settings.claude_api_key:
                    response = await self._call_claude(full_prompt, provider_config, max_tokens)
                    if response:
                        self._set_cached(cache_key, response.text, "claude", provider_config["model"], response.tokens_used)
                        return response
                elif provider_config["name"] == "openai" and settings.openai_api_key:
                    response = await self._call_openai(full_prompt, provider_config, max_tokens)
                    if response:
                        self._set_cached(cache_key, response.text, "openai", provider_config["model"], response.tokens_used)
                        return response
                elif provider_config["name"] == "ollama":
                    response = await self._call_ollama(full_prompt, provider_config, min(max_tokens, 2048))
                    if response:
                        self._set_cached(cache_key, response.text, "ollama", provider_config["model"], response.tokens_used)
                        return response
            except Exception as e:
                errors.append(f"{provider_config['name']}: {str(e)}")
                logger.warning(f"LLM provider {provider_config['name']} failed: {e}")
                continue

        # All providers failed — generate template-based response
        logger.error(f"All LLM providers failed: {errors}")
        return LLMResponse(
            text="[ERROR: All LLM providers failed. Unable to generate report narrative.]",
            provider="none",
            model="none",
        )

    async def _call_claude(self, prompt: str, config: dict, max_tokens: int) -> Optional[LLMResponse]:
        """Call Claude API."""
        try:
            import anthropic

            client = anthropic.AsyncAnthropic(api_key=settings.claude_api_key)
            response = await client.messages.create(
                model=config["model"],
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.content[0].text if response.content else ""
            tokens = response.usage.input_tokens + response.usage.output_tokens if response.usage else 0

            return LLMResponse(
                text=text,
                provider="claude",
                model=config["model"],
                tokens_used=tokens,
            )
        except Exception as e:
            logger.warning(f"Claude API error: {e}")
            return None

    async def _call_openai(self, prompt: str, config: dict, max_tokens: int) -> Optional[LLMResponse]:
        """Call OpenAI GPT-4o API."""
        try:
            from openai import AsyncOpenAI

            client = AsyncOpenAI(api_key=settings.openai_api_key)
            response = await client.chat.completions.create(
                model=config["model"],
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.choices[0].message.content or ""
            tokens = response.usage.total_tokens if response.usage else 0

            return LLMResponse(
                text=text,
                provider="openai",
                model=config["model"],
                tokens_used=tokens,
            )
        except Exception as e:
            logger.warning(f"OpenAI API error: {e}")
            return None

    async def _call_ollama(self, prompt: str, config: dict, max_tokens: int) -> Optional[LLMResponse]:
        """Call Ollama Mistral-7B-Instruct (local)."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{settings.ollama_base_url}/api/generate",
                    json={
                        "model": config["model"],
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "num_predict": max_tokens,
                        },
                    },
                )
                response.raise_for_status()
                data = response.json()
                text = data.get("response", "")

                return LLMResponse(
                    text=text,
                    provider="ollama",
                    model=config["model"],
                    tokens_used=data.get("eval_count", 0),
                )
        except Exception as e:
            logger.warning(f"Ollama API error: {e}")
            return None

    def generate_report_prompt(self, findings: list[dict], scan_info: dict) -> str:
        """Generate LLM prompt for pentest report."""
        findings_text = ""
        for i, f in enumerate(findings, 1):
            findings_text += f"\n{i}. [{f.get('severity', 'Unknown')}] {f.get('title', 'Untitled')}\n"
            findings_text += f"   Description: {f.get('description', 'N/A')}\n"
            if f.get('cve_id'):
                findings_text += f"   CVE: {f['cve_id']}\n"
            if f.get('cwe_id'):
                findings_text += f"   CWE: {f['cwe_id']}\n"
            if f.get('recommendation'):
                findings_text += f"   Recommendation: {f['recommendation']}\n"

        prompt = f"""You are a professional penetration tester writing a security assessment report. Write a clear, professional report based on the following findings.

IMPORTANT: Only include CVE IDs that are explicitly listed in the findings. Do NOT invent or hallucinate CVE IDs.

Target: {scan_info.get('target', 'Unknown')}
Date: {scan_info.get('date', 'N/A')}
Scan Type: {scan_info.get('scan_type', 'N/A')}
Total Findings: {len(findings)}

Findings:
{findings_text}

Please write:
1. Executive Summary (2-3 paragraphs)
2. Findings Summary Table
3. Detailed Findings (for each finding)
4. Recommendations (prioritized)

Format the report in Markdown."""
        return prompt

    def generate_cve_verification_prompt(self, cve_ids: list[str]) -> str:
        """Generate prompt to verify CVE IDs exist in our local NVD mirror."""
        cve_list = ", ".join(cve_ids)
        return f"""The following CVE IDs were mentioned in a security report: {cve_list}

For each CVE ID, respond with ONLY 'VALID' or 'INVALID'. Do not add any other text."""
