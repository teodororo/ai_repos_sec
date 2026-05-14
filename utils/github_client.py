"""
GitHub REST API client with caching, automatic rate-limit handling,
transparent retry logic, and per-category request counting.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import (
    CACHE_DIR,
    CACHE_EXPIRY_HOURS,
    GITHUB_API_BASE,
    GITHUB_TOKEN,
    RATE_LIMIT_BUFFER,
    SEARCH_RATE_LIMIT_BUFFER,
)

logger = logging.getLogger(__name__)


@dataclass
class RequestStats:
    core: int = 0       # GET/POST/DELETE to non-search endpoints
    search: int = 0     # GET /search/*
    cache_hits: int = 0 # responses served from disk cache (no HTTP call made)
    git_clones: int = 0 # subprocess git clone calls (tracked externally)

    def total_api(self) -> int:
        return self.core + self.search

    def summary(self) -> str:
        return (
            f"core={self.core}, search={self.search}, "
            f"cache_hits={self.cache_hits}, git_clones={self.git_clones}"
        )


class GitHubClient:
    def __init__(self):
        self._session = self._build_session()
        self._cache_dir = CACHE_DIR / "api"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._remaining = 5000 if GITHUB_TOKEN else 60
        self._reset_at = 0.0
        self._search_remaining = 30 if GITHUB_TOKEN else 10
        self._search_reset_at = 0.0
        self.stats = RequestStats()

        if not GITHUB_TOKEN:
            logger.warning(
                "No GITHUB_TOKEN found — unauthenticated mode (60 req/hour). "
                "Set GITHUB_TOKEN in .env for much faster collection."
            )

    # ── Session ────────────────────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        s.headers.update(headers)

        retry = Retry(
            total=5,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "DELETE"],
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        return s

    # ── Cache ───────────────────────────────────────────────────────────────

    def _cache_key(self, url: str, params: Optional[dict]) -> Path:
        raw = url + json.dumps(sorted((params or {}).items()))
        h = hashlib.sha1(raw.encode()).hexdigest()
        return self._cache_dir / f"{h}.json"

    def _from_cache(self, path: Path) -> Optional[Any]:
        if not path.exists():
            return None
        age_hours = (time.time() - path.stat().st_mtime) / 3600
        if age_hours > CACHE_EXPIRY_HOURS:
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def _to_cache(self, path: Path, data: Any) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError as exc:
            logger.debug("Cache write failed: %s", exc)

    # ── Rate limit handling ─────────────────────────────────────────────────

    def _parse_rate_limit(self, resp: requests.Response, is_search: bool = False) -> None:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")

        if remaining is not None:
            n = int(remaining)
            if is_search:
                self._search_remaining = n
            else:
                self._remaining = n

        if reset is not None:
            ts = float(reset)
            if is_search:
                self._search_reset_at = ts
            else:
                self._reset_at = ts

        effective = self._search_remaining if is_search else self._remaining
        effective_reset = self._search_reset_at if is_search else self._reset_at
        threshold = SEARCH_RATE_LIMIT_BUFFER if is_search else RATE_LIMIT_BUFFER

        if effective <= threshold:
            wait = max(0.0, effective_reset - time.time()) + 5
            logger.warning(
                "Rate limit low (%d remaining). Sleeping %.0fs …", effective, wait
            )
            time.sleep(wait)

    def _handle_secondary_limit(self, resp: requests.Response) -> None:
        retry_after = resp.headers.get("Retry-After")
        wait = float(retry_after) if retry_after else 60.0
        logger.warning("Secondary rate limit hit — waiting %.0fs …", wait)
        time.sleep(wait)

    # ── Core request ────────────────────────────────────────────────────────

    def get(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        use_cache: bool = True,
        accept: Optional[str] = None,
    ) -> Optional[Any]:
        url = endpoint if endpoint.startswith("http") else f"{GITHUB_API_BASE}{endpoint}"
        is_search = "/search/" in url
        cache_path = self._cache_key(url, params)

        if use_cache:
            cached = self._from_cache(cache_path)
            if cached is not None:
                self.stats.cache_hits += 1
                logger.debug("Cache hit: %s", url)
                return cached

        if is_search:
            self.stats.search += 1
        else:
            self.stats.core += 1

        extra_headers: dict = {}
        if accept:
            extra_headers["Accept"] = accept

        for attempt in range(4):
            try:
                resp = self._session.get(
                    url, params=params, headers=extra_headers, timeout=30
                )
            except requests.exceptions.RequestException as exc:
                logger.error("Request error (%s): %s", url, exc)
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                return None

            self._parse_rate_limit(resp, is_search=is_search)

            if resp.status_code == 200:
                data = resp.json()
                if use_cache:
                    self._to_cache(cache_path, data)
                return data

            if resp.status_code in (301, 302):
                url = resp.headers.get("Location", url)
                continue

            if resp.status_code == 304:
                return self._from_cache(cache_path)

            if resp.status_code == 403:
                body = resp.json() if resp.content else {}
                msg = body.get("message", "")
                if "secondary rate limit" in msg.lower() or "abuse" in msg.lower():
                    self._handle_secondary_limit(resp)
                    continue
                logger.debug("403 Forbidden: %s — %s", url, msg)
                return None

            if resp.status_code == 404:
                logger.debug("404 Not Found: %s", url)
                return None

            if resp.status_code == 409:
                logger.debug("409 Conflict (empty repo?): %s", url)
                return None

            if resp.status_code == 422:
                logger.debug("422 Unprocessable: %s — %s", url, resp.text[:200])
                return None

            logger.warning("Unexpected status %d for %s", resp.status_code, url)
            if attempt < 3:
                time.sleep(2 ** attempt)

        return None

    def post(
        self,
        endpoint: str,
        payload: Optional[dict] = None,
    ) -> Optional[Any]:
        url = endpoint if endpoint.startswith("http") else f"{GITHUB_API_BASE}{endpoint}"
        self.stats.core += 1
        try:
            resp = self._session.post(url, json=payload or {}, timeout=30)
            self._parse_rate_limit(resp)
            if resp.status_code in (200, 201, 202):
                return resp.json()
            logger.warning("POST %s → %d: %s", url, resp.status_code, resp.text[:200])
            return None
        except requests.exceptions.RequestException as exc:
            logger.error("POST error (%s): %s", url, exc)
            return None

    def delete(self, endpoint: str) -> bool:
        url = endpoint if endpoint.startswith("http") else f"{GITHUB_API_BASE}{endpoint}"
        self.stats.core += 1
        try:
            resp = self._session.delete(url, timeout=30)
            return resp.status_code in (200, 204)
        except requests.exceptions.RequestException as exc:
            logger.error("DELETE error (%s): %s", url, exc)
            return False

    # ── Pagination ──────────────────────────────────────────────────────────

    def get_paginated(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        max_pages: Optional[int] = None,
    ) -> List[Any]:
        all_items: List[Any] = []
        base = {**(params or {}), "per_page": 100}

        for page in range(1, (max_pages or 9999) + 1):
            data = self.get(endpoint, params={**base, "page": page})
            if data is None:
                break

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and "items" in data:
                items = data["items"]
            else:
                all_items.append(data)
                break

            if not items:
                break

            all_items.extend(items)
            logger.debug("  page %d → %d items (total so far: %d)", page, len(items), len(all_items))

            if len(items) < 100:
                break

        return all_items

    # ── Helpers ─────────────────────────────────────────────────────────────

    def file_exists(self, owner: str, repo: str, path: str) -> bool:
        return self.get(f"/repos/{owner}/{repo}/contents/{path}") is not None

    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        data = self.get(f"/repos/{owner}/{repo}/contents/{path}")
        if not data or not isinstance(data, dict):
            return None
        import base64
        content = data.get("content", "")
        if content:
            try:
                return base64.b64decode(content).decode("utf-8", errors="replace")
            except Exception:
                pass
        return None

    def get_contributors_count(self, owner: str, repo: str) -> int:
        """Return contributor count using the anon=1 + per_page=1 Link-header trick."""
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contributors"
        self.stats.core += 1
        try:
            resp = self._session.get(
                url, params={"per_page": 1, "anon": "true"}, timeout=30
            )
            self._parse_rate_limit(resp)
            if resp.status_code != 200:
                return 0
            link = resp.headers.get("Link", "")
            if 'rel="last"' in link:
                import re
                m = re.search(r'page=(\d+)>;\s*rel="last"', link)
                if m:
                    return int(m.group(1))
            items = resp.json()
            return len(items) if isinstance(items, list) else 0
        except Exception as exc:
            logger.debug("contributors count failed (%s/%s): %s", owner, repo, exc)
            return 0

    def get_rate_limit(self) -> Dict:
        return self.get("/rate_limit", use_cache=False) or {}
