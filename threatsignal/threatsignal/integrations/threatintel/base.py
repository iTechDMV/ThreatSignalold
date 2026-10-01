"""
Threat Intelligence Integration Module
Abstract base class for threat intelligence connectors.

Provides:
  - IndicatorType / detect_indicator_type : automatic IOC type detection
  - IntelResult                           : normalized, vendor-agnostic result
  - ThreatIntelConnector                  : abstract base with dispatch, batch
    lookup, rate-limiting and retry logic shared by all connectors
"""

import asyncio
import ipaddress
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import aiohttp


class IntelAPIError(Exception):
    """Raised when a threat intel API call fails permanently."""
    pass


class IntelNotFoundError(IntelAPIError):
    """Raised when an indicator is not present in the vendor's dataset."""
    pass


class IndicatorType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


# --- IOC type detection -----------------------------------------------------

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")


def detect_indicator_type(indicator: str) -> IndicatorType:
    """Best-effort classification of an IOC string."""
    i = indicator.strip()
    if _SHA256_RE.match(i):
        return IndicatorType.SHA256
    if _SHA1_RE.match(i):
        return IndicatorType.SHA1
    if _MD5_RE.match(i):
        return IndicatorType.MD5
    try:
        ipaddress.ip_address(i)
        return IndicatorType.IP
    except ValueError:
        pass
    if i.lower().startswith(("http://", "https://")):
        return IndicatorType.URL
    if _DOMAIN_RE.match(i):
        return IndicatorType.DOMAIN
    return IndicatorType.UNKNOWN


# --- Normalized result ------------------------------------------------------

@dataclass
class IntelResult:
    """Vendor-agnostic threat intelligence result."""
    indicator: str
    indicator_type: IndicatorType
    source: str
    malicious_score: int = 0                       # 0-100, normalized across vendors
    reputation: Optional[int] = None               # vendor-native reputation, if any
    categories: List[str] = field(default_factory=list)
    reports: int = 0
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def is_malicious(self) -> bool:
        return self.malicious_score >= 75

    @property
    def is_suspicious(self) -> bool:
        return 25 <= self.malicious_score < 75

    @property
    def is_clean(self) -> bool:
        return self.malicious_score < 25

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "source": self.source,
            "malicious_score": self.malicious_score,
            "reputation": self.reputation,
            "categories": self.categories,
            "reports": self.reports,
            "tags": self.tags,
            "checked_at": self.checked_at,
            "verdict": ("malicious" if self.is_malicious
                        else "suspicious" if self.is_suspicious else "clean"),
        }


# --- Abstract connector -----------------------------------------------------

class ThreatIntelConnector(ABC):
    """Abstract base class for threat intel connectors.

    Subclasses must implement connect() and lookup_ip(); other lookup
    methods have safe defaults raising NotImplementedError so vendors only
    implement what their API actually supports (e.g. AbuseIPDB is IP-only).
    """

    source_name: str = "unknown"
    min_request_interval: float = 0.0   # seconds between requests; override for free tiers
    max_concurrency: int = 4

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{__name__}.{type(self).__name__}")
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request_at: float = 0.0

    # -- capabilities (override in subclasses) --

    @abstractmethod
    async def connect(self) -> bool:
        """Validate credentials and connectivity."""

    @abstractmethod
    async def lookup_ip(self, ip_address: str) -> IntelResult:
        """Look up an IP address."""

    async def lookup_domain(self, domain: str) -> IntelResult:
        raise NotImplementedError(f"{type(self).__name__} does not support domain lookups")

    async def lookup_url(self, url: str) -> IntelResult:
        raise NotImplementedError(f"{type(self).__name__} does not support URL lookups")

    async def lookup_hash(self, file_hash: str) -> IntelResult:
        raise NotImplementedError(f"{type(self).__name__} does not support hash lookups")

    # -- dispatch --

    async def lookup(self, indicator: str) -> IntelResult:
        """Look up any indicator, auto-detecting its type."""
        itype = detect_indicator_type(indicator)
        dispatch = {
            IndicatorType.IP: self.lookup_ip,
            IndicatorType.DOMAIN: self.lookup_domain,
            IndicatorType.URL: self.lookup_url,
            IndicatorType.MD5: self.lookup_hash,
            IndicatorType.SHA1: self.lookup_hash,
            IndicatorType.SHA256: self.lookup_hash,
        }
        handler = dispatch.get(itype)
        if handler is None:
            raise ValueError(f"Unrecognized indicator: {indicator!r}")
        return await handler(indicator)

    async def lookup_many(self, indicators: List[str]) -> List[IntelResult]:
        """Look up many indicators concurrently (bounded, errors captured)."""
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _bounded(ind: str) -> IntelResult:
            async with semaphore:
                try:
                    return await self.lookup(ind)
                except Exception as exc:
                    self.logger.error("Lookup failed for %s: %s", ind, exc)
                    return IntelResult(
                        indicator=ind,
                        indicator_type=detect_indicator_type(ind),
                        source=self.source_name,
                        tags=["error"],
                        raw={"error": str(exc)},
                    )

        return list(await asyncio.gather(*(_bounded(i) for i in indicators)))

    # -- lifecycle / shared HTTP plumbing --

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session

    async def _throttle(self) -> None:
        """Enforce min_request_interval to respect vendor rate limits."""
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.min_request_interval:
            await asyncio.sleep(self.min_request_interval - elapsed)
        self._last_request_at = time.monotonic()

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        retries: int = 3,
        backoff: float = 2.0,
    ) -> Dict[str, Any]:
        """Async HTTP request with retry, backoff and Retry-After support."""
        await self._throttle()
        last_exc: Optional[Exception] = None

        for attempt in range(1, retries + 1):
            try:
                session = await self._ensure_session()
                async with session.request(
                    method, url, headers=headers, params=params, json=json
                ) as resp:
                    if resp.status == 429:
                        retry_after = float(
                            resp.headers.get("Retry-After", backoff ** attempt)
                        )
                        self.logger.warning(
                            "Rate limited by %s, sleeping %.1fs (attempt %d/%d)",
                            self.source_name, retry_after, attempt, retries,
                        )
                        await asyncio.sleep(retry_after)
                        continue
                    if resp.status in (401, 403):
                        raise IntelAPIError(
                            f"{self.source_name} authentication failed "
                            f"({resp.status}) - check API key"
                        )
                    if resp.status == 404:
                        return {"data": None, "error": "not_found"}
                    resp.raise_for_status()
                    return await resp.json()

            except IntelAPIError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                self.logger.warning(
                    "%s request failed (attempt %d/%d): %s",
                    self.source_name, attempt, retries, exc,
                )
                if attempt < retries:
                    await asyncio.sleep(backoff ** attempt)

        raise IntelAPIError(
            f"{self.source_name} request failed after {retries} attempts: {last_exc}"
        )
