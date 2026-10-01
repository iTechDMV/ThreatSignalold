"""
VirusTotal connector (API v3)
Free tier: 4 lookups/min, 500 lookups/day - handled via rate limiting.
"""

import base64
import logging
from typing import Any, Dict, List

from .base import (
    IntelNotFoundError,
    IntelResult,
    ThreatIntelConnector,
)

logger = logging.getLogger(__name__)


class VirusTotalConnector(ThreatIntelConnector):
    """VirusTotal v3 connector for IPs, domains, URLs and file hashes."""

    source_name = "virustotal"
    FREE_TIER_INTERVAL = 15.0  # seconds; 4 req/min on the public API tier

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.virustotal.com/api/v3",
        min_request_interval: float = FREE_TIER_INTERVAL,
    ):
        super().__init__()
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.min_request_interval = min_request_interval
        self._headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    async def connect(self) -> bool:
        """VirusTotal has no auth endpoint - validate the key via /users/current."""
        data = await self._request(
            "GET", f"{self.base_url}/users/current", headers=self._headers
        )
        user = data.get("data", {})
        if user:
            self.logger.info(
                "Connected to VirusTotal as %s", user.get("attributes", {}).get("email")
            )
            return True
        return False

    # -- lookups --

    async def lookup_ip(self, ip_address: str) -> IntelResult:
        data = await self._get_entity("ip_addresses", ip_address)
        return self._build_result(ip_address, "ip", data)

    async def lookup_domain(self, domain: str) -> IntelResult:
        data = await self._get_entity("domains", domain)
        return self._build_result(domain, "domain", data)

    async def lookup_hash(self, file_hash: str) -> IntelResult:
        data = await self._get_entity("files", file_hash.lower())
        result = self._build_result(file_hash, "file", data)
        meaningful = data.get("attributes", {}).get("meaningful_name")
        if meaningful:
            result.tags.append(meaningful)
        return result

    async def lookup_url(self, url: str) -> IntelResult:
        # VT v3 identifies URLs by their base64url-encoded form (no padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = await self._get_entity("urls", url_id)
        return self._build_result(url, "url", data)

    # -- internals --

    async def _get_entity(self, collection: str, entity_id: str) -> Dict[str, Any]:
        data = await self._request(
            "GET",
            f"{self.base_url}/{collection}/{entity_id}",
            headers=self._headers,
        )
        if data.get("data") is None:
            raise IntelNotFoundError(
                f"{entity_id!r} not found in VirusTotal ({collection})"
            )
        return data["data"]

    def _build_result(self, indicator: str, kind: str, data: Dict[str, Any]) -> IntelResult:
        from .base import IndicatorType  # local import keeps module namespace clean

        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        itype = {
            "ip": IndicatorType.IP,
            "domain": IndicatorType.DOMAIN,
            "url": IndicatorType.URL,
            "file": IndicatorType.SHA256,
        }[kind]

        categories_obj = attrs.get("categories") or {}
        categories: List[str] = sorted(categories_obj.keys()) if isinstance(categories_obj, dict) else []

        return IntelResult(
            indicator=indicator,
            indicator_type=itype,
            source=self.source_name,
            malicious_score=self._score_from_stats(stats),
            reputation=attrs.get("reputation"),
            categories=categories,
            reports=stats.get("malicious", 0),
            tags=attrs.get("tags") or [],
            raw=attrs,
        )

    @staticmethod
    def _score_from_stats(stats: Dict[str, int]) -> int:
        """Normalize vendor analysis stats to a 0-100 score."""
        bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        return round(100 * bad / total)
