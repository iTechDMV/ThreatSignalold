"""
AbuseIPDB connector (API v2)
Free tier: 1,000 checks/day - IP addresses only.
"""

import logging
from typing import Any, Dict

from .base import IndicatorType, IntelResult, ThreatIntelConnector

logger = logging.getLogger(__name__)


class AbuseIPDBConnector(ThreatIntelConnector):
    """AbuseIPDB connector for IP reputation (IP indicators only)."""

    source_name = "abuseipdb"
    CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, max_age_in_days: int = 90):
        super().__init__()
        self.api_key = api_key
        self.max_age_in_days = max_age_in_days
        self._headers = {"Key": self.api_key, "Accept": "application/json"}

    async def connect(self) -> bool:
        """AbuseIPDB has no auth endpoint - validate the key with a known IP."""
        result = await self.lookup_ip("1.1.1.1")
        return "error" not in result.raw

    async def lookup_ip(self, ip_address: str) -> IntelResult:
        data = await self._request(
            "GET",
            self.CHECK_URL,
            headers=self._headers,
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": self.max_age_in_days,
                "verbose": "",
            },
        )
        d: Dict[str, Any] = data.get("data", {})

        # Flatten report categories when verbose is enabled
        categories = sorted({
            cat
            for report in d.get("reports", [])
            for cat in report.get("categories", [])
        })

        tags = [t for t in (d.get("usageType"), d.get("isp")) if t]

        return IntelResult(
            indicator=ip_address,
            indicator_type=IndicatorType.IP,
            source=self.source_name,
            malicious_score=int(d.get("abuseConfidenceScore", 0)),
            categories=categories,
            reports=int(d.get("totalReports", 0)),
            tags=tags,
            raw=d,
        )

    # AbuseIPDB supports IP addresses only - override with explicit guidance.

    async def lookup_domain(self, domain: str) -> IntelResult:
        raise NotImplementedError(
            "AbuseIPDB supports IP addresses only; use VirusTotal for domains"
        )

    async def lookup_url(self, url: str) -> IntelResult:
        raise NotImplementedError(
            "AbuseIPDB supports IP addresses only; use VirusTotal for URLs"
        )

    async def lookup_hash(self, file_hash: str) -> IntelResult:
        raise NotImplementedError(
            "AbuseIPDB supports IP addresses only; use VirusTotal for hashes"
        )
