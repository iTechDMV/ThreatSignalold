"""Unit tests for threat intel integrations (no network required)."""

import pytest
from unittest.mock import AsyncMock

from threatsignal.integrations.threatintel import (
    AbuseIPDBConnector,
    IndicatorType,
    IntelNotFoundError,
    VirusTotalConnector,
    detect_indicator_type,
)


# --- indicator type detection ---

@pytest.mark.parametrize("ioc,expected", [
    ("8.8.8.8", IndicatorType.IP),
    ("2001:db8::1", IndicatorType.IP),
    ("evil.example.com", IndicatorType.DOMAIN),
    ("https://evil.example.com/payload.exe", IndicatorType.URL),
    ("44d88612fea8a8c36da82e2e40453f7b", IndicatorType.MD5),
    ("a" * 40, IndicatorType.SHA1),
    ("a" * 64, IndicatorType.SHA256),
    ("not an ioc", IndicatorType.UNKNOWN),
])
def test_detect_indicator_type(ioc, expected):
    assert detect_indicator_type(ioc) == expected


# --- VirusTotal ---

def _vt_attrs(malicious=10, suspicious=0, harmless=80, undetected=10):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": -50,
                "categories": {"alpha": "phishing"},
                "tags": ["phishing"],
            }
        }
    }


@pytest.mark.asyncio
async def test_vt_lookup_ip_parses_stats():
    vt = VirusTotalConnector(api_key="test")
    vt._request = AsyncMock(return_value=_vt_attrs(malicious=10, suspicious=0,
                                                   harmless=80, undetected=10))
    result = await vt.lookup_ip("203.0.113.99")
    assert result.source == "virustotal"
    assert result.indicator_type == IndicatorType.IP
    assert result.malicious_score == 10  # 10 bad / 100 total
    assert result.is_suspicious is False and result.is_clean
    assert "alpha" in result.categories
    assert result.reputation == -50


@pytest.mark.asyncio
async def test_vt_lookup_hash_flags_malicious():
    vt = VirusTotalConnector(api_key="test")
    vt._request = AsyncMock(return_value=_vt_attrs(malicious=60, suspicious=20,
                                                   harmless=15, undetected=5))
    result = await vt.lookup_hash("a" * 64)
    assert result.malicious_score == 80
    assert result.is_malicious


@pytest.mark.asyncio
async def test_vt_not_found_raises():
    vt = VirusTotalConnector(api_key="test")
    vt._request = AsyncMock(return_value={"data": None})
    with pytest.raises(IntelNotFoundError):
        await vt.lookup_ip("203.0.113.99")


# --- AbuseIPDB ---

def _abuse_payload(score=85, reports=42):
    return {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Host Ltd",
            "reports": [{"categories": [3, 10]}, {"categories": [3]}],
        }
    }


@pytest.mark.asyncio
async def test_abuseipdb_lookup_ip():
    abuse = AbuseIPDBConnector(api_key="test")
    abuse._request = AsyncMock(return_value=_abuse_payload())
    result = await abuse.lookup_ip("203.0.113.99")
    assert result.source == "abuseipdb"
    assert result.malicious_score == 85
    assert result.is_malicious
    assert result.reports == 42
    assert result.categories == [3, 10]  # flattened & sorted
    assert "Data Center/Web Hosting/Transit" in result.tags


@pytest.mark.asyncio
async def test_abuseipdb_rejects_non_ip_indicators():
    abuse = AbuseIPDBConnector(api_key="test")
    with pytest.raises(NotImplementedError):
        await abuse.lookup("evil.example.com")


# --- dispatch ---

@pytest.mark.asyncio
async def test_lookup_dispatches_on_type():
    abuse = AbuseIPDBConnector(api_key="test")
    abuse._request = AsyncMock(return_value=_abuse_payload(score=10, reports=1))
    result = await abuse.lookup("203.0.113.99")  # no explicit lookup_ip call
    assert result.indicator_type == IndicatorType.IP


@pytest.mark.asyncio
async def test_lookup_many_never_raises():
    vt = VirusTotalConnector(api_key="test")
    vt._request = AsyncMock(side_effect=[_vt_attrs(), Exception("boom"), _vt_attrs()])
    results = await vt.lookup_many(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    assert len(results) == 3
    assert "error" in results[1].tags
