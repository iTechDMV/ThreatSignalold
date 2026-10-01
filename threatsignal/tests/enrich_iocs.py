"""Example: enrich IOCs across multiple threat intel sources.

Usage:
    export VT_API_KEY="..."
    export ABUSEIPDB_API_KEY="..."
    python examples/enrich_iocs.py
"""

import asyncio
import os

from threatsignal.integrations.threatintel import (
    AbuseIPDBConnector,
    VirusTotalConnector,
)

INDICATORS = [
    "8.8.8.8",
    "203.0.113.99",
    "evil.example.com",
    "https://evil.example.com/payload.exe",
    "44d88612fea8a8c36da82e2e40453f7b",  # EICAR test file MD5
]

SOURCES = []  # filled in main(); add your own ThreatIntelConnector subclasses here


async def main() -> None:
    sources = [
        VirusTotalConnector(api_key=os.environ["VT_API_KEY"]),
        AbuseIPDBConnector(api_key=os.environ["ABUSEIPDB_API_KEY"]),
    ]

    for source in sources:
        await source.connect()
        print(f"\n=== {source.source_name} ===")
        results = await source.lookup_many(INDICATORS)
        for r in results:
            d = r.to_dict()
            print(f"{d['indicator']:<42} {d['indicator_type']:<8} "
                  f"score={d['malicious_score']:>3}  {d['verdict']:<10} "
                  f"tags={r.tags}")

    for source in sources:
        await source.close()


if __name__ == "__main__":
    asyncio.run(main())
