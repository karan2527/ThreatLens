"""DNS, RDAP, and email-authentication intelligence for domain indicators."""

import asyncio
from datetime import UTC, datetime
from typing import Any

import dns.exception
import dns.resolver
import httpx

from app.integrations.base import ThreatProvider
from app.integrations.provider_utils import result
from app.models.enums import IndicatorType, ProviderStatus, Verdict
from app.schemas.provider import NormalizedProviderResult, ProviderCheckRequest

DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2")


class DomainIntelligenceProvider(ThreatProvider):
    """Collect passive domain configuration and registration intelligence."""

    name = "domain_intelligence"

    async def check(self, indicator: ProviderCheckRequest) -> NormalizedProviderResult:
        if indicator.type != IndicatorType.DOMAIN:
            return result(
                self.name,
                ProviderStatus.SKIPPED,
                error_code="NOT_APPLICABLE",
                reason="Domain intelligence requires a domain indicator.",
            )

        domain = indicator.normalized_value
        try:
            records = await self._resolve_records_async(domain)
            dkim_records = await self._resolve_dkim(domain)
            rdap = await self._fetch_rdap(domain)
            data = self._build_analysis(domain, records, rdap, dkim_records)
            return NormalizedProviderResult(
                provider_name=self.name,
                status=ProviderStatus.SUCCESS,
                verdict=Verdict.UNKNOWN,
                checked_at=datetime.now(UTC),
                normalized_data=data,
            )
        except httpx.TimeoutException:
            return result(self.name, ProviderStatus.TIMEOUT, error_code="RDAP_TIMEOUT")
        except httpx.HTTPError:
            return result(
                self.name, ProviderStatus.FAILED, error_code="RDAP_REQUEST_FAILED"
            )
        except (KeyError, TypeError, ValueError):
            return result(
                self.name, ProviderStatus.FAILED, error_code="DOMAIN_ANALYSIS_FAILED"
            )

    @staticmethod
    def _resolve_records(domain: str) -> dict[str, list[str]]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        records: dict[str, list[str]] = {}
        for record_type in DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, record_type)
                records[record_type] = [
                    answer.to_text().strip().strip('"') for answer in answers
                ]
            except (
                dns.exception.DNSException,
                OSError,
            ):
                records[record_type] = []
        return records

    @classmethod
    async def _resolve_records_async(cls, domain: str) -> dict[str, list[str]]:
        values = await asyncio.gather(
            *(
                asyncio.to_thread(cls._resolve_one, domain, record_type)
                for record_type in DNS_RECORD_TYPES
            )
        )
        return dict(zip(DNS_RECORD_TYPES, values, strict=True))

    @staticmethod
    def _resolve_one(domain: str, record_type: str) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 2.5
        try:
            answers = resolver.resolve(domain, record_type)
            return [answer.to_text().strip().strip('"') for answer in answers]
        except (dns.exception.DNSException, OSError):
            return []

    @classmethod
    async def _resolve_dkim(cls, domain: str) -> dict[str, list[str]]:
        values = await asyncio.gather(
            *(
                asyncio.to_thread(
                    cls._resolve_one, f"{selector}._domainkey.{domain}", "TXT"
                )
                for selector in COMMON_DKIM_SELECTORS
            )
        )
        return {
            selector: records
            for selector, records in zip(COMMON_DKIM_SELECTORS, values, strict=True)
            if records
        }

    @staticmethod
    async def _fetch_rdap(domain: str) -> dict[str, Any]:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(8.0), follow_redirects=True
        ) as client:
            response = await client.get(f"https://rdap.org/domain/{domain}")
            if response.status_code == 404:
                return {}
            response.raise_for_status()
            payload = response.json()
            return payload if isinstance(payload, dict) else {}

    @classmethod
    def _build_analysis(
        cls,
        domain: str,
        records: dict[str, list[str]],
        rdap: dict[str, Any],
        dkim_records: dict[str, list[str]],
    ) -> dict[str, object]:
        anomalies = cls._find_anomalies(records)
        email_auth = cls._email_authentication(records, dkim_records)
        return {
            "domain": domain,
            "dns_records": records,
            "registration": cls._registration(rdap),
            "nameservers": cls._nameserver_analysis(records),
            "email_authentication": email_auth,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
        }

    @staticmethod
    def _registration(rdap: dict[str, Any]) -> dict[str, object]:
        events = rdap.get("events", [])
        event_dates: dict[str, str] = {}
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    action = event.get("eventAction")
                    date = event.get("eventDate")
                    if isinstance(action, str) and isinstance(date, str):
                        event_dates[action] = date
        registration_date = event_dates.get("registration")
        age_days: int | None = None
        if registration_date:
            try:
                registered = datetime.fromisoformat(
                    registration_date.replace("Z", "+00:00")
                )
                age_days = max(0, (datetime.now(UTC) - registered).days)
            except ValueError:
                age_days = None
        entities = rdap.get("entities", [])
        registrar: str | None = None
        if isinstance(entities, list):
            for entity in entities:
                if not isinstance(entity, dict) or "registrar" not in entity.get(
                    "roles", []
                ):
                    continue
                vcard = entity.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for field in vcard[1]:
                        if (
                            isinstance(field, list)
                            and len(field) > 3
                            and field[0] == "fn"
                            and isinstance(field[3], str)
                        ):
                            registrar = field[3]
                            break
                registrar = registrar or entity.get("handle")
                if registrar:
                    break
        return {
            "registrar": registrar,
            "registration_date": registration_date,
            "expiration_date": event_dates.get("expiration"),
            "last_changed_date": event_dates.get("last changed"),
            "age_days": age_days,
            "rdap_available": bool(rdap),
        }

    @staticmethod
    def _nameserver_analysis(records: dict[str, list[str]]) -> dict[str, object]:
        nameservers = [value.rstrip(".").lower() for value in records.get("NS", [])]
        operators = {name.split(".", 1)[-1] for name in nameservers if "." in name}
        return {
            "nameservers": nameservers,
            "count": len(nameservers),
            "unique_count": len(set(nameservers)),
            "operator_domains": sorted(operators),
            "diversity": "diverse" if len(operators) > 1 else "single_operator",
        }

    @staticmethod
    def _email_authentication(
        records: dict[str, list[str]], dkim_records: dict[str, list[str]]
    ) -> dict[str, object]:
        txt_records = records.get("TXT", [])
        spf_records = [
            record for record in txt_records if record.lower().startswith("v=spf1")
        ]
        dmarc_records = [
            record for record in txt_records if record.lower().startswith("v=dmarc1")
        ]
        return {
            "spf": {
                "present": bool(spf_records),
                "record_count": len(spf_records),
                "records": spf_records,
                "valid": len(spf_records) == 1,
            },
            "dkim": {
                "checked_selectors": list(COMMON_DKIM_SELECTORS),
                "selectors_found": dkim_records,
                "present": bool(dkim_records),
            },
            "dmarc": {
                "present": bool(dmarc_records),
                "records": dmarc_records,
                "valid": len(dmarc_records) == 1,
            },
        }

    @staticmethod
    def _find_anomalies(records: dict[str, list[str]]) -> list[str]:
        anomalies: list[str] = []
        if (
            not records.get("A")
            and not records.get("AAAA")
            and not records.get("CNAME")
        ):
            anomalies.append("Domain has no address or CNAME record.")
        if records.get("CNAME") and (
            records.get("A") or records.get("AAAA") or records.get("MX")
        ):
            anomalies.append("CNAME is published alongside records it should replace.")
        if len(set(records.get("NS", []))) < 2:
            anomalies.append("Fewer than two unique authoritative nameservers found.")
        txt_records = records.get("TXT", [])
        spf_count = sum(record.lower().startswith("v=spf1") for record in txt_records)
        dmarc_count = sum(
            record.lower().startswith("v=dmarc1") for record in txt_records
        )
        if spf_count == 0:
            anomalies.append("No SPF policy was found.")
        elif spf_count > 1:
            anomalies.append("Multiple SPF policies were found.")
        if dmarc_count == 0:
            anomalies.append("No DMARC policy was found.")
        elif dmarc_count > 1:
            anomalies.append("Multiple DMARC policies were found.")
        return anomalies
