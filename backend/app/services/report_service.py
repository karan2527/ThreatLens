"""Deterministic local JSON and PDF report generation."""

import hashlib
import json
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError, NotFoundError
from app.models.indicator import Indicator
from app.models.provider_result import ProviderResult
from app.models.report import Report
from app.models.scan import Scan

REPORT_DIR = Path(__file__).resolve().parents[2] / "reports_output"


def _report_payload(
    scan: Scan, indicator: Indicator, providers: list[ProviderResult]
) -> dict[str, object]:
    """Build the public report document without raw provider responses."""
    return {
        "report_version": "report_v1",
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "progress": scan.progress,
        },
        "indicator": {
            "type": indicator.type,
            "normalized_value": indicator.normalized_value,
            "hash_algorithm": indicator.hash_algorithm,
        },
        "assessment": {
            "verdict": scan.verdict,
            "severity": scan.severity,
            "risk_score": scan.risk_score,
            "coverage": scan.coverage,
            "explanation": scan.explanation,
        },
        "providers": [
            {
                "provider_name": item.provider_name,
                "status": item.status,
                "verdict": item.verdict,
                "malicious_count": item.malicious_count,
                "suspicious_count": item.suspicious_count,
                "harmless_count": item.harmless_count,
                "undetected_count": item.undetected_count,
                "confidence": item.confidence,
                "normalized_data": item.normalized_data,
                "error_code": item.error_code,
                "checked_at": item.checked_at,
                "from_cache": item.from_cache,
                "cache_age_seconds": item.cache_age_seconds,
            }
            for item in providers
        ],
    }


def _pdf_bytes(payload: dict[str, object]) -> bytes:
    """Create a small valid PDF containing the report assessment."""
    assessment = payload["assessment"]
    if not isinstance(assessment, dict):
        raise AppError("REPORT_ERROR", "report assessment is invalid", 500)
    lines = [
        "ThreatLens security report",
        f"Indicator: {payload['indicator']}",
        f"Risk score: {assessment.get('risk_score')}",
        f"Verdict: {assessment.get('verdict')}",
        f"Severity: {assessment.get('severity')}",
    ]
    escaped = [
        line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        for line in lines
    ]
    text = (
        "BT /F1 11 Tf 50 760 Td "
        + " ".join(f"({line}) Tj 0 -18 Td" for line in escaped)
        + " ET"
    )
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(text.encode())} >>\nstream\n{text}\nendstream".encode(),
    ]
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode())
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    output.extend(
        b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:])
    )
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(output)


async def generate_report(
    db: AsyncSession, scan: Scan, report_type: str
) -> tuple[Report, bytes]:
    """Generate, persist, and return a report for an owned scan."""
    if report_type not in {"json", "pdf"}:
        raise AppError("INVALID_REPORT_TYPE", "report type must be json or pdf", 422)
    indicator = await db.get(Indicator, scan.indicator_id)
    if indicator is None:
        raise NotFoundError()
    rows = await db.execute(
        select(ProviderResult)
        .where(ProviderResult.scan_id == scan.id)
        .order_by(ProviderResult.provider_name)
    )
    payload = _report_payload(scan, indicator, list(rows.scalars()))
    if report_type == "json":
        content = json.dumps(
            payload, default=str, ensure_ascii=True, indent=2, sort_keys=True
        ).encode()
        extension = "json"
    else:
        content = _pdf_bytes(payload)
        extension = "pdf"
    checksum = hashlib.sha256(content).hexdigest()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / f"{uuid4()}-{scan.id}.{extension}"
    path.write_bytes(content)
    report = Report(
        scan_id=scan.id,
        report_type=report_type,
        storage_path=str(path),
        checksum=checksum,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report, content
