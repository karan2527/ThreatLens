"""Report API schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ReportCreateResponse(BaseModel):
    """Metadata returned after generating a report."""

    report_id: str
    scan_id: str
    report_type: Literal["json", "pdf"]
    checksum: str
    created_at: datetime
    download_url: str
