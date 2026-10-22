from datetime import datetime
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class Finding(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str
    explanation: str
    evidence: list[str]
    recommendation: str
    source: str = "heuristic"
    limitations: str


class ScanResult(BaseModel):
    id: int
    original_url: str
    normalized_url: str
    hostname: str
    registered_domain: str
    risk_score: int
    risk_level: str
    score_reasons: list[str]
    findings: list[Finding]
    created_at: datetime


class ScanPage(BaseModel):
    items: list[ScanResult]
    total: int
    page: int
    page_size: int
