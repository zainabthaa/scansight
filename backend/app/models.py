"""Pydantic schemas shared by the API, the job manager and the parsers."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ScanStatus(StrEnum):
    queued = "queued"
    running = "running"
    enriching = "enriching"
    completed = "completed"
    failed = "failed"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"
    unknown = "unknown"


def severity_from_cvss(score: float | None) -> Severity:
    """CVSS v3 qualitative rating scale."""
    if score is None:
        return Severity.unknown
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0.0:
        return Severity.low
    return Severity.none


# --- Requests --------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str = Field(..., max_length=253, examples=["scanme.nmap.org"])
    technique: str = Field("connect", examples=["connect", "syn", "udp"])
    timing: int = Field(4, ge=0, le=5)
    port_preset: str = Field("top100", examples=["top100", "top1000", "all", "custom"])
    custom_ports: str | None = Field(None, max_length=400, examples=["22,80,443,8000-8100"])
    service_detection: bool = True
    cve_detection: bool = True
    os_detection: bool = False
    skip_host_discovery: bool = True
    authorized: bool = Field(
        False, description="User confirms they own the target or have permission to scan it"
    )


class ExplainRequest(BaseModel):
    product: str | None = Field(None, max_length=200)
    version: str | None = Field(None, max_length=100)
    port: int | None = Field(None, ge=1, le=65535)
    # Scan-time data, used only if NVD has no score (e.g. offline or rate-limited).
    cvss: float | None = Field(None, ge=0, le=10)
    is_exploit: bool = False


# --- Scan results ----------------------------------------------------------------------


class CVE(BaseModel):
    id: str
    cvss: float | None = None
    severity: Severity = Severity.unknown
    source: str = "vulners"
    is_exploit: bool = False  # vulners knows of public exploit code
    # FIRST EPSS: probability (0-1) of exploitation in the next 30 days, and its percentile.
    # From FIRST's API (app/cve/epss.py), or from vulners.nse 2.x when it supplies one.
    epss: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False  # listed in CISA Known Exploited Vulnerabilities
    kev_date_added: str | None = None
    kev_ransomware: bool = False
    description: str | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    published: str | None = None
    cwe: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    url: str | None = None


class Port(BaseModel):
    port: int
    protocol: str
    state: str
    reason: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpes: list[str] = Field(default_factory=list)
    cves: list[CVE] = Field(default_factory=list)


class OSMatch(BaseModel):
    name: str
    accuracy: int


class Host(BaseModel):
    address: str
    hostnames: list[str] = Field(default_factory=list)
    status: str = "unknown"
    os_matches: list[OSMatch] = Field(default_factory=list)
    ports: list[Port] = Field(default_factory=list)


class ScanResult(BaseModel):
    nmap_version: str | None = None
    command: str | None = None
    started_at: datetime | None = None
    elapsed_seconds: float | None = None
    summary: str | None = None
    hosts: list[Host] = Field(default_factory=list)

    def all_cves(self) -> list[CVE]:
        return [c for h in self.hosts for p in h.ports for c in p.cves]


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class ScanJob(BaseModel):
    id: str
    target: str
    resolved_ip: str
    options: dict
    command: list[str]
    status: ScanStatus = ScanStatus.queued
    progress: float = 0.0
    current_task: str | None = None
    error: str | None = None
    created_at: datetime
    finished_at: datetime | None = None
    result: ScanResult | None = None
    severity_counts: SeverityCounts | None = None


class ScanSummary(BaseModel):
    """Lightweight row for the history list."""

    id: str
    target: str
    status: ScanStatus
    created_at: datetime
    open_ports: int = 0
    cve_count: int = 0
    severity_counts: SeverityCounts | None = None


class Explanation(BaseModel):
    cve_id: str
    summary: str
    impact: str
    who_is_affected: str
    remediation: list[str]
    risk_level: str
    provider: str
    model: str
    cached: bool = False
