from datetime import datetime
from pydantic import BaseModel, Field
from typing import Literal, Optional


# --- Vulnerability Schemas ---


class VulnerabilityBase(BaseModel):
    cve_id: Optional[str] = None
    cvss_score: float = 0.0
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "LOW"
    description: str = ""
    affected_host: str = ""
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    solution: str = ""
    references: list[str] = Field(default_factory=list)
    exploit_available: bool = False
    source_scanner: str = ""
    raw_output: dict = Field(default_factory=dict)


class VulnerabilityCreate(VulnerabilityBase):
    scan_id: int


class VulnerabilityResponse(VulnerabilityBase):
    id: int
    scan_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- Scan Schemas ---


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP to scan")
    scanners: list[str] = Field(
        default=["nmap", "nuclei"], description="List of scanners to use"
    )


class ScanResponse(BaseModel):
    id: int
    target: str
    status: str
    scanners_used: list[str]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    avg_cvss: float
    progress: int = 0
    current_scanner: str = ""
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ScanResultsResponse(BaseModel):
    scan: ScanResponse
    vulnerabilities: list[VulnerabilityResponse]


# --- CVE Schemas ---


class CVEResponse(BaseModel):
    id: int
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    solution: str
    references: list[str]
    exploit_available: bool
    source: str
    indexed_at: datetime

    class Config:
        from_attributes = True


# --- RAG Schemas ---


class ChatRequest(BaseModel):
    message: str = Field(
        ..., description="User question about vulnerabilities", max_length=10000
    )
    session_id: str = Field(
        default="default", description="Chat session ID", max_length=200
    )


class ChatSource(BaseModel):
    cve_id: Optional[str] = None
    content: str = ""
    score: float = 0.0


class ChatResponse(BaseModel):
    answer: str
    sources: list[ChatSource] = Field(default_factory=list)
    session_id: str


class ChatMessageResponse(BaseModel):
    id: int
    session_id: str
    role: str
    content: str
    sources: list[dict] = Field(default_factory=list)
    created_at: datetime

    class Config:
        from_attributes = True


# --- Attack Path Schemas ---


class AttackNode(BaseModel):
    id: str
    label: str
    type: str  # host, vulnerability, service
    severity: Optional[str] = None
    cvss_score: Optional[float] = None


class AttackEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None


class AttackPath(BaseModel):
    path_id: str
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    total_cvss: float
    risk_level: str


class AttackPathsResponse(BaseModel):
    scan_id: int
    paths: list[AttackPath]
    total_paths: int


# --- Stats Schemas ---


class DashboardStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int
    avg_cvss: float
    recent_scans: list[ScanResponse]


# --- Evaluation Schemas ---


class EvalResult(BaseModel):
    metric: str
    score: float
    details: dict = Field(default_factory=dict)
