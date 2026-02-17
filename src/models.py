"""Pydantic data models for the security scanner."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


# --- Enums ---

class Severity(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Priority(str, Enum):
    """Priority levels for remediation."""
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class ScanStatus(str, Enum):
    """Status of a security scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ComplianceStatus(str, Enum):
    """Compliance assessment status."""
    COMPLIANT = "COMPLIANT"
    MOSTLY_COMPLIANT = "MOSTLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"


# --- Security Rules ---

class DetectionMethod(BaseModel):
    """How a security rule is detected in code."""
    pattern: Optional[str] = None
    ast_query: Optional[str] = None
    llm_prompt: Optional[str] = None


class CodeExample(BaseModel):
    """Vulnerable and secure code examples for a rule."""
    vulnerable: str
    secure: str


class ComplianceMapping(BaseModel):
    """Maps a rule to compliance framework controls."""
    iso_27001: List[str] = Field(default_factory=list)
    pci_dss: List[str] = Field(default_factory=list)
    soc_2: List[str] = Field(default_factory=list)


class SecurityRule(BaseModel):
    """A security rule used for code analysis."""
    rule_id: str
    title: str
    category: str
    severity: Severity
    description: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    compliance: ComplianceMapping = Field(default_factory=ComplianceMapping)
    detection: DetectionMethod = Field(default_factory=DetectionMethod)
    examples: Optional[CodeExample] = None
    remediation: str = ""
    references: List[str] = Field(default_factory=list)


# --- Scan Findings ---

class Finding(BaseModel):
    """A security finding detected during a scan."""
    finding_id: str
    rule_id: str
    severity: Severity
    title: str
    category: str
    file_path: str
    line_number: int
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    code_snippet: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    compliance: ComplianceMapping = Field(default_factory=ComplianceMapping)
    effort_estimate_hours: int = 0
    priority: Priority = Priority.P2
    references: List[str] = Field(default_factory=list)


# --- Scan Results ---

class ScanMetadata(BaseModel):
    """Metadata about a completed scan."""
    scan_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: int = 0
    scanner_version: str = "1.0.0"
    rules_version: str = "2026.02"


class ScanScope(BaseModel):
    """Scope of a scan (what was scanned)."""
    repository: str
    branch: Optional[str] = None
    commit: Optional[str] = None
    files_scanned: int = 0
    lines_of_code: int = 0
    languages: Dict[str, int] = Field(default_factory=dict)


class ComplianceGap(BaseModel):
    """A gap in compliance for a specific control."""
    control: str
    description: str
    violations: int = 0
    severity: Optional[Severity] = None


class FrameworkCompliance(BaseModel):
    """Compliance status for a single framework."""
    framework: str
    compliant_controls: int = 0
    total_controls: int = 0
    percentage: float = 0.0
    status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    gaps: List[ComplianceGap] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """Summary statistics from a scan."""
    total_findings: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    security_score: int = 100
    compliance: Dict[str, FrameworkCompliance] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Complete result of a security scan."""
    metadata: ScanMetadata
    scope: ScanScope
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: List[Finding] = Field(default_factory=list)
    files_analyzed: List[Dict] = Field(default_factory=list)


# --- API Request/Response Models ---

class ScanRequest(BaseModel):
    """Request to start a new scan."""
    codebase_path: str
    rule_set: List[str] = Field(
        default=["owasp", "cwe", "bandit"],
        description="Rule sets to apply: owasp, cwe, bandit, iso27001, pci_dss, soc2",
    )
    output_formats: List[str] = Field(
        default=["json", "markdown"],
        description="Report formats: json, markdown, pdf, html, csv",
    )
    exclude_patterns: List[str] = Field(
        default=["**/test_*.py", "**/tests/**", "**/vendor/**", "**/.venv/**"],
        description="Glob patterns for files to exclude",
    )


class ScanResponse(BaseModel):
    """Response after starting a scan."""
    scan_id: str
    status: ScanStatus
    estimated_time: Optional[int] = None
    message: str = ""


class ScanStatusResponse(BaseModel):
    """Response for scan status query."""
    scan_id: str
    status: ScanStatus
    progress: int = 0
    result: Optional[ScanResult] = None
    report_urls: Dict[str, str] = Field(default_factory=dict)


class RuleUploadResponse(BaseModel):
    """Response after uploading security rule PDFs."""
    status: str
    rules_extracted: int = 0
    processing_time: float = 0.0
    message: str = ""


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    ollama_connected: bool = False
    scanner_version: str = "1.0.0"
    rules_loaded: int = 0
