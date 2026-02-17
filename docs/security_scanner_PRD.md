# Product Requirements Document (PRD)
## Local AI-Powered Security Code Scanner

**Version**: 1.0  
**Date**: February 16, 2026  
**Author**: JO  
**Status**: Ready for Implementation

---

## EXECUTIVE SUMMARY

Build a **local AI-powered security scanner** that analyzes Python codebases against ISO 27001, PCI DSS, and SOC 2 compliance frameworks. The scanner runs 100% locally on M2 Max MacBook Pro, uses DeepSeek-Coder LLM for intelligent analysis, and generates professional multi-format compliance reports.

**Target User**: Security consultant friend who needs to scan client codebases for compliance violations  
**Key Constraint**: Must run entirely on local hardware (no cloud dependencies)  
**Timeline**: 14 hours over 7 days (MVP in Week 1)

---

## TABLE OF CONTENTS

1. [Product Overview](#1-product-overview)
2. [User Personas & Use Cases](#2-user-personas--use-cases)
3. [Technical Architecture](#3-technical-architecture)
4. [Functional Requirements](#4-functional-requirements)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [Security Rules Specification](#6-security-rules-specification)
7. [Reporting Requirements](#7-reporting-requirements)
8. [Data Models](#8-data-models)
9. [API Specifications](#9-api-specifications)
10. [Implementation Phases](#10-implementation-phases)
11. [Success Metrics](#11-success-metrics)
12. [Out of Scope](#12-out-of-scope)

---

## 1. PRODUCT OVERVIEW

### 1.1 Problem Statement

Security consultants need to quickly assess client codebases for compliance with ISO 27001, PCI DSS, and SOC 2 standards. Current solutions either:
- Require cloud uploads (security/privacy concerns)
- Are too generic (not compliance-focused)
- Generate poor reports (not stakeholder-ready)
- Miss context-aware vulnerabilities (rule-based only)

### 1.2 Solution

A local AI-powered scanner that:
1. **Parses security rules** from PDF documents (OWASP, CWE, compliance standards)
2. **Analyzes code** using tree-sitter AST parsing + LLM intelligence
3. **Detects violations** through pattern matching + semantic understanding
4. **Generates reports** in multiple formats (PDF, HTML, JSON, CSV, Markdown)
5. **Runs 100% locally** on M2 Max MacBook Pro

### 1.3 Key Value Propositions

**For Security Consultant**:
- ✅ Fast client codebase assessment (18-25 minutes for typical project)
- ✅ Professional compliance reports for stakeholders
- ✅ AI-powered context-aware detection
- ✅ Complete data privacy (local processing)
- ✅ Framework-specific compliance mapping

**For End Clients**:
- ✅ Clear remediation roadmap
- ✅ Effort estimates for fixes
- ✅ Compliance gap analysis
- ✅ Executive-ready summaries

---

## 2. USER PERSONAS & USE CASES

### 2.1 Primary Persona: Security Consultant

**Name**: Alex (Security Consultant)  
**Role**: Independent security consultant  
**Goals**:
- Quickly assess client codebases
- Generate professional audit reports
- Identify compliance gaps
- Provide actionable remediation guidance

**Pain Points**:
- Manual code review is time-consuming
- Clients need ISO/PCI/SOC2 compliance
- Generic tools miss compliance context
- Report generation takes hours

**Use Cases**:
1. Upload client codebase → Get compliance assessment in 20 mins
2. Generate executive report for C-level stakeholders
3. Create technical remediation guide for dev teams
4. Track compliance progress over time

### 2.2 Secondary Persona: Client CISO/CTO

**Name**: Jordan (Client CISO)  
**Goals**:
- Understand security posture
- Pass compliance audits
- Prioritize remediation work

**Needs from Scanner**:
- Clear risk scoring
- Compliance framework mapping
- Cost/effort estimates
- Board-ready executive summary

---

## 3. TECHNICAL ARCHITECTURE

### 3.1 System Architecture

```
┌─────────────────────────────────────────────────────┐
│                    USER INTERFACE                    │
│              FastAPI Web Application                 │
└─────────────────┬───────────────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌─────────┐  ┌─────────┐  ┌──────────┐
│  PDF    │  │  Code   │  │ Report   │
│ Parser  │  │ Analyzer│  │Generator │
└────┬────┘  └────┬────┘  └────┬─────┘
     │            │             │
     ▼            ▼             ▼
┌─────────────────────────────────┐
│      Vector Database            │
│        (ChromaDB)               │
└─────────────────────────────────┘
                  │
                  ▼
        ┌──────────────────┐
        │  LLM Interface   │
        │  (Ollama)        │
        └──────────────────┘
                  │
                  ▼
        ┌──────────────────┐
        │ DeepSeek-Coder   │
        │  33B (Native)    │
        └──────────────────┘
```

### 3.2 Technology Stack

**Core Application**:
- **Language**: Python 3.11+
- **Web Framework**: FastAPI 0.109+
- **Async Runtime**: asyncio, uvicorn

**PDF Processing**:
- **Library**: PyMuPDF (fitz) 1.23+
- **Fallback**: pdfplumber 0.10+

**Code Analysis**:
- **AST Parser**: tree-sitter 0.20+
- **Languages**: tree-sitter-python, tree-sitter-javascript, tree-sitter-java
- **Pattern Matching**: regex (built-in)

**LLM Integration**:
- **Runtime**: Ollama (native macOS)
- **Model**: DeepSeek-Coder 33B (4-bit quantized)
- **Client**: ollama-python 0.1.6

**Vector Database**:
- **Database**: ChromaDB 0.4.22
- **Embeddings**: sentence-transformers 2.3.1

**Report Generation**:
- **PDF**: WeasyPrint 60.0+
- **HTML**: Jinja2 3.1+
- **Charts**: matplotlib 3.8+, plotly 5.18+

**Containerization**:
- **Container**: Docker (FastAPI app only)
- **Orchestration**: docker-compose

### 3.3 Hardware Specifications

**Platform**: M2 Max MacBook Pro (2023)
- **CPU**: Apple M2 Max (12-core)
- **RAM**: 32GB unified memory
- **Storage**: 512GB+ SSD
- **GPU**: Apple M2 Max (38-core) - Metal acceleration

**LLM Requirements**:
- DeepSeek-Coder 33B (4-bit): ~17GB RAM
- Inference speed: 20-25 tokens/sec
- Available RAM: ~15GB headroom

### 3.4 Deployment Architecture

**Hybrid Docker Setup** (Critical for M2 Max):

```
┌─────────────────────────────────────────────┐
│         macOS (Native)                      │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │  Ollama + DeepSeek-Coder 33B         │  │
│  │  (GPU Accelerated via Metal)         │  │
│  │  Listens on: localhost:11434         │  │
│  └──────────────────────────────────────┘  │
│                    ▲                        │
│                    │                        │
│  ┌─────────────────┼────────────────────┐  │
│  │     Docker Container                 │  │
│  │  ┌──────────────────────────────┐    │  │
│  │  │  FastAPI Application         │    │  │
│  │  │  Connects to:                │    │  │
│  │  │  host.docker.internal:11434  │    │  │
│  │  └──────────────────────────────┘    │  │
│  │                                      │  │
│  │  Volumes:                            │  │
│  │  - ./data/security_rules:/app/data  │  │
│  │  - ./data/vector_db:/app/vector_db  │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

**Why Hybrid**:
- Docker on M2 Max doesn't support GPU acceleration
- Ollama needs native Metal acceleration for performance
- FastAPI containerized for portability/deployment

---

## 4. FUNCTIONAL REQUIREMENTS

### 4.1 Core Features (MVP - Week 1)

#### FR-1: PDF Rule Parsing
**Priority**: P0 (Critical)

**Description**: Extract security rules from PDF documents

**Acceptance Criteria**:
- Parse OWASP Top 10 PDF (10 categories)
- Parse CWE Top 25 PDF (25 weaknesses)
- Extract rule ID, title, description, examples
- Store in structured format (JSON)
- Handle multi-page documents
- Handle tables and lists

**Input**: PDF file path
**Output**: Structured rule objects

**Example**:
```python
{
  "rule_id": "OWASP-A02-001",
  "category": "Cryptographic Failures",
  "severity": "CRITICAL",
  "description": "Hard-coded credentials found in source code",
  "cwe_mapping": ["CWE-798"],
  "examples": {
    "vulnerable": "password = 'admin123'",
    "secure": "password = os.environ.get('DB_PASSWORD')"
  }
}
```

#### FR-2: Code Analysis Engine
**Priority**: P0 (Critical)

**Description**: Parse and analyze Python source code

**Acceptance Criteria**:
- Traverse directory recursively
- Parse Python files with tree-sitter
- Extract AST (Abstract Syntax Tree)
- Identify code patterns (assignments, function calls, imports)
- Support .py files only (MVP)
- Exclude test files, vendor directories

**Input**: Directory path
**Output**: AST + code metadata

**Performance**: 500 files in <5 minutes

#### FR-3: Violation Detection
**Priority**: P0 (Critical)

**Description**: Detect security violations using patterns + LLM

**Acceptance Criteria**:
- **Pattern Matching**: Regex-based detection (hard-coded secrets, SQL concat)
- **AST Analysis**: tree-sitter queries (missing auth checks, weak crypto)
- **LLM Analysis**: Context-aware semantic analysis
- Categorize by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Map to compliance frameworks (ISO 27001, PCI DSS, SOC 2)
- Provide file path, line number, code snippet

**Input**: Code AST + Security rules
**Output**: List of violations

**Example Violation**:
```python
{
  "finding_id": "FIND-001",
  "severity": "CRITICAL",
  "title": "Hard-coded Database Password",
  "category": "CWE-798",
  "file": "src/database/connection.py",
  "line_number": 23,
  "code_snippet": 'password = "P@ssw0rd123!"',
  "description": "Database password hard-coded in source code...",
  "remediation": "Use environment variables: os.environ.get('DB_PASSWORD')",
  "compliance": {
    "iso_27001": "A.9.4.3",
    "pci_dss": "6.2.4",
    "soc_2": "CC6.1"
  }
}
```

#### FR-4: Vector Search for Rule Matching
**Priority**: P1 (High)

**Description**: Use semantic search to find relevant rules

**Acceptance Criteria**:
- Embed security rules in ChromaDB
- Query with code context
- Return top 5 relevant rules
- Use sentence-transformers for embeddings

**Input**: Code snippet + context
**Output**: Ranked list of applicable rules

#### FR-5: LLM Integration
**Priority**: P0 (Critical)

**Description**: Use DeepSeek-Coder for intelligent analysis

**Acceptance Criteria**:
- Connect to Ollama via HTTP (localhost:11434)
- Send code + rules as context
- Request structured JSON response
- Parse LLM output (handle hallucinations)
- Timeout: 30 seconds per query
- Retry logic: 3 attempts

**Prompt Template**:
```
You are a security code reviewer. Analyze this code for violations.

CODE:
{code_snippet}

RELEVANT RULES:
{rules}

TASK:
1. Identify security violations
2. Map to compliance frameworks
3. Provide remediation

OUTPUT (JSON only):
{
  "violations": [...],
  "severity": "...",
  "remediation": "..."
}
```

#### FR-6: Report Generation (JSON + Markdown)
**Priority**: P0 (Critical)

**Description**: Generate scan reports

**Acceptance Criteria**:
- **JSON**: Complete structured data
- **Markdown**: Developer-friendly summary
- Include scan metadata (date, duration, files scanned)
- Summary statistics (violations by severity)
- Detailed findings list
- Compliance mapping

**Output Files**:
- `security_report.json`
- `security_report.md`

### 4.2 Enhanced Features (Week 2-3)

#### FR-7: Multi-Format Reporting
**Priority**: P1 (High)

**Formats**:
- PDF (Executive + Management + Technical)
- HTML (Interactive dashboard)
- CSV (Spreadsheet export)

**See**: `security_scanner_reporting_spec.md` for detailed specs

#### FR-8: Compliance-Specific Rules
**Priority**: P1 (High)

**Additional Rules**:
- ISO 27001: 15 framework-specific rules
- PCI DSS: 20 framework-specific rules (especially Req 3.2.1 - no CVV storage)
- SOC 2: 10 framework-specific rules

**See**: `compliance_frameworks_integration.md` for detailed mappings

#### FR-9: Multi-Language Support
**Priority**: P2 (Medium)

**Languages**:
- JavaScript/TypeScript
- Java
- Go (future)

#### FR-10: Historical Tracking
**Priority**: P2 (Medium)

**Description**: Track compliance over time

**Features**:
- Store scan history
- Compare against previous scans
- Trend analysis
- Regression detection

### 4.3 FastAPI Endpoints

#### POST /rules/upload
**Description**: Upload security rule PDFs

**Request**:
```json
{
  "file": "multipart/form-data"
}
```

**Response**:
```json
{
  "status": "success",
  "rules_extracted": 42,
  "processing_time": 12.5
}
```

#### POST /scan
**Description**: Scan a codebase

**Request**:
```json
{
  "codebase_path": "/path/to/code",
  "rule_set": "iso27001+pci_dss+soc2",
  "output_formats": ["json", "markdown", "pdf"]
}
```

**Response**:
```json
{
  "scan_id": "scan_20260216_143022",
  "status": "running",
  "estimated_time": 1200
}
```

#### GET /scan/{scan_id}
**Description**: Get scan status/results

**Response**:
```json
{
  "scan_id": "scan_20260216_143022",
  "status": "completed",
  "summary": {
    "total_findings": 105,
    "critical": 3,
    "high": 12,
    "medium": 28,
    "low": 47,
    "info": 15
  },
  "report_urls": {
    "json": "/reports/scan_20260216_143022.json",
    "markdown": "/reports/scan_20260216_143022.md"
  }
}
```

#### GET /reports/{scan_id}/{format}
**Description**: Download report in specific format

**Response**: File download (PDF/HTML/JSON/CSV/MD)

#### GET /compliance/{framework}
**Description**: Get compliance status for specific framework

**Response**:
```json
{
  "framework": "pci_dss",
  "compliant_requirements": 7,
  "total_requirements": 12,
  "compliance_percentage": 58,
  "gaps": [
    {
      "requirement": "3.2.1",
      "description": "No storage of CVV2",
      "violations": 2
    }
  ]
}
```

---

## 5. NON-FUNCTIONAL REQUIREMENTS

### 5.1 Performance

**NFR-1**: Scan Performance
- 500 Python files: ≤20 minutes (33B model)
- 500 Python files: ≤15 minutes (13B model)
- Single file analysis: ≤5 seconds

**NFR-2**: LLM Inference
- Token generation: 20-25 tok/s (33B model)
- Context window: 8K tokens
- RAM usage: ≤17GB for model

**NFR-3**: Report Generation
- PDF generation: ≤30 seconds
- HTML dashboard: ≤10 seconds
- JSON export: ≤2 seconds

### 5.2 Reliability

**NFR-4**: Error Handling
- Graceful degradation if LLM unavailable
- Retry logic for transient failures
- Detailed error logging
- User-friendly error messages

**NFR-5**: Data Integrity
- Validate all inputs (file paths, JSON)
- Handle malformed PDFs gracefully
- Prevent code injection in paths

### 5.3 Usability

**NFR-6**: User Experience
- Clear progress indicators
- Estimated time remaining
- Intuitive API responses
- Self-documenting endpoints (OpenAPI/Swagger)

**NFR-7**: Documentation
- README with setup instructions
- API documentation
- Architecture diagrams
- Code examples

### 5.4 Security

**NFR-8**: Data Privacy
- All processing 100% local
- No external API calls (except Ollama localhost)
- No telemetry/tracking
- Sensitive data never logged

**NFR-9**: Input Validation
- Sanitize file paths (prevent directory traversal)
- Validate file types
- Limit file sizes (prevent DoS)
- Rate limiting on API endpoints

### 5.5 Maintainability

**NFR-10**: Code Quality
- Type hints throughout
- Unit test coverage >70%
- Integration tests for critical paths
- Linting: black, flake8, mypy

**NFR-11**: Modularity
- Clear separation of concerns
- Pluggable rule sets
- Extensible report formats
- Easy to add new languages

### 5.6 Scalability

**NFR-12**: Resource Management
- Batch processing for large codebases
- Memory-efficient parsing
- Disk space management for reports
- Configurable concurrency

---

## 6. SECURITY RULES SPECIFICATION

### 6.1 Rule Sources

**Primary Sources** (Week 1 MVP):
1. **OWASP Top 10 (2025)**: ~30 rules
2. **CWE Top 25**: ~25 rules
3. **Bandit Python Rules**: ~40 rules

**Total MVP Rules**: ~95 rules

**Additional Sources** (Week 2-3):
4. **ISO 27001 Annex A**: ~15 framework-specific rules
5. **PCI DSS v4.0**: ~20 framework-specific rules
6. **SOC 2 Trust Criteria**: ~10 framework-specific rules

**Total Production Rules**: ~140 rules

**See**: `security_rules_sources_guide.md` for detailed source information

### 6.2 Rule Structure

**Rule Schema**:
```json
{
  "rule_id": "string (unique identifier)",
  "title": "string (short description)",
  "category": "string (OWASP/CWE category)",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "string (detailed explanation)",
  "cwe_id": "string (CWE-XXX)",
  "owasp_category": "string (A01-A10)",
  "compliance": {
    "iso_27001": ["A.9.4.3", "..."],
    "pci_dss": ["6.2.4", "..."],
    "soc_2": ["CC6.1", "..."]
  },
  "detection": {
    "pattern": "regex pattern",
    "ast_query": "tree-sitter query",
    "llm_prompt": "context for LLM"
  },
  "examples": {
    "vulnerable": "code snippet",
    "secure": "code snippet"
  },
  "remediation": "string (how to fix)",
  "references": ["url1", "url2"]
}
```

### 6.3 Priority Rules (Must Implement in MVP)

**Critical Rules** (P0):

1. **CWE-798**: Hard-coded Credentials
   - Detect: `password =`, `api_key =`, `secret =` with string literals
   - Compliance: ISO A.9.4.3, PCI 6.2.4, SOC CC6.1

2. **CWE-89**: SQL Injection
   - Detect: String concatenation in SQL queries
   - Compliance: PCI 6.2.4, SOC CC7.2

3. **CWE-79**: Cross-Site Scripting (XSS)
   - Detect: Unescaped user input in HTML output
   - Compliance: PCI 6.2.4, SOC CC7.2

4. **CWE-327**: Weak Cryptography
   - Detect: MD5, SHA1, DES usage
   - Compliance: ISO A.10.1.1, PCI 4.2, SOC CC6.7

5. **CWE-284**: Missing Authorization
   - Detect: API endpoints without auth checks
   - Compliance: ISO A.9.4.1, PCI 7.1, SOC CC6.2

6. **PCI-DSS-3.2.1**: CVV Storage (CRITICAL)
   - Detect: Variables named `cvv`, `cvv2`, `cvc2`
   - Compliance: PCI 3.2.1 (MANDATORY)

### 6.4 Rule Categories

**OWASP Top 10 (2025) Breakdown**:
- A01: Broken Access Control (8-10 rules)
- A02: Cryptographic Failures (10-12 rules)
- A03: Injection (6-8 rules)
- A04: Insecure Design (4-6 rules)
- A05: Security Misconfiguration (6-8 rules)
- A06: Vulnerable Components (2-4 rules)
- A07: Authentication Failures (6-8 rules)
- A08: Software/Data Integrity (4-6 rules)
- A09: Logging Failures (4-6 rules)
- A10: SSRF (2-4 rules)

---

## 7. REPORTING REQUIREMENTS

### 7.1 Report Formats

**Week 1 MVP**:
- JSON (complete structured data)
- Markdown (developer-friendly)

**Week 2-3**:
- PDF (executive/management/technical)
- HTML (interactive dashboard)
- CSV (spreadsheet export)

**See**: `security_scanner_reporting_spec.md` for comprehensive reporting specifications

### 7.2 Report Structure

**Three-Tier Architecture**:

1. **Executive Summary** (2 pages)
   - Overall risk score (0-100)
   - Critical findings (top 3)
   - Compliance status
   - Recommendations

2. **Management Report** (8-10 pages)
   - All findings by category
   - Remediation roadmap
   - Compliance gap analysis
   - Cost estimates

3. **Technical Details** (20+ pages)
   - Code-level findings
   - Before/after examples
   - Step-by-step remediation
   - References

### 7.3 Report Content Requirements

**Scan Metadata**:
- Scan ID (unique identifier)
- Timestamp
- Duration
- Files scanned
- Lines of code
- Languages detected
- Rules applied
- Scanner version

**Summary Statistics**:
- Total findings
- Breakdown by severity
- Breakdown by category (OWASP/CWE)
- Compliance status (ISO/PCI/SOC2)
- Security score (calculated)

**Findings List**:
- Finding ID
- Severity (color-coded)
- Title
- Category
- File path
- Line number
- Code snippet
- Description
- Impact
- Remediation
- Effort estimate
- Priority
- Compliance mapping

**Visualizations**:
- Risk gauge (overall score)
- Severity pie chart
- Category bar chart
- File heat map
- Compliance radar chart

### 7.4 Compliance Reporting

**Per Framework Summary**:

```json
{
  "iso_27001": {
    "compliant_controls": 18,
    "total_controls": 25,
    "percentage": 72,
    "status": "MOSTLY_COMPLIANT",
    "gaps": [
      {
        "control": "A.10.1.1",
        "description": "Weak encryption found",
        "violations": 3
      }
    ]
  },
  "pci_dss": {
    "compliant_requirements": 7,
    "total_requirements": 12,
    "percentage": 58,
    "status": "NON_COMPLIANT",
    "blockers": [
      {
        "requirement": "3.2.1",
        "description": "CVV storage forbidden",
        "violations": 2,
        "severity": "CRITICAL"
      }
    ]
  },
  "soc_2": {
    "compliant_criteria": 15,
    "total_criteria": 20,
    "percentage": 75,
    "status": "MOSTLY_COMPLIANT",
    "gaps": [...]
  }
}
```

---

## 8. DATA MODELS

### 8.1 Core Data Models

#### SecurityRule
```python
from pydantic import BaseModel
from typing import List, Dict, Optional

class DetectionMethod(BaseModel):
    pattern: Optional[str] = None
    ast_query: Optional[str] = None
    llm_prompt: Optional[str] = None

class CodeExample(BaseModel):
    vulnerable: str
    secure: str

class ComplianceMapping(BaseModel):
    iso_27001: List[str] = []
    pci_dss: List[str] = []
    soc_2: List[str] = []

class SecurityRule(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    compliance: ComplianceMapping
    detection: DetectionMethod
    examples: CodeExample
    remediation: str
    references: List[str] = []
```

#### Finding
```python
class Finding(BaseModel):
    finding_id: str
    rule_id: str
    severity: str
    title: str
    category: str
    file_path: str
    line_number: int
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    code_snippet: str
    description: str
    impact: str
    remediation: str
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    compliance: ComplianceMapping
    effort_estimate_hours: int
    priority: str  # P0, P1, P2, P3
    references: List[str] = []
```

#### ScanResult
```python
class ScanMetadata(BaseModel):
    scan_id: str
    timestamp: str
    duration_seconds: int
    scanner_version: str
    rules_version: str

class ScanScope(BaseModel):
    repository: str
    branch: Optional[str] = None
    commit: Optional[str] = None
    files_scanned: int
    lines_of_code: int
    languages: Dict[str, int]  # {"Python": 92, "JavaScript": 8}

class ScanSummary(BaseModel):
    total_findings: int
    by_severity: Dict[str, int]  # {"CRITICAL": 3, "HIGH": 12, ...}
    by_category: Dict[str, int]  # {"Injection": 4, ...}
    security_score: int  # 0-100
    compliance: Dict[str, Dict]  # Compliance status per framework

class ScanResult(BaseModel):
    metadata: ScanMetadata
    scope: ScanScope
    summary: ScanSummary
    findings: List[Finding]
    files_analyzed: List[Dict]  # File paths + violation counts
```

### 8.2 Database Schema (ChromaDB)

**Collection**: `security_rules`
- **Documents**: Rule text (description + examples)
- **Embeddings**: sentence-transformers embeddings
- **Metadata**: rule_id, category, severity, compliance mappings

**Collection**: `scan_history`
- **Documents**: Scan summaries
- **Metadata**: scan_id, timestamp, repository, summary stats

---

## 9. API SPECIFICATIONS

### 9.1 REST API Endpoints

**Base URL**: `http://localhost:8000`

#### Health Check
```
GET /health
Response: {"status": "healthy", "ollama_connected": true}
```

#### Rule Management
```
POST /rules/upload
Content-Type: multipart/form-data
Body: {file: PDF file}
Response: {status: "success", rules_extracted: 42}

GET /rules
Response: {rules: [...], total: 142}

GET /rules/{rule_id}
Response: {rule object}
```

#### Scanning
```
POST /scan
Content-Type: application/json
Body: {
  "codebase_path": "/path/to/code",
  "rule_set": ["owasp", "cwe", "iso27001", "pci_dss", "soc2"],
  "output_formats": ["json", "markdown"],
  "exclude_patterns": ["**/test_*.py", "**/vendor/**"]
}
Response: {
  "scan_id": "scan_20260216_143022",
  "status": "running",
  "estimated_time": 1200
}

GET /scan/{scan_id}
Response: {
  "scan_id": "...",
  "status": "completed|running|failed",
  "progress": 75,
  "result": {ScanResult object}
}

GET /scan/{scan_id}/findings
Query params: ?severity=CRITICAL&category=Injection
Response: {findings: [...]}
```

#### Reporting
```
GET /reports/{scan_id}/{format}
Formats: json, markdown, pdf, html, csv
Response: File download

GET /reports/{scan_id}/compliance/{framework}
Frameworks: iso27001, pci_dss, soc2
Response: {compliance status object}
```

### 9.2 WebSocket API (Optional - Week 3)

```
WS /scan/stream
Purpose: Real-time scan progress updates

Messages:
{
  "event": "progress",
  "scan_id": "...",
  "progress": 45,
  "current_file": "src/auth/login.py",
  "findings_count": 12
}

{
  "event": "complete",
  "scan_id": "...",
  "summary": {...}
}
```

---

## 10. IMPLEMENTATION PHASES

### 10.1 Phase 1: Foundation (Days 1-2)

**Day 1: Environment Setup + PDF Parsing** (2 hours)
- ✅ Install Homebrew, Python 3.11, Ollama
- ✅ Download DeepSeek-Coder 13B model
- ✅ Set up project structure
- ✅ Implement PDF parser (PyMuPDF)
- ✅ Test on OWASP Top 10 PDF

**Day 2: Code Analysis Engine** (2 hours)
- ✅ Set up tree-sitter
- ✅ Implement Python AST parsing
- ✅ Pattern matching (regex-based)
- ✅ Test on sample Python files

**Deliverables**:
- PDF → JSON rule extraction working
- Python file → AST parsing working
- ~20 rules extracted from OWASP PDF

### 10.2 Phase 2: Core Scanning (Days 3-4)

**Day 3: LLM Integration** (2 hours)
- ✅ Ollama Python client setup
- ✅ Prompt engineering
- ✅ ChromaDB integration
- ✅ Vector search for rules

**Day 4: FastAPI Application** (2 hours)
- ✅ FastAPI project setup
- ✅ Core endpoints (/scan, /rules/upload)
- ✅ Pydantic models
- ✅ Background task processing

**Deliverables**:
- LLM analyzing code snippets
- FastAPI responding to requests
- End-to-end: upload code → get findings

### 10.3 Phase 3: Integration & Testing (Days 5-6)

**Day 5: Full Integration** (2 hours)
- ✅ Connect all components
- ✅ PDF → Rules → Vector DB → Code → LLM → Findings
- ✅ JSON + Markdown report generation
- ✅ Test on real codebase (500 files)

**Day 6: Testing & Bug Fixes** (2 hours)
- ✅ Unit tests (pytest)
- ✅ Integration tests
- ✅ Edge case handling
- ✅ Performance optimization

**Deliverables**:
- Working end-to-end scanner
- JSON + Markdown reports
- Test coverage >50%

### 10.4 Phase 4: Deployment (Day 7)

**Day 7: Docker + Documentation** (2 hours)
- ✅ Dockerfile for FastAPI
- ✅ docker-compose.yml (hybrid setup)
- ✅ README.md
- ✅ Deployment guide for friend

**Deliverables**:
- Deployable Docker container
- Complete documentation
- Ready for friend to use

### 10.5 Phase 5: Enhancement (Weeks 2-3)

**Week 2**:
- PDF report generation (WeasyPrint)
- HTML dashboard (with charts)
- CSV export
- Compliance-specific rules (ISO/PCI/SOC2)

**Week 3**:
- Multi-language support (JavaScript, Java)
- Historical tracking
- Performance optimization
- Production hardening

---

## 11. SUCCESS METRICS

### 11.1 Functional Metrics

**Accuracy**:
- ✅ True positive rate >85% (correct violations detected)
- ✅ False positive rate <15% (incorrect violations)
- ✅ Compliance mapping accuracy: 100%

**Coverage**:
- ✅ 95 rules implemented (Week 1)
- ✅ 140 rules implemented (Week 3)
- ✅ Python support: 100%
- ✅ JavaScript support: 80% (Week 3)

**Performance**:
- ✅ 500 files scanned in <25 minutes
- ✅ Report generation in <30 seconds
- ✅ API response time: <1 second (non-scan endpoints)

### 11.2 User Metrics

**Consultant Satisfaction**:
- ✅ Can complete client assessment in <30 minutes
- ✅ Reports are stakeholder-ready (no manual editing)
- ✅ 90%+ of findings are actionable

**Client Satisfaction**:
- ✅ Executive summary readable in <5 minutes
- ✅ Developers can understand remediation steps
- ✅ Compliance status is clear

### 11.3 Technical Metrics

**Reliability**:
- ✅ Uptime: 99%+ (local app)
- ✅ Error rate: <1%
- ✅ All scans complete successfully

**Maintainability**:
- ✅ Code coverage: >70%
- ✅ Documentation: 100% of public APIs
- ✅ Type hints: 100% coverage

---

## 12. OUT OF SCOPE

### 12.1 Explicitly Out of Scope (v1.0)

**Not Included**:
- ❌ Real-time code scanning (IDE integration)
- ❌ Automatic remediation (code fixes)
- ❌ Cloud deployment / SaaS version
- ❌ Multi-user / team collaboration
- ❌ Issue tracking integration (Jira/GitHub)
- ❌ CI/CD pipeline integration
- ❌ Mobile app
- ❌ Web-based UI (only API in MVP)
- ❌ Custom rule creation UI
- ❌ Container/Docker image scanning
- ❌ Infrastructure-as-Code scanning
- ❌ Dependency vulnerability scanning (focus is on code)

### 12.2 Future Considerations (v2.0+)

**Potential Future Features**:
- GitHub Actions integration
- GitLab CI integration
- VS Code extension
- Automatic PR comments with findings
- Trend analysis dashboard
- Team collaboration features
- Custom rule builder UI
- AI-powered automatic fixes
- Additional compliance frameworks (HIPAA, GDPR, etc.)
- Additional languages (Go, Rust, C++, etc.)

---

## 13. APPENDICES

### 13.1 Reference Documents

**Planning Documents** (from previous session):
1. `security_rules_sources_guide.md` - Where to get rules
2. `security_scanner_reporting_spec.md` - Report format details
3. `compliance_frameworks_integration.md` - ISO/PCI/SOC2 details
4. `context_transfer_guide.md` - How to use in Claude Code

### 13.2 File Structure

```
security-scanner/
├── README.md
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── .gitignore
├── docs/
│   ├── architecture.md
│   ├── api_reference.md
│   ├── deployment.md
│   └── development.md
├── src/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app
│   ├── config.py                  # Configuration
│   ├── models.py                  # Pydantic models
│   ├── api/
│   │   ├── __init__.py
│   │   ├── rules.py              # Rule management endpoints
│   │   ├── scan.py               # Scanning endpoints
│   │   └── reports.py            # Report endpoints
│   ├── core/
│   │   ├── __init__.py
│   │   ├── pdf_parser.py         # PDF extraction
│   │   ├── code_analyzer.py      # Tree-sitter parsing
│   │   ├── llm_interface.py      # Ollama client
│   │   ├── vector_store.py       # ChromaDB
│   │   └── rule_matcher.py       # Pattern + LLM matching
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── json_report.py
│   │   ├── markdown_report.py
│   │   ├── pdf_report.py         # Week 2
│   │   ├── html_report.py        # Week 2
│   │   └── csv_report.py         # Week 2
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       └── helpers.py
├── data/
│   ├── security_rules/           # PDF storage
│   │   ├── owasp_top10.pdf
│   │   ├── cwe_top25.pdf
│   │   └── ...
│   ├── vector_db/                # ChromaDB data
│   └── models/                   # Downloaded LLM models (if needed)
├── tests/
│   ├── __init__.py
│   ├── test_pdf_parser.py
│   ├── test_code_analyzer.py
│   ├── test_llm_interface.py
│   └── test_api.py
└── outputs/                      # Generated reports
    ├── scan_20260216_143022.json
    ├── scan_20260216_143022.md
    └── ...
```

### 13.3 Dependencies (requirements.txt)

```
# Core Framework
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.0
python-multipart==0.0.6

# LLM Integration
ollama==0.1.6

# PDF Processing
pymupdf==1.23.0
pdfplumber==0.10.0

# Code Analysis
tree-sitter==0.20.4
tree-sitter-python==0.20.4
tree-sitter-javascript==0.20.1
tree-sitter-java==0.20.2

# Vector Database
chromadb==0.4.22
sentence-transformers==2.3.1

# Report Generation
jinja2==3.1.2
weasyprint==60.0
markdown==3.5
matplotlib==3.8.0
plotly==5.18.0

# Utilities
python-dotenv==1.0.0
loguru==0.7.2
tqdm==4.66.0
rich==13.7.0
pyyaml==6.0.1

# Testing
pytest==7.4.4
pytest-asyncio==0.21.1
httpx==0.25.2
pytest-cov==4.1.0

# Development
black==23.12.0
flake8==6.1.0
mypy==1.7.0
```

### 13.4 Environment Variables (.env)

```bash
# Ollama Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=deepseek-coder:33b-instruct-q4_K_M

# Application Settings
APP_NAME=Security Scanner
APP_VERSION=1.0.0
DEBUG=false
LOG_LEVEL=INFO

# Paths
DATA_DIR=./data
OUTPUT_DIR=./outputs
RULES_DIR=./data/security_rules
VECTOR_DB_DIR=./data/vector_db

# Scanning Configuration
MAX_FILE_SIZE_MB=10
SCAN_TIMEOUT_SECONDS=3600
MAX_CONCURRENT_FILES=5

# Report Configuration
DEFAULT_OUTPUT_FORMATS=json,markdown
INCLUDE_CODE_SNIPPETS=true
MAX_SNIPPET_LINES=10

# Security
API_KEY=your-secret-key-here  # Optional for production
ALLOWED_ORIGINS=http://localhost:3000

# Performance
EMBEDDING_BATCH_SIZE=32
LLM_CONTEXT_WINDOW=8000
LLM_MAX_TOKENS=2000
```

---

## SIGN-OFF

**Prepared By**: JO  
**Date**: February 16, 2026  
**Status**: APPROVED - Ready for Implementation

**Next Steps**:
1. Review PRD with friend (security consultant)
2. Confirm compliance framework priorities
3. Begin Day 1 implementation
4. Use this PRD in Claude Code for guided development

**Contact**:
- For questions: Refer to planning documents in `/docs` folder
- For implementation: Use Claude Code with this PRD as context

---

**END OF PRD**
