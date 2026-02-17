# Local Security Scanner

AI-powered security code scanner that analyzes Python codebases against ISO 27001, PCI DSS, and SOC 2 compliance frameworks. Runs 100% locally using Ollama + DeepSeek-Coder LLM.

## Quick Start

```bash
# Clone and setup
git clone <repo-url>
cd local-security-scanner
cp .env.example .env
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Project Status

| Day | Phase | Status |
|-----|-------|--------|
| 1 | Scaffolding, config, models, rules, PDF parser | Complete |
| 2 | Tree-sitter code analysis engine + pattern matching | Complete |
| 3 | LLM integration (Ollama) + ChromaDB | Complete |
| 4 | FastAPI application + Docker Compose | Complete |
| 5 | Full integration (end-to-end) | Complete |
| 6 | Testing + bug fixes | Pending |
| 7 | Docker setup + documentation | Pending |

---

## Day 1: Foundation — Scaffolding, Config, Models, Rules, PDF Parser

### What Was Built

| Component | File | Description |
|-----------|------|-------------|
| Config | `src/config.py` | Pydantic-settings configuration loaded from `.env` |
| Data Models | `src/models.py` | All Pydantic v2 models: SecurityRule, Finding, ScanResult, API request/response models |
| Logger | `src/utils/logger.py` | Loguru-based structured logging |
| Helpers | `src/utils/helpers.py` | Path sanitization, code snippet extraction, language detection, file hashing |
| PDF Parser | `src/core/pdf_parser.py` | PyMuPDF-based PDF text/table extraction with OWASP/CWE auto-detection |
| Security Rules | `data/security_rules/builtin_rules.json` | 30 real OWASP Top 10 rules with regex patterns, compliance mappings, code examples |
| CWE Placeholder | `data/security_rules/cwe_rules_placeholder.json` | 3 placeholder rules (Phase 2) |
| Bandit Placeholder | `data/security_rules/bandit_rules_placeholder.json` | 3 placeholder rules (Phase 2) |

### How to Run & Verify Day 1

**Prerequisites**: Python 3.11+

```bash
# 1. Set up the virtual environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Verify 1: Config loads from .env

```bash
python -c "
from src.config import get_settings
s = get_settings()
print(f'App: {s.app_name} v{s.app_version}')
print(f'LLM: {s.ollama_model} @ {s.ollama_host}')
print(f'Rules dir: {s.rules_dir}')
print(f'Output formats: {s.output_formats_list}')
print('Config OK')
"
```

**Expected output**:
```
App: Security Scanner v1.0.0
LLM: deepseek-coder:6.7b @ http://localhost:11434
Rules dir: data/security_rules
Output formats: ['json', 'markdown']
Config OK
```

#### Verify 2: Pydantic models validate correctly

```bash
python -c "
from src.models import SecurityRule, Finding, ScanResult, ScanMetadata, ScanScope, Severity, Priority

# Test SecurityRule creation
rule = SecurityRule(
    rule_id='TEST-001',
    title='Test Rule',
    category='Test',
    severity=Severity.HIGH,
    description='A test rule',
)
print(f'Rule: {rule.rule_id} - {rule.title} [{rule.severity.value}]')

# Test Finding creation
finding = Finding(
    finding_id='FIND-0001',
    rule_id='TEST-001',
    severity=Severity.HIGH,
    title='Test Finding',
    category='Test',
    file_path='src/example.py',
    line_number=42,
    code_snippet='password = \"secret\"',
)
print(f'Finding: {finding.finding_id} at {finding.file_path}:{finding.line_number}')

# Test ScanResult
result = ScanResult(
    metadata=ScanMetadata(scan_id='scan_test'),
    scope=ScanScope(repository='test-repo', files_scanned=10),
)
print(f'Scan: {result.metadata.scan_id} - {result.scope.files_scanned} files')
print('Models OK')
"
```

**Expected output**:
```
Rule: TEST-001 - Test Rule [HIGH]
Finding: FIND-0001 at src/example.py:42
Scan: scan_test - 10 files
Models OK
```

#### Verify 3: Security rules load and deserialize

```bash
python -c "
import json
from pathlib import Path
from src.models import SecurityRule

rules_path = Path('data/security_rules/builtin_rules.json')
raw = json.loads(rules_path.read_text())
rules = [SecurityRule(**r) for r in raw]

print(f'Loaded {len(rules)} OWASP rules')
print()

# Show severity breakdown
from collections import Counter
severity_counts = Counter(r.severity.value for r in rules)
for sev, count in sorted(severity_counts.items()):
    print(f'  {sev}: {count}')

print()
# Show categories
categories = set(r.owasp_category for r in rules if r.owasp_category)
print(f'OWASP categories covered: {sorted(categories)}')

# Verify compliance mappings exist
rules_with_compliance = sum(
    1 for r in rules
    if r.compliance.iso_27001 or r.compliance.pci_dss or r.compliance.soc_2
)
print(f'Rules with compliance mappings: {rules_with_compliance}/{len(rules)}')

# Verify detection patterns exist
rules_with_patterns = sum(1 for r in rules if r.detection.pattern)
print(f'Rules with regex patterns: {rules_with_patterns}/{len(rules)}')
print()
print('Rules OK')
"
```

**Expected output**:
```
Loaded 30 OWASP rules

  CRITICAL: 8
  HIGH: 12
  LOW: 1
  MEDIUM: 9

OWASP categories covered: ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']
Rules with compliance mappings: 30/30
Rules with regex patterns: 25/30
Rules OK
```

#### Verify 4: Helper utilities work

```bash
python -c "
from pathlib import Path
from src.utils.helpers import (
    generate_scan_id,
    generate_finding_id,
    sanitize_path,
    detect_language,
    extract_code_snippet,
    count_lines,
)

# Test scan ID generation
scan_id = generate_scan_id()
print(f'Generated scan ID: {scan_id}')

# Test finding ID generation
fid = generate_finding_id(scan_id, 1)
print(f'Generated finding ID: {fid}')

# Test language detection
for ext in ['.py', '.js', '.java', '.go', '.rs']:
    lang = detect_language(Path(f'test{ext}'))
    print(f'  {ext} -> {lang}')

# Test path sanitization
try:
    sanitize_path('../../../etc/passwd')
    print('ERROR: Should have caught traversal!')
except ValueError as e:
    print(f'Path traversal blocked: {e}')

# Test code snippet extraction on a real file
snippet = extract_code_snippet(Path('src/config.py'), 5, context_lines=2)
print(f'Code snippet (5 lines):\\n{snippet[:200]}')
print()
print('Helpers OK')
"
```

#### Verify 5: PDF parser imports and initializes

```bash
python -c "
from src.core.pdf_parser import PDFParser

parser = PDFParser()
print(f'PDFParser created: {type(parser).__name__}')
print(f'Methods: extract_text, extract_tables, parse_owasp_rules, parse_cwe_rules, parse_pdf_to_rules, export_rules_to_json')

# Test export_rules_to_json with sample data
from src.models import SecurityRule, Severity
import tempfile, os

rules = [SecurityRule(
    rule_id='TEST-001',
    title='Test',
    category='Test',
    severity=Severity.HIGH,
    description='Test rule',
)]

with tempfile.TemporaryDirectory() as tmpdir:
    output = parser.export_rules_to_json(rules, os.path.join(tmpdir, 'test.json'))
    print(f'Exported rules to: {output}')
    content = open(output).read()
    print(f'File size: {len(content)} bytes')

print()
print('PDF Parser OK')
"
```

**Note**: Full PDF parsing (extract_text, parse_owasp_rules) requires a real PDF file. Place OWASP Top 10 or CWE PDF files in `data/security_rules/` to test parsing.

### Architecture Notes (Day 1)

```
src/
├── __init__.py
├── config.py              # Settings from .env via pydantic-settings
├── models.py              # All Pydantic data models
├── api/
│   └── __init__.py
├── core/
│   ├── __init__.py
│   └── pdf_parser.py      # PDF rule extraction
├── reports/
│   └── __init__.py
└── utils/
    ├── __init__.py
    ├── helpers.py          # Utility functions
    └── logger.py           # Loguru config

data/security_rules/
├── builtin_rules.json             # 30 OWASP rules (active)
├── cwe_rules_placeholder.json     # CWE placeholder (Phase 2)
└── bandit_rules_placeholder.json  # Bandit placeholder (Phase 2)
```

---

## Day 2: Code Analysis Engine — Rule Loader, Pattern Matcher, Tree-sitter Parser

### What Was Built

| Component | File | Description |
|-----------|------|-------------|
| Rule Loader | `src/core/rule_loader.py` | Loads security rules from JSON files, indexes by ID, filters by severity/category |
| Pattern Matcher | `src/core/pattern_matcher.py` | Compiles regex patterns from rules, scans files/text/directories for matches |
| Tree-sitter Parser | `src/core/tree_sitter_parser.py` | Parses Python AST — extracts functions, classes, imports, decorators |
| Code Analyzer | `src/core/analyzer.py` | Orchestrator that combines all components to scan a codebase and produce findings |

### How to Run & Verify Day 2

**Prerequisites**: Day 1 setup complete (venv activated, dependencies installed)

#### Verify 1: Rule loader

```bash
python -c "
from src.core.rule_loader import RuleLoader

loader = RuleLoader()
count = loader.load_builtin_rules()
print(f'Loaded {count} builtin rules')
print(f'Rules with patterns: {len(loader.get_rules_with_patterns())}')
print(f'Categories: {sorted(loader.get_categories())}')
print(f'CRITICAL rules: {len(loader.get_rules_by_severity(\"CRITICAL\"))}')
print('RuleLoader OK')
"
```

**Expected**: 30 rules loaded, 25 with patterns, 10 OWASP categories, 8 CRITICAL.

#### Verify 2: Pattern matcher detects vulnerabilities

```bash
python -c "
from src.core.rule_loader import RuleLoader
from src.core.pattern_matcher import PatternMatcher

loader = RuleLoader()
loader.load_builtin_rules()
matcher = PatternMatcher(loader.get_rules_with_patterns())
print(f'Matcher ready with {matcher.rule_count} patterns')

test_code = '''
import os
DB_PASSWORD = \"SuperSecret123\"
os.system(f\"ls {user_input}\")
query = f\"SELECT * FROM users WHERE id = {uid}\"
data = pickle.loads(request.data)
'''

matches = matcher.scan_text(test_code, 'test_vulnerable.py')
print(f'Found {len(matches)} matches in test code:')
for m in matches:
    print(f'  Line {m.line_number}: [{m.rule.severity.value}] {m.rule.title}')
print('PatternMatcher OK')
"
```

**Expected**: 3 matches found — Hard-coded Credentials, OS Command Injection, Insecure Deserialization.

#### Verify 3: Tree-sitter parses Python structure

```bash
python -c "
from src.core.tree_sitter_parser import TreeSitterParser

parser = TreeSitterParser()
test_code = '''
import os
from pathlib import Path

class UserService:
    def get_user(self, user_id: int) -> dict:
        return db.find(user_id)

@app.get(\"/users\")
@login_required
def list_users(request):
    return UserService().get_all()
'''

analysis = parser.parse_text(test_code, 'test_service.py')
print(f'Imports: {len(analysis.imports)}')
print(f'Classes: {len(analysis.classes)} ({analysis.classes[0].name}, {len(analysis.classes[0].methods)} methods)')
print(f'Functions: {len(analysis.functions)} ({analysis.functions[0].name})')
print(f'Decorators on list_users: {analysis.functions[0].decorators}')
print('TreeSitterParser OK')
"
```

**Expected**: 2 imports, 1 class (UserService with 1 method), 1 function (list_users with 2 decorators).

#### Verify 4: Full scan of a codebase

```bash
python -c "
from src.core.analyzer import CodeAnalyzer

analyzer = CodeAnalyzer()
result = analyzer.scan_codebase('src/')
print(f'Scan ID: {result.metadata.scan_id}')
print(f'Files scanned: {result.scope.files_scanned}')
print(f'Lines of code: {result.scope.lines_of_code}')
print(f'Total findings: {result.summary.total_findings}')
print(f'Security score: {result.summary.security_score}/100')
print(f'By severity: {result.summary.by_severity}')
print('CodeAnalyzer OK')
"
```

**Expected**: Scans all .py files under src/, produces findings and a security score.

### Architecture Notes (Day 2)

```
src/core/
├── analyzer.py           # Orchestrator: scan codebase -> ScanResult
├── pattern_matcher.py    # Regex engine: compiled patterns -> matches
├── rule_loader.py        # Load JSON rules -> SecurityRule objects
├── tree_sitter_parser.py # AST parser: Python -> functions, classes, imports
└── pdf_parser.py         # (Day 1) PDF rule extraction

Flow:
  RuleLoader -> loads rules from JSON
       |
  PatternMatcher -> compiles regex patterns from rules
       |
  CodeAnalyzer -> for each file:
       |            1. PatternMatcher.scan_file() -> regex matches
       |            2. TreeSitterParser.parse_file() -> AST analysis
       |            3. Convert matches -> Finding objects
       v
  ScanResult (findings, summary, metadata)
```

---

## Day 3: LLM Integration — Ollama Client, LLM Analyzer, ChromaDB Vector Store

### What Was Built

| Component | File | Description |
|-----------|------|-------------|
| Ollama Client | `src/core/llm_client.py` | Connects to local Ollama instance, sends prompts, parses JSON responses defensively, handles retries and context window limits |
| LLM Analyzer | `src/core/llm_analyzer.py` | Uses LLM for deep security analysis: per-rule contextual scanning, false positive validation, code complexity detection |
| Vector Store | `src/core/vector_store.py` | ChromaDB-backed semantic search — embeds security rules, finds the most relevant rules for a given code snippet |

### How to Run & Verify Day 3

**Prerequisites**: Day 1-2 setup complete, Ollama installed and running

#### Verify 1: Ollama client connects and checks model availability

```bash
# First, make sure Ollama is running:
ollama serve &  # if not already running

# Pull the dev model (if not already pulled):
ollama pull deepseek-coder:6.7b

# Verify the client:
python -c "
from src.core.llm_client import OllamaClient

client = OllamaClient()
print(f'LLM available: {client.is_available()}')
print(f'Token estimate for 400 chars: {client.estimate_tokens(\"x\" * 400)}')
print(f'Fits context: {client.fits_context(\"x\" * 1000)}')
print('OllamaClient OK')
"
```

**Expected**: `LLM available: True` (if deepseek-coder:6.7b is pulled), token estimate ~100, fits context True.

#### Verify 2: LLM analyzer complexity detection (no LLM needed)

```bash
python -c "
from src.core.llm_analyzer import LLMAnalyzer
from src.core.tree_sitter_parser import TreeSitterParser

parser = TreeSitterParser()
analyzer = LLMAnalyzer()

# Create test code with a very long function
long_func = 'def process_data(a, b, c, d, e, f, g, h):\n' + '    x = 1\n' * 60
analysis = parser.parse_text(long_func, 'test_complex.py')

issues = analyzer.detect_complexity_issues(analysis)
print(f'Complexity issues found: {len(issues)}')
for issue in issues:
    print(f'  - {issue.function_name}: {issue.issue[:80]}...')

findings = analyzer.complexity_to_findings(issues)
print(f'Converted to {len(findings)} findings')
for f in findings:
    print(f'  [{f.severity.value}] {f.title}')
print('Complexity detection OK')
"
```

**Expected**: 2 complexity issues — function too long (61 lines > 50 threshold) and too many parameters (8 > 7 threshold).

#### Verify 3: LLM-powered code analysis (requires Ollama + model)

```bash
python -c "
from src.core.llm_analyzer import LLMAnalyzer
from src.models import SecurityRule, Severity, DetectionMethod

analyzer = LLMAnalyzer()
if not analyzer.is_available:
    print('LLM not available — skipping (pull deepseek-coder:6.7b first)')
else:
    rule = SecurityRule(
        rule_id='TEST-LLM-001',
        title='SQL Injection',
        category='Injection',
        severity=Severity.CRITICAL,
        description='Detect SQL injection via string concatenation',
        detection=DetectionMethod(
            llm_prompt='Check if user input is concatenated into SQL queries without parameterization'
        ),
    )

    code = '''
def get_user(user_id):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"
    return db.execute(query)
'''

    finding = analyzer.analyze_code_with_rule(code, rule, 'test.py')
    if finding:
        print(f'Finding: [{finding.severity.value}] {finding.title}')
        print(f'  Line: {finding.line_number}')
        print(f'  Description: {finding.description[:100]}')
    else:
        print('No finding (LLM did not flag this — may vary by model)')
    print('LLM analysis OK')
"
```

**Expected**: LLM detects the SQL injection and returns a Finding (results may vary depending on model).

#### Verify 4: ChromaDB vector store indexes and queries rules

```bash
python -c "
from src.core.vector_store import VectorStore
from src.core.rule_loader import RuleLoader

# Load rules
loader = RuleLoader()
loader.load_builtin_rules()
print(f'Loaded {len(loader.rules)} rules')

# Index into ChromaDB
store = VectorStore(persist_dir='/tmp/test_vector_db')
indexed = store.index_rules(loader.rules)
print(f'Indexed {indexed} rules into ChromaDB')
print(f'Collection size: {store.rule_count}')

# Query with a code snippet
code = '''
password = \"admin123\"
db_connection = connect(host, user, password)
'''
relevant = store.query_relevant_rules(code, n_results=3)
print(f'Top 3 relevant rules for hardcoded password code:')
for r in relevant:
    print(f'  [{r.severity.value}] {r.rule_id}: {r.title}')

# Cleanup
store.clear()
print('VectorStore OK')
"
```

**Expected**: 30 rules indexed, query returns rules related to hardcoded credentials/authentication.

### Architecture Notes (Day 3)

```
src/core/
├── llm_client.py        # Ollama connection + prompt/response handling
├── llm_analyzer.py      # LLM-powered security analysis + complexity
├── vector_store.py      # ChromaDB semantic rule matching
├── analyzer.py          # (Day 2) Orchestrator
├── pattern_matcher.py   # (Day 2) Regex engine
├── rule_loader.py       # (Day 2) JSON rule loading
├── tree_sitter_parser.py # (Day 2) AST parser
└── pdf_parser.py        # (Day 1) PDF extraction

Three-layer scanning pipeline:
  1. Regex (fast)    — PatternMatcher scans all files against 25 regex rules
  2. Semantic (smart) — VectorStore finds relevant rules per code snippet
  3. LLM (deep)      — LLMAnalyzer does contextual analysis + validation

  Code Snippet
       |
  VectorStore.query_relevant_rules()
       |  (top N semantically similar rules)
       v
  LLMAnalyzer.analyze_code_with_rules()
       |  (LLM confirms/denies vulnerability)
       v
  Findings (high confidence, low false-positive rate)

Additional:
  - LLMAnalyzer.validate_finding() — validates regex findings to reduce false positives
  - LLMAnalyzer.detect_complexity_issues() — flags overly complex functions (no LLM needed)
```

---

## Day 4: FastAPI Application + Docker Compose

### What Was Built

| Component | File | Description |
|-----------|------|-------------|
| Scan Manager | `src/api/scan_manager.py` | In-memory scan state tracking, background task orchestration, singleton component management |
| API Routes | `src/api/routes.py` | 5 endpoints: start scan, get status, health check, upload rules PDF, list rules |
| App Factory | `src/main.py` | FastAPI app with lifespan, CORS, API versioning at `/api/v1` |
| Dockerfile | `Dockerfile` | Python 3.11-slim container with tree-sitter + WeasyPrint system deps, non-root user |
| Docker Compose | `docker-compose.yml` | Orchestrates FastAPI container, connects to host Ollama via `host.docker.internal:11434` |
| Docker Ignore | `.dockerignore` | Excludes .venv, .git, tests, docs, .env from build context |

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scan` | Start a background scan (returns 202) |
| `GET` | `/api/v1/scan/{scan_id}` | Get scan status and results |
| `GET` | `/api/v1/health` | Health check (Ollama, rules, version) |
| `POST` | `/api/v1/rules/upload` | Upload a PDF to extract security rules |
| `GET` | `/api/v1/rules` | List all loaded security rules |

### How to Run & Verify Day 4

**Prerequisites**: Day 1-3 setup complete (venv activated, dependencies installed, Ollama running)

#### Option A: Run locally (no Docker)

```bash
# Start the API server
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

#### Option B: Run with Docker Compose

```bash
# Make sure Ollama is running on the host
ollama serve &

# Build and start the container
docker-compose up --build

# The API is available at http://localhost:8000
```

#### Verify 1: Health check

```bash
curl -s http://localhost:8000/api/v1/health | python -m json.tool
```

**Expected output**:
```json
{
    "status": "healthy",
    "ollama_connected": true,
    "scanner_version": "1.0.0",
    "rules_loaded": 30
}
```

Note: `ollama_connected` will be `true` if deepseek-coder:6.7b is pulled and Ollama is running. Status will be "degraded" (not "unhealthy") if Ollama is offline — regex scanning still works.

#### Verify 2: List security rules

```bash
curl -s http://localhost:8000/api/v1/rules | python -m json.tool | head -20
```

**Expected**: JSON with `total: 30` and a list of OWASP rules with rule_id, title, category, severity.

#### Verify 3: Start a scan and check results

```bash
# Start a scan of the src/ directory
curl -s -X POST "http://localhost:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"codebase_path":"src/"}' | python -m json.tool

# Note the scan_id from the response, then check status:
curl -s "http://localhost:8000/api/v1/scan/{scan_id}" | python -m json.tool
```

**Expected**: First call returns 202 with `status: "pending"`. Second call (after a second) returns `status: "completed"` with full scan results including findings, summary, and security score.

#### Verify 4: Interactive API docs

Open in your browser:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Architecture Notes (Day 4)

```
Request Flow:
  Client (curl / browser / frontend)
       |
  FastAPI (src/main.py)
       |  CORS middleware, /api/v1 prefix
       v
  Routes (src/api/routes.py)
       |  Path validation, request parsing
       v
  ScanManager (src/api/scan_manager.py)
       |  In-memory state, background tasks
       v
  CodeAnalyzer (src/core/analyzer.py)
       |  Pattern matching + tree-sitter AST
       v
  ScanResult → JSON response

Docker Architecture:
  ┌─────────────────────────┐     ┌──────────────────────┐
  │  Docker Container       │     │  Host Machine (bare)  │
  │                         │     │                       │
  │  FastAPI (port 8000)    │────▶│  Ollama (port 11434)  │
  │  tree-sitter, ChromaDB  │     │  deepseek-coder:6.7b  │
  │  PyMuPDF, WeasyPrint    │     │  Metal GPU accel      │
  └─────────────────────────┘     └──────────────────────┘
        host.docker.internal:11434
```

---

## Day 5: Full End-to-End Integration

### What Was Built

Day 5 wires together all components from Days 1-4 into a fully functional three-layer scanning pipeline. Before this, the analyzer only used regex + tree-sitter. Now it also uses ChromaDB semantic search, LLM deep analysis, complexity detection, false positive filtering, and report generation.

| Component | File | Description |
|-----------|------|-------------|
| Analyzer Refactor | `src/core/analyzer.py` | Major refactor — wired LLM + VectorStore + complexity detection into `scan_codebase()` with graceful degradation |
| Scan Manager Update | `src/api/scan_manager.py` | Added ReportManager integration and `report_paths` tracking in scan state |
| JSON Report | `src/reports/json_report.py` | Generates structured JSON reports from `ScanResult` |
| Markdown Report | `src/reports/markdown_report.py` | Generates human-readable Markdown reports with executive summary, findings table, severity breakdown |
| Report Manager | `src/reports/report_manager.py` | Orchestrator that dispatches to format-specific generators, returns `{format: file_path}` |
| Routes Update | `src/api/routes.py` | Scan status response now includes `report_urls` with paths to generated reports |

### Three-Layer Pipeline (Now Fully Wired)

```
Layer 1: Regex (fast, broad)
  PatternMatcher scans all files against 25 regex rules
       |
Layer 1.5: Complexity Detection (tree-sitter, no LLM)
  Flags functions that are too long, too complex, or have too many parameters
       |
Layer 2: Semantic Matching (ChromaDB)
  VectorStore.query_relevant_rules() finds top 5 rules per file
       |
Layer 3: LLM Deep Analysis (Ollama + DeepSeek-Coder)
  LLMAnalyzer.analyze_code_with_rules() does contextual analysis
       |
Layer 3.5: False Positive Validation
  LLM validates CRITICAL/HIGH regex findings to reduce noise
       |
  All findings combined → ScanResult → Reports (JSON + Markdown)
```

### Graceful Degradation

The scanner works at multiple capability levels:

| Mode | When | What Works |
|------|------|------------|
| Full | Ollama running + model pulled | All 3 layers + validation + reports |
| Degraded | Ollama offline | Regex + complexity only (still useful) |
| Minimal | No dependencies | Regex scanning only |

### How to Run & Verify Day 5

**Prerequisites**: Day 1-4 setup complete, Ollama running with deepseek-coder:6.7b

#### Verify 1: Full pipeline scan via API

```bash
# Start the server
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Run a scan
curl -s -X POST "http://localhost:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"codebase_path":"src/"}' | python -m json.tool

# Wait for completion (LLM analysis takes a few minutes), then:
curl -s "http://localhost:8000/api/v1/scan/{scan_id}" | python -m json.tool
```

**Expected**: Response includes findings from all three layers:
- `regex` findings (pattern matches)
- `llm` findings (LLM-detected issues)
- `complexity` findings (overly complex functions)
- `report_urls` with paths to JSON and Markdown reports

#### Verify 2: Check generated reports

```bash
# List generated reports
ls -la outputs/

# View JSON report
cat outputs/scan_*.json | python -m json.tool | head -30

# View Markdown report
cat outputs/scan_*.md | head -50
```

**Expected**: `outputs/` contains `{scan_id}.json` and `{scan_id}.md` files with full scan results.

#### Verify 3: Analyzer directly (no API)

```bash
python -c "
from src.core.analyzer import CodeAnalyzer

analyzer = CodeAnalyzer(enable_llm=True)
result = analyzer.scan_codebase('src/')

print(f'Scan: {result.metadata.scan_id}')
print(f'Files: {result.scope.files_scanned}')
print(f'Total findings: {result.summary.total_findings}')
print(f'Security score: {result.summary.security_score}/100')
print(f'By severity: {result.summary.by_severity}')
print()
for f in result.findings[:5]:
    print(f'  [{f.severity.value}] {f.title} @ {f.file_path}:{f.line_number}')
print('Full pipeline OK')
"
```

#### Verify 4: Graceful degradation (LLM offline)

```bash
# Stop Ollama, then:
python -c "
from src.core.analyzer import CodeAnalyzer

analyzer = CodeAnalyzer(enable_llm=True)  # Will detect Ollama is offline
result = analyzer.scan_codebase('src/')

print(f'Findings: {result.summary.total_findings} (regex + complexity only)')
print(f'Score: {result.summary.security_score}/100')
print('Degraded mode OK')
"
```

### Architecture Notes (Day 5)

```
Full Pipeline Flow:

  scan_codebase(path)
       |
  _collect_files() → list of .py files
       |
  ┌────┴─────────────────────────────────────────────┐
  │  Per file:                                        │
  │    PatternMatcher.scan_file() → regex matches     │
  │    TreeSitterParser.parse_file() → AST analysis   │
  └──────────────────────────────────────────────────┘
       |
  _matches_to_findings() → regex findings
       |
  ┌────┴─────────────────────────────────────────────┐
  │  Complexity Detection (per file with AST):        │
  │    LLMAnalyzer.detect_complexity_issues()         │
  │    LLMAnalyzer.complexity_to_findings()           │
  └──────────────────────────────────────────────────┘
       |
  ┌────┴─────────────────────────────────────────────┐
  │  Semantic + LLM (per .py file, if LLM available): │
  │    VectorStore.query_relevant_rules(code[:2000])  │
  │    Filter to rules with llm_prompt                │
  │    LLMAnalyzer.analyze_code_with_rules()          │
  └──────────────────────────────────────────────────┘
       |
  ┌────┴─────────────────────────────────────────────┐
  │  False Positive Validation (CRITICAL/HIGH only):  │
  │    LLMAnalyzer.validate_finding() per finding     │
  └──────────────────────────────────────────────────┘
       |
  Combine: validated_regex + llm + complexity
       |
  ScanResult → ReportManager.generate_reports()
       |
  outputs/{scan_id}.json + outputs/{scan_id}.md
```
