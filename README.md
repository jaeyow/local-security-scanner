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
| 2 | Tree-sitter code analysis engine | Pending |
| 3 | LLM integration (Ollama) + ChromaDB | Pending |
| 4 | FastAPI application + endpoints | Pending |
| 5 | Full integration (end-to-end) | Pending |
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
