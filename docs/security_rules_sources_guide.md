# Security Rules Sources Guide
## Where to Get Security Standards and Rules for Your Scanner

---

## EXECUTIVE SUMMARY

**Good news**: You do NOT need to create security rules from scratch. There are **extensive, free, well-maintained** security standards available.

**Best approach**: Combine multiple sources to create a comprehensive rule set.

**Recommendation**: Start with OWASP (easiest) + CWE (comprehensive) + Your friend's specific compliance needs.

---

## TIER 1: PRIMARY SOURCES (Start Here)

### 1. OWASP (Open Web Application Security Project)

**What it is**: The gold standard for web application security

**Why use it**:
- ✅ FREE and open source
- ✅ Industry-recognized worldwide
- ✅ Regularly updated by security experts
- ✅ Practical, actionable rules
- ✅ Focused on common vulnerabilities

**Available Resources**:

#### A) OWASP Top 10 (2025 Edition)
**What**: List of 10 most critical web application security risks
**Format**: PDF available
**URL**: https://owasp.org/Top10/
**Coverage**:
1. Broken Access Control
2. Cryptographic Failures
3. Injection (SQL, XSS, etc.)
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

**Perfect for**: Your security scanner's initial rule set

#### B) OWASP Secure Coding Practices Quick Reference Guide
**What**: Technology-agnostic secure coding checklist
**Format**: PDF (17 pages)
**URL**: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
**Coverage**:
- Input validation
- Output encoding
- Authentication and password management
- Session management
- Access control
- Cryptographic practices
- Error handling and logging
- Data protection
- Communication security
- System configuration
- Database security
- File management
- Memory management
- General coding practices

**Perfect for**: Detailed rule implementation

#### C) OWASP Cheat Sheet Series
**What**: Collection of specific security topic guides
**Format**: Web pages (can be converted to text/PDF)
**URL**: https://cheatsheetseries.owasp.org/
**Coverage**: 100+ specific topics like:
- SQL Injection Prevention
- XSS Prevention
- Authentication
- Session Management
- Cryptography
- API Security
- etc.

**Perfect for**: Deep-dive into specific vulnerability types

---

### 2. CWE (Common Weakness Enumeration)

**What it is**: Comprehensive dictionary of software/hardware weaknesses

**Why use it**:
- ✅ FREE from MITRE Corporation
- ✅ 600+ categorized weaknesses
- ✅ Hierarchical structure
- ✅ Detailed descriptions with examples
- ✅ Maintained by US DHS/CISA
- ✅ Maps to CVEs (actual vulnerabilities)

**Available Resources**:

#### CWE Top 25 Most Dangerous Software Weaknesses
**What**: Annual list of most critical weaknesses
**Format**: Web + downloadable data (XML, CSV)
**URL**: https://cwe.mitre.org/top25/
**Perfect for**: Prioritizing which rules to implement first

#### Full CWE Database
**What**: Complete enumeration of all weaknesses
**Format**: XML, CSV, web browsable
**URL**: https://cwe.mitre.org/data/downloads.html
**Coverage**: Examples include:
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-120: Buffer Overflow
- CWE-798: Use of Hard-coded Credentials
- CWE-22: Path Traversal
- CWE-502: Deserialization of Untrusted Data
- etc. (600+ total)

**Perfect for**: Comprehensive coverage

#### Download Options:
```bash
# CWE data available in multiple formats:
# - XML (full database)
# - CSV (tabular format)
# - Web API

# Example: Download CWE XML
wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
```

---

### 3. NIST (National Institute of Standards and Technology)

**What it is**: US government security standards

**Why use it**:
- ✅ FREE from US government
- ✅ Highly authoritative
- ✅ Used for compliance (government contracts)
- ✅ Comprehensive frameworks

**Key Publications**:

#### NIST SP 800-218: Secure Software Development Framework (SSDF)
**What**: High-level secure development practices
**Format**: PDF
**URL**: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf
**Coverage**:
- Prepare the organization
- Protect the software
- Produce well-secured software
- Respond to vulnerabilities

**Perfect for**: Development process rules (broader than code-level)

#### NIST SP 800-53: Security and Privacy Controls
**What**: Comprehensive security controls catalog
**Format**: PDF
**Coverage**: Technical, operational, and management controls

---

## TIER 2: COMPLIANCE-SPECIFIC SOURCES

### 4. PCI DSS (Payment Card Industry Data Security Standard)

**What**: Security standard for handling credit card data

**When to use**: If your friend's clients handle payment data

**Available**: Free after registration at https://www.pcisecuritystandards.org/

**Coverage**:
- Secure network architecture
- Data encryption
- Access control
- Security testing
- etc.

---

### 5. ISO/IEC 27001

**What**: International information security standard

**When to use**: If clients need ISO compliance

**Note**: NOT free (paid standard), but security controls are well-documented

**Alternative**: Use publicly available ISO 27001 control lists (many organizations publish these)

---

### 6. CERT Secure Coding Standards

**What**: Language-specific secure coding rules

**Why use it**:
- ✅ FREE from Carnegie Mellon University
- ✅ Language-specific (C, C++, Java, Python, Android)
- ✅ Very detailed

**URL**: https://wiki.sei.cmu.edu/confluence/display/seccode

**Coverage by Language**:
- **SEI CERT C Coding Standard**
- **SEI CERT C++ Coding Standard**
- **SEI CERT Java Coding Standard**
- **SEI CERT Perl Coding Standard**
- **SEI CERT Android Secure Coding Standard**

**Perfect for**: Language-specific deep rules

---

## TIER 3: SPECIALIZED SOURCES

### 7. SANS Top 25

**What**: SANS Institute's most dangerous software errors

**URL**: https://www.sans.org/top25-software-errors/

**Overlap**: Similar to CWE Top 25 (they collaborate)

---

### 8. Government/Regional Standards

**Examples**:
- **UK DWP Software Development Security Standard** (PDF available)
- **Australian Government ISM** (Information Security Manual)
- **EU GDPR** (for data protection rules)

**When to use**: If your friend's clients operate in specific jurisdictions

---

## MY RECOMMENDATION: STARTER RULE SET

### Phase 1: Core Rules (Week 1)

**Start with these 3 sources**:

1. **OWASP Top 10 (2025)**
   - Download: https://owasp.org/Top10/
   - Extract 10 main categories
   - Create ~30-50 rules from this

2. **OWASP Secure Coding Practices**
   - Download: PDF from OWASP site
   - Extract checklist items
   - Create ~100 rules from this

3. **CWE Top 25**
   - Access: https://cwe.mitre.org/top25/
   - Focus on most dangerous weaknesses
   - Create ~25 high-priority rules

**Total**: ~150-175 rules (excellent starting point)

---

### Phase 2: Language-Specific Rules

**Python-specific** (since you mentioned Python codebases):

Sources to add:
1. **Bandit** default rule set (open source Python security linter)
   - URL: https://bandit.readthedocs.io/
   - Coverage: Python-specific vulnerabilities
   - Format: Well-documented rules

2. **Semgrep Python rules** (open source)
   - URL: https://semgrep.dev/r
   - Format: YAML rules (can be converted)

3. **CERT Python Coding Standard**
   - URL: https://wiki.sei.cmu.edu/confluence/display/python

---

### Phase 3: Expand Coverage

**Add domain-specific rules**:
1. API Security (OWASP API Security Top 10)
2. Cloud Security (CSA Cloud Controls Matrix)
3. Container Security (CIS Docker Benchmark)
4. Cryptography (NIST cryptographic standards)

---

## PRACTICAL IMPLEMENTATION STRATEGY

### Step 1: Download Core PDFs

```bash
# Create directory structure
mkdir -p security-rules/{owasp,cwe,nist,custom}

# Download OWASP Top 10
wget -O security-rules/owasp/top10-2025.pdf [URL from OWASP]

# Download OWASP Secure Coding Practices
wget -O security-rules/owasp/secure-coding-practices.pdf [URL]

# Download CWE data
wget -O security-rules/cwe/cwec_latest.xml.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
unzip security-rules/cwe/cwec_latest.xml.zip

# Download NIST SSDF
wget -O security-rules/nist/sp800-218.pdf https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf
```

### Step 2: Structure Rules

Create a standardized format for each rule:

```json
{
  "rule_id": "OWASP-TOP10-2025-A01",
  "category": "Broken Access Control",
  "severity": "CRITICAL",
  "description": "Application does not properly restrict access to authenticated functionality",
  "detection_patterns": [
    "Missing authorization checks",
    "Insecure direct object references",
    "Elevation of privilege"
  ],
  "code_examples": {
    "vulnerable": "if user.is_authenticated: return sensitive_data",
    "secure": "if user.is_authenticated and user.has_permission('view_sensitive'): return sensitive_data"
  },
  "cwe_mapping": ["CWE-284", "CWE-285"],
  "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
}
```

### Step 3: Organize by Priority

**Critical (P0)**: Must scan for
- SQL Injection (CWE-89)
- XSS (CWE-79)
- Hard-coded credentials (CWE-798)
- Path traversal (CWE-22)
- Command injection (CWE-78)

**High (P1)**: Should scan for
- Insecure cryptography
- Session management issues
- Access control flaws

**Medium (P2)**: Nice to have
- Code quality issues
- Performance problems with security implications

**Low (P3)**: Optional
- Style/formatting with security angle

---

## WHAT YOUR FRIEND NEEDS TO PROVIDE

Ask your friend these questions:

1. **What compliance frameworks do his clients need?**
   - ISO 27001?
   - PCI DSS?
   - SOC 2?
   - HIPAA?
   - GDPR?

2. **What industries are his clients in?**
   - Healthcare → Add HIPAA rules
   - Finance → Add PCI DSS rules
   - Government → Add NIST rules

3. **Does he have existing security policies?**
   - If yes: Get those PDFs
   - If no: Use OWASP + CWE

4. **What programming languages do clients use?**
   - Python → Focus on Python-specific rules
   - JavaScript → Add Node.js security rules
   - Java → Add Java-specific rules
   - etc.

---

## SAMPLE RULE SOURCES (Ready to Use)

### Example 1: OWASP Top 10 Rule

**From**: OWASP Top 10 2025 - A03: Injection

**Rule**: SQL Injection Prevention
```
Rule ID: OWASP-A03-001
Title: SQL Injection via String Concatenation
Severity: CRITICAL
Description: SQL queries must not be built using string concatenation with user input
Pattern: Detect string concatenation in SQL queries
Example (Python):
  BAD:  query = "SELECT * FROM users WHERE id = " + user_input
  GOOD: cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

### Example 2: CWE Rule

**From**: CWE-798: Use of Hard-coded Credentials

**Rule**: Hard-coded Password Detection
```
Rule ID: CWE-798-001
Title: Hard-coded Password in Source Code
Severity: CRITICAL
Description: Credentials must not be hard-coded in source code
Pattern: Detect variable assignments with names containing 'password', 'secret', 'api_key' assigned to string literals
Example (Python):
  BAD:  PASSWORD = "admin123"
  GOOD: PASSWORD = os.environ.get('DB_PASSWORD')
```

---

## TOOLS TO HELP EXTRACT RULES

### Option 1: Manual Extraction (Week 1)
- Read PDFs
- Extract key points
- Create rule JSON files
- ~20-30 rules per PDF

### Option 2: Semi-Automated (Week 2+)
- Use PyMuPDF to extract text
- Use LLM to structure into rules
- Human review and refinement

### Option 3: Use Existing Rule Sets (Best for MVP)
- **Semgrep community rules**: https://semgrep.dev/r
  - Already in structured format
  - Can be adapted to your format
  - 2000+ rules available
- **Bandit rules** (for Python)
  - Already well-documented
  - Easy to convert to your format

---

## FINAL RECOMMENDATION

### For Your Week 1 MVP:

**Use these 3 sources**:

1. **OWASP Top 10 2025** (PDF)
   - 10 categories → ~30 concrete rules
   - Download from: https://owasp.org/Top10/

2. **OWASP Secure Coding Practices** (PDF)
   - Checklist → ~50 additional rules
   - Download from OWASP project page

3. **Bandit Python Security Rules** (JSON/YAML)
   - Already structured for Python
   - ~40 Python-specific rules
   - Clone from: https://github.com/PyCQA/bandit

**Total**: ~120 rules (perfect for MVP)

**Time to prepare**: 4-6 hours to download, extract, and structure

---

### After Week 1 (Expansion):

**Add**:
1. CWE Top 25 (download XML)
2. Client-specific compliance (ask your friend)
3. Language-specific rules (CERT standards)

**Goal**: 300-500 comprehensive rules over 2-3 months

---

## BOTTOM LINE

**You do NOT need to create rules from scratch.**

**Action items**:
1. ✅ Download OWASP Top 10 PDF
2. ✅ Download OWASP Secure Coding Practices PDF
3. ✅ Clone Bandit rules (for Python)
4. ✅ Ask your friend what compliance frameworks his clients need
5. ✅ Start with these ~120 rules for Week 1 MVP

**These sources are**:
- FREE ✅
- Industry-standard ✅
- Regularly updated ✅
- PDF/structured format ✅
- Perfect for your scanner ✅

**No need to reinvent the wheel!**
