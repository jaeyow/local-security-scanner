# Compliance Framework Integration
## ISO 27001, PCI DSS, SOC 2 Security Scanner Requirements

---

## EXECUTIVE SUMMARY

**Target Compliance Frameworks**:
1. **ISO 27001** - Information Security Management System
2. **PCI DSS** - Payment Card Industry Data Security Standard
3. **SOC 2** - Service Organization Control 2 (Trust Services Criteria)

**Good News**: These frameworks have significant overlap with OWASP and CWE, so you're not starting from scratch.

**Strategy**: Map existing OWASP/CWE rules → Compliance frameworks

---

## FRAMEWORK OVERVIEW

### ISO 27001 (Information Security Management)

**What it is**: International standard for information security management systems (ISMS)

**Focus Areas**:
- Access control (who can access what)
- Cryptography (how data is protected)
- Physical security (server protection)
- Operations security (secure development)
- Communications security (network protection)
- System acquisition/development (secure SDLC)

**Controls Relevant to Code Scanning**:
- A.8: Asset Management (code as asset)
- A.9: Access Control
- A.10: Cryptography
- A.12: Operations Security
- A.14: System Acquisition, Development, and Maintenance

**Key Code-Level Requirements**:
```
✓ Hard-coded credentials → FORBIDDEN
✓ Encryption for sensitive data → REQUIRED
✓ Access control checks → REQUIRED
✓ Secure coding practices → REQUIRED
✓ Input validation → REQUIRED
✓ Error handling (no info disclosure) → REQUIRED
✓ Logging and monitoring → REQUIRED
```

**Compliance Mapping File**: ISO 27001 Annex A controls → Security rules

---

### PCI DSS (Payment Card Industry)

**What it is**: Security standard for organizations handling credit card data

**Current Version**: PCI DSS v4.0 (March 2024)

**12 Core Requirements**:
1. Install and maintain network security controls
2. Apply secure configurations
3. Protect stored account data
4. Protect cardholder data with strong cryptography
5. Protect systems from malware
6. Develop and maintain secure systems
7. Restrict access to cardholder data
8. Identify users and authenticate access
9. Restrict physical access
10. Log and monitor access
11. Test security systems regularly
12. Support information security with policies

**Most Relevant to Code Scanning**:
- **Requirement 6**: Develop and maintain secure systems and software
  - 6.2.4: Secure coding techniques
  - 6.3.2: Review custom code for vulnerabilities
  - 6.4: Security testing

**Key Code-Level Requirements**:
```
✓ NO storage of sensitive authentication data (CVV, PIN)
✓ Encryption of cardholder data (AES-256, RSA-2048+)
✓ NO hard-coded encryption keys
✓ Input validation (prevent injection)
✓ Access control (authentication + authorization)
✓ Audit logging (who accessed what, when)
✓ Secure session management
✓ Protection against common attacks (OWASP Top 10)
```

**Critical for Your Scanner**:
- Must detect hard-coded credit card numbers (regex patterns)
- Must detect hard-coded encryption keys
- Must detect weak cryptography (MD5, SHA1, DES)
- Must verify input validation on payment endpoints

---

### SOC 2 (Trust Services Criteria)

**What it is**: Audit framework for service organizations (SaaS companies)

**Five Trust Services Criteria**:
1. **Security** (Common Criteria - always included)
2. **Availability** (optional)
3. **Processing Integrity** (optional)
4. **Confidentiality** (optional)
5. **Privacy** (optional)

**Most Relevant: Security Criteria (CC)**

**Common Criteria Categories**:
- **CC6**: Logical and Physical Access Controls
  - CC6.1: Access controls exist
  - CC6.2: Access is authorized
  - CC6.6: Logical access is removed when no longer needed
  - CC6.7: Data is protected during transmission and storage

- **CC7**: System Operations
  - CC7.1: Procedures exist to detect and respond to security incidents
  - CC7.2: Software is monitored
  - CC7.4: System changes are authorized and tested

**Key Code-Level Requirements**:
```
✓ Authentication mechanisms (multi-factor support)
✓ Authorization checks (role-based access)
✓ Encryption in transit (TLS 1.2+)
✓ Encryption at rest (AES-256)
✓ Secure session management
✓ Input validation
✓ Logging and monitoring
✓ Secure development lifecycle
```

---

## COMPLIANCE RULE MAPPING

### Overlap Analysis

**Great News**: ~70% overlap between OWASP/CWE and compliance frameworks

```
OWASP Top 10 Rules
    ├─ 90% map to PCI DSS Requirement 6
    ├─ 85% map to ISO 27001 A.14
    └─ 80% map to SOC 2 CC6/CC7

CWE Top 25 Rules
    ├─ 95% map to PCI DSS
    ├─ 90% map to ISO 27001
    └─ 85% map to SOC 2

Your Scanner Needs
    ├─ Core: OWASP + CWE (already planned)
    └─ Add: Compliance-specific checks (incremental)
```

### Rule Mapping Table

| Security Rule | OWASP | CWE | ISO 27001 | PCI DSS | SOC 2 |
|---------------|-------|-----|-----------|---------|-------|
| Hard-coded credentials | A02 | 798 | A.9.4.3 | 6.2.4 | CC6.1 |
| SQL Injection | A03 | 89 | A.14.2.5 | 6.2.4 | CC7.2 |
| Weak encryption | A02 | 327 | A.10.1 | 4.2 | CC6.7 |
| Missing auth check | A01 | 284 | A.9.4.1 | 7.1 | CC6.2 |
| XSS vulnerability | A03 | 79 | A.14.2.5 | 6.2.4 | CC7.2 |
| Insecure session | A07 | 384 | A.9.4.2 | 6.2.4 | CC6.1 |
| Path traversal | A01 | 22 | A.9.4.5 | 6.2.4 | CC6.2 |
| Info disclosure | A05 | 209 | A.18.1.3 | 6.2.4 | CC7.1 |

**Implementation**: Each rule in your scanner includes compliance mappings

---

## COMPLIANCE-SPECIFIC RULES TO ADD

### ISO 27001 Specific

**A.9.4.3 - Password Management**
```python
# Rule: Password complexity requirements
DETECT:
  - Password length < 12 characters
  - No complexity requirements in validation
  - Passwords stored in plaintext
  - Passwords hashed with weak algorithms (MD5, SHA1)

EXAMPLE:
  BAD:  password = request.form['password']
        db.save(username, password)
  
  GOOD: from werkzeug.security import generate_password_hash
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        db.save(username, hashed)
```

**A.10.1.1 - Cryptographic Controls**
```python
# Rule: Strong encryption required
DETECT:
  - Use of DES, 3DES, RC4 (weak ciphers)
  - Use of MD5, SHA1 for hashing (weak hashes)
  - RSA key size < 2048 bits
  - AES key size < 256 bits

EXAMPLE:
  BAD:  cipher = DES.new(key, DES.MODE_ECB)
  
  GOOD: from cryptography.fernet import Fernet
        cipher = Fernet(key)
```

**A.14.2.5 - Secure Development**
```python
# Rule: Input validation required
DETECT:
  - User input used directly in:
    • SQL queries
    • System commands
    • File paths
    • HTML output
  - Missing input sanitization
  - Missing output encoding

EXAMPLE:
  BAD:  os.system(f"ls {user_input}")
  
  GOOD: import shlex
        safe_input = shlex.quote(user_input)
        subprocess.run(['ls', safe_input])
```

---

### PCI DSS Specific

**Req 3.2.1 - No Storage of Sensitive Authentication Data**
```python
# Rule: Detect storage of forbidden data
DETECT:
  - Full magnetic stripe data
  - CAV2/CVC2/CVV2/CID (card verification codes)
  - PIN/PIN blocks

REGEX PATTERNS:
  - Credit card numbers: \b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b
  - CVV patterns: cvv.*=.*\d{3,4}
  - Variable names: cvv2|cvc2|cav2|cid

EXAMPLE:
  BAD:  card_data = {
            'number': '4532-1234-5678-9010',
            'cvv': '123',  # ❌ FORBIDDEN
            'exp': '12/25'
        }
  
  GOOD: # Only store:
        # - Truncated PAN (first 6, last 4 digits)
        # - Token from payment processor
        card_data = {
            'token': 'tok_abc123...',
            'last4': '9010',
            'brand': 'visa'
        }
```

**Req 4.2 - Strong Cryptography for Transmission**
```python
# Rule: Enforce TLS 1.2+ for card data
DETECT:
  - TLS 1.0, TLS 1.1 (deprecated)
  - SSLv2, SSLv3 (vulnerable)
  - HTTP instead of HTTPS for payment endpoints
  - Weak cipher suites

EXAMPLE:
  BAD:  context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
  
  GOOD: context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
```

**Req 6.2.4 - Secure Coding Practices**
```python
# Rule: OWASP Top 10 compliance
DETECT:
  - All OWASP Top 10 vulnerabilities
  - Injection flaws
  - Broken authentication
  - Sensitive data exposure
  - XML external entities (XXE)
  - Broken access control
  - Security misconfiguration
  - Cross-site scripting (XSS)
  - Insecure deserialization
  - Known vulnerable components
  - Insufficient logging

# This maps directly to your OWASP rules
```

---

### SOC 2 Specific

**CC6.1 - Authentication**
```python
# Rule: Multi-factor authentication support
DETECT:
  - Login endpoints without MFA capability
  - Session tokens without additional factors
  - Password-only authentication for privileged access

EXAMPLE:
  BAD:  if check_password(username, password):
            return create_session(user)
  
  GOOD: if check_password(username, password):
            if user.requires_mfa:
                return require_mfa_verification(user)
            return create_session(user)
```

**CC6.7 - Encryption in Transit and at Rest**
```python
# Rule: Data encryption verification
DETECT:
  - Sensitive data transmitted without TLS
  - Database connections without encryption
  - Files stored without encryption
  - API calls without HTTPS

EXAMPLE:
  BAD:  # Unencrypted database connection
        conn = psycopg2.connect(
            host="db.example.com",
            database="mydb"
        )
  
  GOOD: conn = psycopg2.connect(
            host="db.example.com",
            database="mydb",
            sslmode="require"  # Force SSL/TLS
        )
```

**CC7.2 - System Monitoring**
```python
# Rule: Security event logging
DETECT:
  - Authentication attempts not logged
  - Authorization failures not logged
  - Data access not logged
  - Configuration changes not logged

EXAMPLE:
  BAD:  def login(username, password):
            user = authenticate(username, password)
            return user
  
  GOOD: def login(username, password):
            user = authenticate(username, password)
            if user:
                logger.info(f"Successful login: {username}")
            else:
                logger.warning(f"Failed login attempt: {username}")
            return user
```

---

## UPDATED RULE SET FOR YOUR SCANNER

### Core Rules (Week 1 MVP)

1. **OWASP Top 10 (2025)** - 30 rules
2. **CWE Top 25** - 25 rules
3. **Bandit Python** - 40 rules

**PLUS Compliance-Specific**:

4. **ISO 27001 Controls** - 15 additional rules
   - Cryptography requirements
   - Access control checks
   - Logging requirements
   
5. **PCI DSS Requirements** - 20 additional rules
   - Cardholder data detection
   - Strong cryptography enforcement
   - No forbidden data storage

6. **SOC 2 Criteria** - 10 additional rules
   - Authentication mechanisms
   - Encryption verification
   - Audit logging

**Total: ~140 rules for MVP** (up from 120)

---

## COMPLIANCE REPORTING ENHANCEMENTS

### Add to PDF/HTML Reports:

**Compliance Dashboard Section**:
```
═══════════════════════════════════════════════════
COMPLIANCE STATUS OVERVIEW
═══════════════════════════════════════════════════

ISO 27001 (Annex A Controls)
┌────────────────────────────────────────────────┐
│ A.9  Access Control          [████████░░] 80%  │
│ A.10 Cryptography            [██████░░░░] 60%  │
│ A.14 Secure Development      [███████░░░] 70%  │
│                                                 │
│ Overall: 18/25 Controls  ✅ 72% COMPLIANT      │
└────────────────────────────────────────────────┘

PCI DSS v4.0
┌────────────────────────────────────────────────┐
│ Req 3  Protect Stored Data   [██░░░░░░░░] 20% │
│ Req 4  Encrypt Transmission  [████████░░] 80% │
│ Req 6  Secure Development    [███████░░░] 70% │
│                                                 │
│ Overall: 7/12 Requirements  ⚠️  58% COMPLIANT  │
│ Status: FAILED - Req 3 non-compliant           │
└────────────────────────────────────────────────┘

SOC 2 (Trust Services Criteria)
┌────────────────────────────────────────────────┐
│ CC6.1 Access Controls        [████████░░] 80%  │
│ CC6.7 Data Protection        [██████░░░░] 60%  │
│ CC7.2 Monitoring             [███████░░░] 70%  │
│                                                 │
│ Overall: 15/20 Criteria  ✅ 75% COMPLIANT      │
└────────────────────────────────────────────────┘

CRITICAL COMPLIANCE GAPS:
❌ PCI DSS Req 3: CVV data found in code (FORBIDDEN)
❌ ISO 27001 A.10: Weak encryption (MD5) in use
⚠️  SOC 2 CC6.7: Database connections unencrypted
```

### Add to Finding Details:

```
═══════════════════════════════════════════════════
FINDING #001: Hard-coded CVV Storage
═══════════════════════════════════════════════════

COMPLIANCE IMPACT:
┌──────────────────────────────────────────────────┐
│ ❌ PCI DSS Req 3.2.1: CRITICAL VIOLATION         │
│    Storage of CVV2 data is STRICTLY FORBIDDEN    │
│    Impact: IMMEDIATE FAIL of PCI DSS audit       │
│                                                   │
│ ❌ ISO 27001 A.8.2.3: Asset Handling FAILED      │
│    Sensitive authentication data mishandled      │
│                                                   │
│ ⚠️  SOC 2 CC6.7: Data Protection GAP             │
│    Confidential data not adequately protected    │
└──────────────────────────────────────────────────┘

REGULATORY CONSEQUENCES:
• PCI DSS: Card brands may revoke processing rights
• Fines: $5,000-$100,000 per month of non-compliance
• ISO 27001: Certification will be denied/revoked
• SOC 2: Type II audit report will include exception
```

---

## COMPLIANCE VERIFICATION CHECKLIST

### ISO 27001 Readiness

```
Code-Level Requirements:
✅ A.9.4.1  Access control policy implemented
✅ A.9.4.3  Password management secure
⚠️  A.10.1.1 Strong cryptography (3 weak instances found)
✅ A.14.2.5 Input validation present
✅ A.18.1.3 No sensitive info in logs
⚠️  A.12.4.1 Logging incomplete (5 gaps)

Process Requirements (Outside Code Scan):
□ Information security policy documented
□ Risk assessment performed
□ Incident response plan exists
□ Access control procedures defined
```

### PCI DSS Readiness

```
Requirement 6 Compliance:
✅ 6.2.4.1 Injection flaws prevented (mostly)
❌ 6.2.4.2 Authentication broken (2 critical issues)
✅ 6.2.4.3 Sensitive data encrypted (in transit)
❌ 6.2.4.4 Forbidden data stored (CVV found)
✅ 6.2.4.5 Access control implemented
⚠️  6.2.4.6 Security misconfiguration (3 issues)

Overall Req 6: 4/6 sub-requirements ⚠️  NOT READY
BLOCKER: Must remove CVV storage before audit
```

### SOC 2 Readiness

```
Security Criteria (CC) Compliance:
✅ CC6.1  Access controls exist
⚠️  CC6.2  Access authorized (some gaps)
✅ CC6.6  Access removal mechanisms exist
⚠️  CC6.7  Encryption (DB connections unencrypted)
✅ CC7.1  Security monitoring present
⚠️  CC7.2  Logging incomplete
✅ CC7.4  Change management evident in code

Overall Security: 5/7 criteria ⚠️  MINOR GAPS
Status: AUDITABLE with exceptions noted
```

---

## IMPLEMENTATION PRIORITY

### Week 1: Core + Critical Compliance
1. OWASP Top 10 rules
2. CWE Top 25 rules
3. PCI DSS Req 3 (forbidden data detection)
4. ISO 27001 cryptography checks

### Week 2-3: Full Compliance Integration
5. Complete ISO 27001 Annex A mappings
6. Complete PCI DSS Req 6 mappings
7. Complete SOC 2 CC6/CC7 mappings
8. Enhanced compliance reporting

### Month 2: Certification Support
9. Generate compliance evidence packages
10. Export audit-ready documentation
11. Create remediation tracking
12. Historical compliance trending

---

## DATA SOURCES

### ISO 27001
**Official Standard**: ISO/IEC 27001:2022 (paid)
**Free Resources**:
- Annex A control list (available online)
- https://www.iso.org/isoiec-27001-information-security.html
- Many consultancies publish free control checklists

### PCI DSS
**Official Standard**: PCI DSS v4.0 (FREE)
**Download**: https://www.pcisecuritystandards.org/
**Specifically**: "PCI DSS Requirements and Testing Procedures v4.0" (PDF)
**Key Sections**: Requirement 6 (Secure Development)

### SOC 2
**Official Framework**: AICPA Trust Services Criteria (paid)
**Free Resources**:
- https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report
- Many audit firms publish free guides
- Common Criteria (CC) publicly documented

---

## ACTION ITEMS FOR YOUR FRIEND

**Ask your friend**:
1. Which specific ISO 27001 controls do clients care most about?
2. Are clients Level 1, 2, 3, or 4 merchants (PCI DSS)?
3. Which SOC 2 criteria beyond Security (Availability, Confidentiality, etc.)?
4. Any industry-specific requirements (HIPAA for healthcare, etc.)?

**Provide to your friend**:
1. Compliance gap analysis
2. Remediation roadmap mapped to frameworks
3. Evidence packages for auditors
4. Pre-audit checklist

---

## BOTTOM LINE

**Good News**:
✅ OWASP/CWE covers ~70% of compliance requirements
✅ Need ~40 additional compliance-specific rules
✅ Reporting needs compliance dashboard section
✅ PCI DSS and ISO 27001 standards are FREE to download

**Your Scanner Will**:
✅ Detect violations of ISO 27001, PCI DSS, SOC 2
✅ Map findings to specific control requirements
✅ Generate compliance-ready reports
✅ Provide audit evidence

**Deliverable**:
Professional security scanner that explicitly addresses the three frameworks your friend's clients need most.

---

Ready to build this with full compliance integration!
