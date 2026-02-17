"""LLM-powered security analysis — deep contextual code scanning."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from loguru import logger

from src.core.llm_client import OllamaClient
from src.core.tree_sitter_parser import FileAnalysis, FunctionInfo
from src.models import Finding, Priority, SecurityRule, Severity
from src.utils.helpers import generate_finding_id, generate_scan_id


# --- Complexity thresholds ---

MAX_FUNCTION_LINES = 50
MAX_FILE_LINES = 500
MAX_NESTING_DEPTH = 4
MAX_PARAMETERS = 7


SYSTEM_PROMPT = """You are a security code reviewer. You analyze Python source code
for security vulnerabilities. Be precise and factual. Only report issues you are
confident about. Respond in JSON format when asked."""


@dataclass
class ComplexityFinding:
    """A code complexity issue detected via tree-sitter analysis."""

    file_path: str
    function_name: str
    line_start: int
    line_end: int
    issue: str
    line_count: int = 0
    parameter_count: int = 0


class LLMAnalyzer:
    """Uses a local LLM to perform deep security analysis on code.

    Capabilities:
    - Analyze code against specific security rules (contextual analysis)
    - Detect function/file complexity issues
    - Validate regex findings to reduce false positives
    - Analyze code for LLM-only rules (no regex pattern)
    """

    def __init__(self, client: Optional[OllamaClient] = None) -> None:
        """Initialize the LLM analyzer.

        Args:
            client: OllamaClient instance. Creates one if not provided.
        """
        self._client = client or OllamaClient()
        self._available: Optional[bool] = None

    @property
    def is_available(self) -> bool:
        """Check if the LLM is available (cached after first check)."""
        if self._available is None:
            self._available = self._client.is_available()
        return self._available

    def analyze_code_with_rule(
        self, code: str, rule: SecurityRule, file_path: str = "<input>"
    ) -> Optional[Finding]:
        """Analyze code against a specific security rule using the LLM.

        Args:
            code: Source code to analyze.
            rule: The security rule to check against.
            file_path: Path to the source file.

        Returns:
            A Finding if a vulnerability is detected, None otherwise.
        """
        if not self.is_available:
            logger.debug("LLM not available, skipping analysis for {}", rule.rule_id)
            return None

        prompt_text = rule.detection.llm_prompt or rule.description
        code_to_send = self._client.truncate_to_fit(code, reserve_tokens=800)

        prompt = f"""Analyze the following Python code for this security issue:

**Rule**: {rule.title} ({rule.rule_id})
**Check**: {prompt_text}
**Severity**: {rule.severity.value}

```python
{code_to_send}
```

Respond with JSON:
{{
  "vulnerable": true/false,
  "confidence": "high"/"medium"/"low",
  "line_number": <line number of issue or null>,
  "explanation": "<brief explanation>",
  "remediation": "<how to fix>"
}}

Only set "vulnerable" to true if you are confident there is a real issue."""

        result = self._client.generate_json(prompt, SYSTEM_PROMPT)
        if not result:
            return None

        if not result.get("vulnerable", False):
            return None

        confidence = result.get("confidence", "low")
        if confidence == "low":
            logger.debug(
                "Low confidence finding for {} in {}, skipping",
                rule.rule_id,
                file_path,
            )
            return None

        scan_id = generate_scan_id()
        line_num = result.get("line_number") or 1

        return Finding(
            finding_id=generate_finding_id(scan_id, 1),
            rule_id=rule.rule_id,
            severity=rule.severity,
            title=f"[LLM] {rule.title}",
            category=rule.category,
            file_path=file_path,
            line_number=line_num,
            description=result.get("explanation", rule.description),
            remediation=result.get("remediation", rule.remediation),
            impact=f"{rule.severity.value}: {rule.title}",
            cwe_id=rule.cwe_id,
            compliance=rule.compliance,
            priority=self._severity_to_priority(rule.severity),
            references=rule.references,
        )

    def analyze_code_with_rules(
        self,
        code: str,
        rules: List[SecurityRule],
        file_path: str = "<input>",
    ) -> List[Finding]:
        """Analyze code against multiple rules.

        Args:
            code: Source code to analyze.
            rules: List of security rules to check.
            file_path: Path to the source file.

        Returns:
            List of findings from LLM analysis.
        """
        findings: List[Finding] = []
        for rule in rules:
            finding = self.analyze_code_with_rule(code, rule, file_path)
            if finding:
                findings.append(finding)
        return findings

    def validate_finding(self, code: str, finding: Finding) -> bool:
        """Use the LLM to validate a regex-based finding (reduce false positives).

        Args:
            code: Source code containing the finding.
            finding: The regex-detected finding to validate.

        Returns:
            True if the LLM confirms the finding is a real issue.
        """
        if not self.is_available:
            return True  # If LLM unavailable, keep the finding

        code_to_send = self._client.truncate_to_fit(code, reserve_tokens=600)

        prompt = f"""A static analysis tool flagged this code for a potential security issue.

**Issue**: {finding.title}
**Category**: {finding.category}
**File**: {finding.file_path}, line {finding.line_number}

```python
{code_to_send}
```

Is this a real security vulnerability, or a false positive?
Respond with JSON:
{{
  "is_real": true/false,
  "reason": "<brief explanation>"
}}"""

        result = self._client.generate_json(prompt, SYSTEM_PROMPT)
        if not result:
            return True  # Keep finding if LLM fails

        is_real = result.get("is_real", True)
        reason = result.get("reason", "")

        if not is_real:
            logger.info(
                "LLM rejected finding {} as false positive: {}",
                finding.finding_id,
                reason,
            )

        return is_real

    def detect_complexity_issues(
        self, analysis: FileAnalysis
    ) -> List[ComplexityFinding]:
        """Detect code complexity issues from tree-sitter analysis.

        No LLM needed — uses thresholds on function length, parameters, etc.

        Args:
            analysis: Tree-sitter file analysis result.

        Returns:
            List of complexity findings.
        """
        issues: List[ComplexityFinding] = []

        # Check file length
        if analysis.total_lines > MAX_FILE_LINES:
            issues.append(
                ComplexityFinding(
                    file_path=analysis.file_path,
                    function_name="<file>",
                    line_start=1,
                    line_end=analysis.total_lines,
                    issue=f"File is {analysis.total_lines} lines long "
                    f"(threshold: {MAX_FILE_LINES}). "
                    "Consider splitting into smaller modules.",
                    line_count=analysis.total_lines,
                )
            )

        # Check all functions (top-level and class methods)
        all_functions = list(analysis.functions)
        for cls in analysis.classes:
            all_functions.extend(cls.methods)

        for func in all_functions:
            func_lines = func.line_end - func.line_start + 1

            if func_lines > MAX_FUNCTION_LINES:
                issues.append(
                    ComplexityFinding(
                        file_path=analysis.file_path,
                        function_name=func.name,
                        line_start=func.line_start,
                        line_end=func.line_end,
                        issue=f"Function '{func.name}' is {func_lines} lines long "
                        f"(threshold: {MAX_FUNCTION_LINES}). "
                        "Long functions are harder to review and more likely to contain bugs.",
                        line_count=func_lines,
                    )
                )

            if len(func.parameters) > MAX_PARAMETERS:
                issues.append(
                    ComplexityFinding(
                        file_path=analysis.file_path,
                        function_name=func.name,
                        line_start=func.line_start,
                        line_end=func.line_end,
                        issue=f"Function '{func.name}' has {len(func.parameters)} parameters "
                        f"(threshold: {MAX_PARAMETERS}). "
                        "Consider using a data class or config object.",
                        parameter_count=len(func.parameters),
                    )
                )

        if issues:
            logger.debug(
                "Found {} complexity issues in {}",
                len(issues),
                analysis.file_path,
            )

        return issues

    def complexity_to_findings(
        self, complexity_issues: List[ComplexityFinding]
    ) -> List[Finding]:
        """Convert complexity issues into Finding objects.

        Args:
            complexity_issues: List of detected complexity issues.

        Returns:
            List of Finding objects.
        """
        scan_id = generate_scan_id()
        findings: List[Finding] = []

        for idx, issue in enumerate(complexity_issues, start=1):
            findings.append(
                Finding(
                    finding_id=generate_finding_id(scan_id, idx),
                    rule_id="COMPLEXITY-001",
                    severity=Severity.LOW,
                    title=f"Code Complexity: {issue.function_name}",
                    category="Code Complexity",
                    file_path=issue.file_path,
                    line_number=issue.line_start,
                    line_end=issue.line_end,
                    description=issue.issue,
                    remediation="Refactor to reduce complexity. Break long functions "
                    "into smaller, focused functions. Use data classes for "
                    "functions with many parameters.",
                    priority=Priority.P3,
                )
            )

        return findings

    @staticmethod
    def _severity_to_priority(severity: Severity) -> Priority:
        """Map severity to remediation priority."""
        mapping = {
            Severity.CRITICAL: Priority.P0,
            Severity.HIGH: Priority.P1,
            Severity.MEDIUM: Priority.P2,
            Severity.LOW: Priority.P3,
            Severity.INFO: Priority.P3,
        }
        return mapping.get(severity, Priority.P2)
