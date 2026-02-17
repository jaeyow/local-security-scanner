"""Markdown report generator for scan results."""

from pathlib import Path
from typing import Dict, List

from loguru import logger

from src.models import Finding, ScanResult


class MarkdownReportGenerator:
    """Generates Markdown report files from scan results."""

    def generate(self, result: ScanResult, output_path: Path) -> Path:
        """Write a scan result as a Markdown report.

        Args:
            result: The scan result to export.
            output_path: Path to write the Markdown file.

        Returns:
            The path to the generated report file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines: List[str] = []
        self._write_header(lines, result)
        self._write_executive_summary(lines, result)
        self._write_severity_breakdown(lines, result)
        self._write_findings_table(lines, result.findings)
        self._write_finding_details(lines, result.findings)
        self._write_remediation_summary(lines, result.findings)
        self._write_footer(lines, result)

        output_path.write_text("\n".join(lines), encoding="utf-8")

        logger.info(
            "Markdown report written to {} ({} findings)",
            output_path,
            result.summary.total_findings,
        )
        return output_path

    def _write_header(self, lines: List[str], result: ScanResult) -> None:
        """Write report title and metadata."""
        lines.append(f"# Security Scan Report")
        lines.append("")
        lines.append(f"**Scan ID**: `{result.metadata.scan_id}`")
        lines.append(f"**Date**: {result.metadata.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        lines.append(f"**Duration**: {result.metadata.duration_seconds}s")
        lines.append(f"**Repository**: `{result.scope.repository}`")
        lines.append(f"**Files Scanned**: {result.scope.files_scanned}")
        lines.append(f"**Lines of Code**: {result.scope.lines_of_code:,}")
        lines.append("")

    def _write_executive_summary(
        self, lines: List[str], result: ScanResult
    ) -> None:
        """Write the executive summary section."""
        lines.append("## Executive Summary")
        lines.append("")

        score = result.summary.security_score
        if score >= 80:
            rating = "Good"
        elif score >= 60:
            rating = "Needs Improvement"
        elif score >= 40:
            rating = "Poor"
        else:
            rating = "Critical"

        lines.append(f"**Security Score**: **{score}/100** ({rating})")
        lines.append(f"**Total Findings**: {result.summary.total_findings}")
        lines.append("")

        if result.summary.total_findings == 0:
            lines.append("No security issues detected. The codebase appears clean.")
            lines.append("")

    def _write_severity_breakdown(
        self, lines: List[str], result: ScanResult
    ) -> None:
        """Write severity breakdown table."""
        if not result.summary.by_severity:
            return

        lines.append("## Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severity_order:
            count = result.summary.by_severity.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev} | {count} |")

        lines.append("")

        if result.summary.by_category:
            lines.append("## Findings by Category")
            lines.append("")
            lines.append("| Category | Count |")
            lines.append("|----------|-------|")
            for cat, count in sorted(
                result.summary.by_category.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                lines.append(f"| {cat} | {count} |")
            lines.append("")

    def _write_findings_table(
        self, lines: List[str], findings: List[Finding]
    ) -> None:
        """Write the findings summary table."""
        if not findings:
            return

        lines.append("## All Findings")
        lines.append("")
        lines.append("| # | Severity | Rule | File | Line | Title |")
        lines.append("|---|----------|------|------|------|-------|")

        for i, f in enumerate(findings, start=1):
            file_short = Path(f.file_path).name
            lines.append(
                f"| {i} | {f.severity.value} | `{f.rule_id}` | "
                f"`{file_short}` | {f.line_number} | {f.title} |"
            )

        lines.append("")

    def _write_finding_details(
        self, lines: List[str], findings: List[Finding]
    ) -> None:
        """Write detailed finding descriptions."""
        if not findings:
            return

        lines.append("## Finding Details")
        lines.append("")

        for i, f in enumerate(findings, start=1):
            lines.append(f"### {i}. [{f.severity.value}] {f.title}")
            lines.append("")
            lines.append(f"- **Rule**: `{f.rule_id}`")
            lines.append(f"- **File**: `{f.file_path}`")
            lines.append(f"- **Line**: {f.line_number}")
            if f.cwe_id:
                lines.append(f"- **CWE**: {f.cwe_id}")
            lines.append("")
            lines.append(f"**Description**: {f.description}")
            lines.append("")

            if f.code_snippet:
                lines.append("**Code**:")
                lines.append("```python")
                lines.append(f.code_snippet)
                lines.append("```")
                lines.append("")

            if f.remediation:
                lines.append(f"**Remediation**: {f.remediation}")
                lines.append("")

            lines.append("---")
            lines.append("")

    def _write_remediation_summary(
        self, lines: List[str], findings: List[Finding]
    ) -> None:
        """Write a deduplicated remediation summary."""
        if not findings:
            return

        # Deduplicate remediations by rule_id
        seen: Dict[str, str] = {}
        for f in findings:
            if f.remediation and f.rule_id not in seen:
                seen[f.rule_id] = f.remediation

        if not seen:
            return

        lines.append("## Remediation Summary")
        lines.append("")

        for rule_id, remediation in seen.items():
            lines.append(f"- **{rule_id}**: {remediation}")

        lines.append("")

    def _write_footer(self, lines: List[str], result: ScanResult) -> None:
        """Write report footer."""
        lines.append("---")
        lines.append("")
        lines.append(
            f"*Generated by Security Scanner v{result.metadata.scanner_version}*"
        )
