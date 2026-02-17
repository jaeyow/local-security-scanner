"""Code analyzer — orchestrates scanning a codebase against security rules."""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from src.config import get_settings
from src.core.pattern_matcher import PatternMatch, PatternMatcher
from src.core.rule_loader import RuleLoader
from src.core.tree_sitter_parser import FileAnalysis, TreeSitterParser
from src.models import (
    ComplianceMapping,
    Finding,
    Priority,
    ScanMetadata,
    ScanResult,
    ScanScope,
    ScanSummary,
    Severity,
)
from src.utils.helpers import (
    count_lines,
    detect_language,
    extract_code_snippet,
    generate_finding_id,
    generate_scan_id,
    matches_glob_pattern,
)


class CodeAnalyzer:
    """Orchestrates security scanning of a codebase.

    Combines regex pattern matching and tree-sitter AST analysis
    to detect security vulnerabilities against loaded rules.
    """

    def __init__(self, rules_dir: Optional[str] = None) -> None:
        """Initialize the analyzer with rule loader, matcher, and parser.

        Args:
            rules_dir: Path to security rules directory.
                Defaults to settings.rules_dir.
        """
        settings = get_settings()
        self._rules_dir = rules_dir or str(settings.rules_dir)

        self._rule_loader = RuleLoader(self._rules_dir)
        self._ts_parser = TreeSitterParser()
        self._matcher: Optional[PatternMatcher] = None

        self._rule_loader.load_builtin_rules()
        rules_with_patterns = self._rule_loader.get_rules_with_patterns()
        self._matcher = PatternMatcher(rules_with_patterns)

        logger.info(
            "CodeAnalyzer initialized: {} rules loaded, {} with patterns",
            len(self._rule_loader.rules),
            self._matcher.rule_count,
        )

    def scan_codebase(
        self,
        codebase_path: str,
        exclude_patterns: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
    ) -> ScanResult:
        """Scan an entire codebase and produce a ScanResult.

        Args:
            codebase_path: Root directory of the codebase to scan.
            exclude_patterns: Glob patterns for files to skip.
            extensions: File extensions to scan (default: ['.py']).

        Returns:
            ScanResult with all findings and metadata.
        """
        settings = get_settings()
        root = Path(codebase_path).resolve()

        if not root.exists() or not root.is_dir():
            raise ValueError(f"Codebase path is not a valid directory: {codebase_path}")

        if exclude_patterns is None:
            exclude_patterns = [
                "**/test_*.py", "**/tests/**", "**/vendor/**",
                "**/.venv/**", "**/node_modules/**", "**/__pycache__/**",
            ]

        if extensions is None:
            extensions = [".py"]

        scan_id = generate_scan_id()
        start_time = datetime.utcnow()

        logger.info("Starting scan {} on {}", scan_id, root)

        # Collect files to scan
        files = self._collect_files(root, extensions, exclude_patterns)
        logger.info("Found {} files to scan", len(files))

        # Run pattern matching
        all_matches: List[PatternMatch] = []
        file_analyses: List[FileAnalysis] = []
        language_stats: Dict[str, int] = {}
        total_lines = 0

        for file_path in files:
            # Pattern matching
            matches = self._matcher.scan_file(file_path)
            all_matches.extend(matches)

            # Tree-sitter analysis
            if file_path.suffix == ".py":
                analysis = self._ts_parser.parse_file(file_path)
                file_analyses.append(analysis)

            # Stats
            lang = detect_language(file_path) or "Unknown"
            language_stats[lang] = language_stats.get(lang, 0) + 1
            total_lines += count_lines(file_path)

        # Convert matches to findings
        findings = self._matches_to_findings(all_matches, scan_id)

        # Build result
        duration = int((datetime.utcnow() - start_time).total_seconds())

        result = ScanResult(
            metadata=ScanMetadata(
                scan_id=scan_id,
                timestamp=start_time,
                duration_seconds=duration,
            ),
            scope=ScanScope(
                repository=str(root),
                files_scanned=len(files),
                lines_of_code=total_lines,
                languages=language_stats,
            ),
            summary=self._build_summary(findings),
            findings=findings,
            files_analyzed=[
                {
                    "file_path": str(f),
                    "violations": sum(
                        1 for m in all_matches if m.file_path == str(f)
                    ),
                }
                for f in files
                if any(m.file_path == str(f) for m in all_matches)
            ],
        )

        logger.info(
            "Scan {} complete: {} files, {} findings in {}s",
            scan_id,
            len(files),
            len(findings),
            duration,
        )

        return result

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file and return findings.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings from this file.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        matches = self._matcher.scan_file(path)
        scan_id = generate_scan_id()
        return self._matches_to_findings(matches, scan_id)

    def scan_text(self, source: str, filename: str = "<input>") -> List[Finding]:
        """Scan source code text directly.

        Args:
            source: Source code string.
            filename: Label for the source.

        Returns:
            List of findings.
        """
        matches = self._matcher.scan_text(source, filename)
        scan_id = generate_scan_id()
        return self._matches_to_findings(matches, scan_id)

    def _collect_files(
        self,
        root: Path,
        extensions: List[str],
        exclude_patterns: List[str],
    ) -> List[Path]:
        """Collect all scannable files from a directory tree."""
        settings = get_settings()
        max_size = settings.max_file_size_mb * 1024 * 1024
        files: List[Path] = []

        for ext in extensions:
            for file_path in root.rglob(f"*{ext}"):
                if matches_glob_pattern(str(file_path), exclude_patterns):
                    continue

                try:
                    if file_path.stat().st_size > max_size:
                        logger.debug("Skipping large file: {}", file_path)
                        continue
                except OSError:
                    continue

                files.append(file_path)

        return sorted(files)

    def _matches_to_findings(
        self, matches: List[PatternMatch], scan_id: str
    ) -> List[Finding]:
        """Convert pattern matches into Finding objects."""
        findings: List[Finding] = []

        for idx, match in enumerate(matches, start=1):
            rule = match.rule
            file_path = Path(match.file_path)

            snippet = ""
            if file_path.exists():
                snippet = extract_code_snippet(
                    file_path, match.line_number, context_lines=3
                )

            finding = Finding(
                finding_id=generate_finding_id(scan_id, idx),
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                category=rule.category,
                file_path=match.file_path,
                line_number=match.line_number,
                function_name=None,
                code_snippet=snippet or match.line_content,
                description=rule.description,
                impact=f"{rule.severity.value} severity: {rule.title}",
                remediation=rule.remediation,
                cwe_id=rule.cwe_id,
                compliance=rule.compliance,
                priority=self._severity_to_priority(rule.severity),
                references=rule.references,
            )
            findings.append(finding)

        return findings

    def _build_summary(self, findings: List[Finding]) -> ScanSummary:
        """Build a scan summary from findings."""
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}

        for f in findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1

        # Simple scoring: start at 100, deduct per finding
        score = max(
            0,
            100
            - by_severity.get("CRITICAL", 0) * 15
            - by_severity.get("HIGH", 0) * 10
            - by_severity.get("MEDIUM", 0) * 5
            - by_severity.get("LOW", 0) * 2,
        )

        return ScanSummary(
            total_findings=len(findings),
            by_severity=by_severity,
            by_category=by_category,
            security_score=score,
        )

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
