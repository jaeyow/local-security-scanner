"""Code analyzer — orchestrates the three-layer scanning pipeline.

Pipeline:
  1. Regex (fast)    — PatternMatcher scans all files against rules with patterns
  2. Semantic (smart) — VectorStore finds relevant rules per code snippet
  3. LLM (deep)      — LLMAnalyzer does contextual analysis + validation

Additionally:
  - Complexity detection via tree-sitter metrics (no LLM needed)
  - False positive filtering via LLM validation of regex findings
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from src.config import get_settings
from src.core.llm_analyzer import LLMAnalyzer
from src.core.pattern_matcher import PatternMatch, PatternMatcher
from src.core.rule_loader import RuleLoader
from src.core.tree_sitter_parser import FileAnalysis, TreeSitterParser
from src.core.vector_store import VectorStore
from src.models import (
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

    Combines regex pattern matching, tree-sitter AST analysis,
    ChromaDB semantic rule matching, and LLM-powered deep analysis.
    """

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        enable_llm: bool = True,
    ) -> None:
        """Initialize the analyzer with all scanning components.

        Args:
            rules_dir: Path to security rules directory.
                Defaults to settings.rules_dir.
            enable_llm: Whether to enable LLM-powered analysis.
                If False or Ollama is unavailable, falls back to regex-only.
        """
        settings = get_settings()
        self._rules_dir = rules_dir or str(settings.rules_dir)
        self._enable_llm = enable_llm

        # Core components (always available)
        self._rule_loader = RuleLoader(self._rules_dir)
        self._ts_parser = TreeSitterParser()

        # Load rules and init pattern matcher
        self._rule_loader.load_builtin_rules()
        rules_with_patterns = self._rule_loader.get_rules_with_patterns()
        self._matcher = PatternMatcher(rules_with_patterns)

        # LLM components (optional, graceful degradation)
        self._llm_analyzer: Optional[LLMAnalyzer] = None
        self._vector_store: Optional[VectorStore] = None
        self._llm_available = False

        if enable_llm:
            self._init_llm_components()

        logger.info(
            "CodeAnalyzer initialized: {} rules, {} with patterns, LLM: {}",
            len(self._rule_loader.rules),
            self._matcher.rule_count,
            "enabled" if self._llm_available else "disabled",
        )

    def _init_llm_components(self) -> None:
        """Initialize LLM analyzer and vector store if available."""
        try:
            self._llm_analyzer = LLMAnalyzer()
            self._llm_available = self._llm_analyzer.is_available

            if self._llm_available:
                logger.info("LLM is available — enabling deep analysis")
            else:
                logger.warning(
                    "LLM not reachable — falling back to regex + complexity only"
                )

            # Always init vector store (uses local embeddings, no LLM needed)
            self._vector_store = VectorStore()
            self._vector_store.index_rules(self._rule_loader.rules)
            logger.info(
                "VectorStore indexed {} rules",
                self._vector_store.rule_count,
            )
        except Exception as e:
            logger.warning("Failed to initialize LLM components: {}", e)
            self._llm_available = False

    def scan_codebase(
        self,
        codebase_path: str,
        exclude_patterns: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
    ) -> ScanResult:
        """Scan an entire codebase using the three-layer pipeline.

        Args:
            codebase_path: Root directory of the codebase to scan.
            exclude_patterns: Glob patterns for files to skip.
            extensions: File extensions to scan (default: ['.py']).

        Returns:
            ScanResult with all findings and metadata.
        """
        root = Path(codebase_path).resolve()

        if not root.exists() or not root.is_dir():
            raise ValueError(
                f"Codebase path is not a valid directory: {codebase_path}"
            )

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

        # Collect files
        files = self._collect_files(root, extensions, exclude_patterns)
        logger.info("Found {} files to scan", len(files))

        # === Layer 1: Regex pattern matching ===
        all_matches: List[PatternMatch] = []
        file_analyses: Dict[str, FileAnalysis] = {}
        language_stats: Dict[str, int] = {}
        total_lines = 0

        for file_path in files:
            matches = self._matcher.scan_file(file_path)
            all_matches.extend(matches)

            if file_path.suffix == ".py":
                analysis = self._ts_parser.parse_file(file_path)
                file_analyses[str(file_path)] = analysis

            lang = detect_language(file_path) or "Unknown"
            language_stats[lang] = language_stats.get(lang, 0) + 1
            total_lines += count_lines(file_path)

        # Convert regex matches to findings
        regex_findings = self._matches_to_findings(all_matches, scan_id)
        finding_counter = len(regex_findings)

        logger.info(
            "Layer 1 (regex): {} findings from {} matches",
            len(regex_findings),
            len(all_matches),
        )

        # === Layer 1.5: Complexity detection (tree-sitter, no LLM) ===
        complexity_findings: List[Finding] = []
        if self._llm_analyzer:
            for fp, analysis in file_analyses.items():
                issues = self._llm_analyzer.detect_complexity_issues(analysis)
                if issues:
                    cf = self._llm_analyzer.complexity_to_findings(issues)
                    complexity_findings.extend(cf)

        logger.info(
            "Complexity detection: {} issues found",
            len(complexity_findings),
        )

        # === Layer 2+3: Semantic matching + LLM analysis ===
        llm_findings: List[Finding] = []
        validated_findings = list(regex_findings)

        if self._llm_available and self._vector_store and self._llm_analyzer:
            for file_path in files:
                if file_path.suffix != ".py":
                    continue

                try:
                    code = file_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                # Layer 2: Query vector store for relevant rules
                relevant_rules = self._vector_store.query_relevant_rules(
                    code[:2000], n_results=5
                )

                # Filter to rules that need LLM analysis
                # (either LLM-only rules or rules worth deeper inspection)
                llm_rules = [
                    r for r in relevant_rules
                    if r.detection.llm_prompt
                ]

                if llm_rules:
                    # Layer 3: LLM deep analysis
                    file_llm_findings = self._llm_analyzer.analyze_code_with_rules(
                        code, llm_rules, str(file_path)
                    )
                    llm_findings.extend(file_llm_findings)

            logger.info(
                "Layer 2+3 (semantic + LLM): {} findings from {} files",
                len(llm_findings),
                sum(1 for f in files if f.suffix == ".py"),
            )

            # False positive validation on high-severity regex findings
            validated_findings = self._validate_regex_findings(
                regex_findings, files
            )

        # Combine all findings
        all_findings = validated_findings + llm_findings + complexity_findings

        # Re-number finding IDs
        for idx, finding in enumerate(all_findings, start=1):
            finding.finding_id = generate_finding_id(scan_id, idx)

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
            summary=self._build_summary(all_findings),
            findings=all_findings,
            files_analyzed=[
                {
                    "file_path": str(f),
                    "violations": sum(
                        1 for finding in all_findings
                        if finding.file_path == str(f)
                    ),
                }
                for f in files
                if any(finding.file_path == str(f) for finding in all_findings)
            ],
        )

        logger.info(
            "Scan {} complete: {} files, {} findings "
            "(regex: {}, LLM: {}, complexity: {}) in {}s",
            scan_id,
            len(files),
            len(all_findings),
            len(validated_findings),
            len(llm_findings),
            len(complexity_findings),
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

    def _validate_regex_findings(
        self,
        findings: List[Finding],
        files: List[Path],
    ) -> List[Finding]:
        """Use LLM to filter false positives from regex findings.

        Only validates CRITICAL and HIGH severity findings to limit
        LLM calls. Keeps all findings if LLM is unavailable.

        Args:
            findings: Regex-detected findings to validate.
            files: List of scanned file paths.

        Returns:
            Filtered list with false positives removed.
        """
        if not self._llm_available or not self._llm_analyzer:
            return findings

        validated: List[Finding] = []
        rejected_count = 0

        for finding in findings:
            # Only LLM-validate high-severity findings (cost/benefit)
            if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                validated.append(finding)
                continue

            try:
                file_path = Path(finding.file_path)
                if not file_path.exists():
                    validated.append(finding)
                    continue

                code = file_path.read_text(encoding="utf-8", errors="ignore")
                is_real = self._llm_analyzer.validate_finding(code, finding)

                if is_real:
                    validated.append(finding)
                else:
                    rejected_count += 1
            except Exception as e:
                logger.debug(
                    "Validation failed for {}, keeping finding: {}",
                    finding.finding_id, e,
                )
                validated.append(finding)

        if rejected_count:
            logger.info(
                "LLM validation: {} false positives removed from {} findings",
                rejected_count,
                len(findings),
            )

        return validated

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
