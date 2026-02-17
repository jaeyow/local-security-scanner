"""Regex-based pattern matcher for scanning code against security rules."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from src.models import SecurityRule


@dataclass
class PatternMatch:
    """A single regex match found in source code."""

    rule: SecurityRule
    file_path: str
    line_number: int
    line_content: str
    match_text: str


class PatternMatcher:
    """Scans source code files against regex detection patterns from rules."""

    def __init__(self, rules: List[SecurityRule]) -> None:
        """Initialize with rules that have regex detection patterns.

        Args:
            rules: Security rules to match against.
        """
        self._compiled: Dict[str, re.Pattern] = {}
        self._rules: List[SecurityRule] = []

        for rule in rules:
            if rule.detection.pattern:
                try:
                    pattern = re.compile(rule.detection.pattern, re.IGNORECASE)
                    self._compiled[rule.rule_id] = pattern
                    self._rules.append(rule)
                except re.error as e:
                    logger.warning(
                        "Invalid regex in rule {}: {}", rule.rule_id, e
                    )

        logger.info(
            "PatternMatcher initialized with {} compiled patterns",
            len(self._compiled),
        )

    @property
    def rule_count(self) -> int:
        """Number of active rules with valid patterns."""
        return len(self._compiled)

    def scan_file(self, file_path: Path) -> List[PatternMatch]:
        """Scan a single file against all compiled patterns.

        Args:
            file_path: Path to the source file to scan.

        Returns:
            List of pattern matches found.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.error("Cannot read file {}: {}", file_path, e)
            return []

        lines = content.splitlines()
        matches: List[PatternMatch] = []

        for rule in self._rules:
            pattern = self._compiled[rule.rule_id]
            for line_num, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if match:
                    matches.append(
                        PatternMatch(
                            rule=rule,
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.strip(),
                            match_text=match.group(0),
                        )
                    )

        if matches:
            logger.debug(
                "Found {} matches in {}", len(matches), file_path.name
            )

        return matches

    def scan_text(self, text: str, source_name: str = "<string>") -> List[PatternMatch]:
        """Scan raw text content against all compiled patterns.

        Args:
            text: Source code text to scan.
            source_name: Label for the source (used in match results).

        Returns:
            List of pattern matches found.
        """
        lines = text.splitlines()
        matches: List[PatternMatch] = []

        for rule in self._rules:
            pattern = self._compiled[rule.rule_id]
            for line_num, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if match:
                    matches.append(
                        PatternMatch(
                            rule=rule,
                            file_path=source_name,
                            line_number=line_num,
                            line_content=line.strip(),
                            match_text=match.group(0),
                        )
                    )

        return matches

    def scan_directory(
        self,
        directory: Path,
        extensions: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[PatternMatch]:
        """Scan all matching files in a directory tree.

        Args:
            directory: Root directory to scan.
            extensions: File extensions to include (e.g. ['.py', '.js']).
                Defaults to ['.py'].
            exclude_patterns: Glob patterns to exclude.

        Returns:
            All pattern matches found across all files.
        """
        if extensions is None:
            extensions = [".py"]

        if exclude_patterns is None:
            exclude_patterns = []

        all_matches: List[PatternMatch] = []
        files_scanned = 0

        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if self._should_exclude(file_path, exclude_patterns):
                    continue

                file_matches = self.scan_file(file_path)
                all_matches.extend(file_matches)
                files_scanned += 1

        logger.info(
            "Scanned {} files, found {} total matches",
            files_scanned,
            len(all_matches),
        )
        return all_matches

    @staticmethod
    def _should_exclude(file_path: Path, patterns: List[str]) -> bool:
        """Check if a file should be excluded based on glob patterns."""
        from fnmatch import fnmatch

        path_str = str(file_path)
        return any(fnmatch(path_str, p) for p in patterns)
