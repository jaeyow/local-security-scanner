"""Loads security rules from JSON files into SecurityRule objects."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from loguru import logger

from src.models import SecurityRule


class RuleLoader:
    """Loads and manages security rules from built-in and custom JSON files."""

    def __init__(self, rules_dir: str = "data/security_rules") -> None:
        """Initialize the rule loader.

        Args:
            rules_dir: Directory containing rule JSON files.
        """
        self._rules_dir = Path(rules_dir)
        self._rules: List[SecurityRule] = []
        self._rules_by_id: Dict[str, SecurityRule] = {}

    @property
    def rules(self) -> List[SecurityRule]:
        """All loaded rules."""
        return self._rules

    @property
    def rules_by_id(self) -> Dict[str, SecurityRule]:
        """Rules indexed by rule_id."""
        return self._rules_by_id

    def load_builtin_rules(self) -> int:
        """Load the built-in OWASP rules from builtin_rules.json.

        Returns:
            Number of rules loaded.
        """
        builtin_path = self._rules_dir / "builtin_rules.json"
        return self._load_rules_file(builtin_path)

    def load_all_rules(self, rule_sets: Optional[List[str]] = None) -> int:
        """Load rules from all JSON files in the rules directory.

        Args:
            rule_sets: Optional filter — only load files matching these
                prefixes (e.g. ['builtin', 'cwe']). Loads all if None.

        Returns:
            Total number of rules loaded.
        """
        if not self._rules_dir.exists():
            logger.warning("Rules directory not found: {}", self._rules_dir)
            return 0

        total = 0
        for json_file in sorted(self._rules_dir.glob("*.json")):
            if rule_sets:
                stem = json_file.stem.lower()
                if not any(rs.lower() in stem for rs in rule_sets):
                    continue
            total += self._load_rules_file(json_file)

        logger.info("Loaded {} total rules from {}", total, self._rules_dir)
        return total

    def get_rules_with_patterns(self) -> List[SecurityRule]:
        """Return only rules that have a regex detection pattern.

        Returns:
            List of rules with non-null detection.pattern.
        """
        return [r for r in self._rules if r.detection.pattern]

    def get_rules_by_severity(self, severity: str) -> List[SecurityRule]:
        """Filter rules by severity level.

        Args:
            severity: Severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO).

        Returns:
            List of matching rules.
        """
        return [r for r in self._rules if r.severity.value == severity.upper()]

    def get_rules_by_owasp(self, category: str) -> List[SecurityRule]:
        """Filter rules by OWASP category.

        Args:
            category: OWASP category (e.g. 'A01', 'A02').

        Returns:
            List of matching rules.
        """
        return [r for r in self._rules if r.owasp_category == category]

    def get_categories(self) -> Set[str]:
        """Return all unique rule categories."""
        return {r.category for r in self._rules}

    def _load_rules_file(self, file_path: Path) -> int:
        """Load rules from a single JSON file.

        Args:
            file_path: Path to the JSON file.

        Returns:
            Number of rules loaded from this file.
        """
        if not file_path.exists():
            logger.warning("Rules file not found: {}", file_path)
            return 0

        try:
            raw_data = json.loads(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to read rules file {}: {}", file_path, e)
            return 0

        count = 0
        for entry in raw_data:
            try:
                rule = SecurityRule(**entry)
                if rule.rule_id not in self._rules_by_id:
                    self._rules.append(rule)
                    self._rules_by_id[rule.rule_id] = rule
                    count += 1
                else:
                    logger.debug("Skipping duplicate rule: {}", rule.rule_id)
            except Exception as e:
                logger.warning(
                    "Skipping invalid rule in {}: {}", file_path.name, e
                )

        logger.info("Loaded {} rules from {}", count, file_path.name)
        return count
