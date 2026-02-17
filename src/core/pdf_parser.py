"""PDF parser for extracting security rules from standard documents."""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from src.models import (
    CodeExample,
    ComplianceMapping,
    DetectionMethod,
    SecurityRule,
    Severity,
)


class PDFParser:
    """Extracts security rules from PDF documents (OWASP, CWE, etc.)."""

    def __init__(self) -> None:
        self._fitz: Optional[Any] = None

    def _get_fitz(self) -> Any:
        """Lazy import of fitz (PyMuPDF) to avoid import errors if not installed."""
        if self._fitz is None:
            try:
                import fitz
                self._fitz = fitz
            except ImportError:
                raise ImportError(
                    "PyMuPDF (fitz) is required for PDF parsing. "
                    "Install it with: pip install pymupdf"
                )
        return self._fitz

    def extract_text(self, pdf_path: str) -> str:
        """Extract all text from a PDF file.

        Args:
            pdf_path: Path to the PDF file.

        Returns:
            Extracted text content.

        Raises:
            FileNotFoundError: If the PDF file does not exist.
            ValueError: If the file is not a valid PDF.
        """
        path = Path(pdf_path)
        if not path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        if path.suffix.lower() != ".pdf":
            raise ValueError(f"File is not a PDF: {pdf_path}")

        fitz = self._get_fitz()
        logger.info("Extracting text from PDF: {}", pdf_path)

        text_parts: List[str] = []
        try:
            doc = fitz.open(str(path))
            for page_num, page in enumerate(doc):
                page_text = page.get_text()
                if page_text.strip():
                    text_parts.append(page_text)
                logger.debug("Extracted page {}/{}", page_num + 1, len(doc))
            doc.close()
        except Exception as e:
            logger.error("Failed to parse PDF {}: {}", pdf_path, e)
            raise ValueError(f"Failed to parse PDF: {e}") from e

        full_text = "\n".join(text_parts)
        logger.info(
            "Extracted {} characters from {} pages",
            len(full_text),
            len(text_parts),
        )
        return full_text

    def extract_tables(self, pdf_path: str) -> List[List[List[str]]]:
        """Extract tables from a PDF using pdfplumber as fallback.

        Args:
            pdf_path: Path to the PDF file.

        Returns:
            List of tables, where each table is a list of rows.
        """
        try:
            import pdfplumber
        except ImportError:
            logger.warning("pdfplumber not installed, skipping table extraction")
            return []

        tables: List[List[List[str]]] = []
        try:
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    page_tables = page.extract_tables()
                    if page_tables:
                        tables.extend(page_tables)
        except Exception as e:
            logger.error("Failed to extract tables from {}: {}", pdf_path, e)

        logger.info("Extracted {} tables from {}", len(tables), pdf_path)
        return tables

    def parse_owasp_rules(self, pdf_path: str) -> List[SecurityRule]:
        """Parse OWASP Top 10 PDF into security rules.

        Args:
            pdf_path: Path to the OWASP Top 10 PDF.

        Returns:
            List of extracted security rules.
        """
        text = self.extract_text(pdf_path)
        rules: List[SecurityRule] = []

        # Pattern to match OWASP categories (A01-A10)
        category_pattern = re.compile(
            r"A(\d{2})[:\s]+(\d{4})\s*[-–]\s*(.+?)(?=\nA\d{2}|\Z)",
            re.DOTALL,
        )

        matches = category_pattern.finditer(text)
        for match in matches:
            category_num = match.group(1)
            year = match.group(2)
            title = match.group(3).strip().split("\n")[0]

            rule = SecurityRule(
                rule_id=f"OWASP-A{category_num}-001",
                title=title,
                category=f"A{category_num}: {title}",
                severity=self._owasp_severity(category_num),
                description=f"OWASP Top 10 {year} - {title}",
                owasp_category=f"A{category_num}",
                detection=DetectionMethod(
                    llm_prompt=f"Check for {title} vulnerabilities"
                ),
                remediation=f"Follow OWASP guidance for {title}",
                references=[f"https://owasp.org/Top10/A{category_num}/"],
            )
            rules.append(rule)

        logger.info("Parsed {} OWASP rules from {}", len(rules), pdf_path)
        return rules

    def parse_cwe_rules(self, text: str) -> List[SecurityRule]:
        """Parse CWE data into security rules.

        Args:
            text: Raw text content from CWE source.

        Returns:
            List of extracted security rules.
        """
        rules: List[SecurityRule] = []

        # Pattern to match CWE entries
        cwe_pattern = re.compile(
            r"CWE-(\d+)[:\s]+(.+?)(?=CWE-\d+|\Z)",
            re.DOTALL,
        )

        matches = cwe_pattern.finditer(text)
        for match in matches:
            cwe_id = match.group(1)
            content = match.group(2).strip()
            title = content.split("\n")[0].strip()

            rule = SecurityRule(
                rule_id=f"CWE-{cwe_id}-001",
                title=title,
                category=f"CWE-{cwe_id}",
                severity=Severity.HIGH,
                description=content[:500],
                cwe_id=f"CWE-{cwe_id}",
                detection=DetectionMethod(
                    llm_prompt=f"Check for CWE-{cwe_id}: {title}"
                ),
                remediation=f"Address CWE-{cwe_id}: {title}",
                references=[f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"],
            )
            rules.append(rule)

        logger.info("Parsed {} CWE rules", len(rules))
        return rules

    def parse_pdf_to_rules(self, pdf_path: str) -> List[SecurityRule]:
        """Auto-detect PDF type and parse into security rules.

        Args:
            pdf_path: Path to a security standards PDF.

        Returns:
            List of extracted security rules.
        """
        text = self.extract_text(pdf_path)
        text_lower = text.lower()

        if "owasp" in text_lower and "top 10" in text_lower:
            logger.info("Detected OWASP Top 10 document")
            return self.parse_owasp_rules(pdf_path)
        elif "cwe" in text_lower:
            logger.info("Detected CWE document")
            return self.parse_cwe_rules(text)
        else:
            logger.warning("Unknown PDF type, attempting generic extraction")
            return self._generic_parse(text)

    def export_rules_to_json(
        self, rules: List[SecurityRule], output_path: str
    ) -> str:
        """Export parsed rules to a JSON file.

        Args:
            rules: List of security rules to export.
            output_path: Path for the output JSON file.

        Returns:
            Path to the created JSON file.
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        rules_data = [rule.model_dump(mode="json") for rule in rules]
        output.write_text(json.dumps(rules_data, indent=2, default=str))

        logger.info("Exported {} rules to {}", len(rules), output_path)
        return str(output)

    def _generic_parse(self, text: str) -> List[SecurityRule]:
        """Attempt generic extraction of security rules from text."""
        rules: List[SecurityRule] = []
        # Look for numbered items that resemble security rules
        pattern = re.compile(
            r"(\d+\.?\d*)\s*[.:\-–]\s*(.+?)(?=\n\d+\.?\d*\s*[.:\-–]|\Z)",
            re.DOTALL,
        )
        for match in pattern.finditer(text):
            title = match.group(2).strip().split("\n")[0]
            if len(title) > 10 and any(
                kw in title.lower()
                for kw in ["security", "vulnerability", "injection", "access", "auth"]
            ):
                rule = SecurityRule(
                    rule_id=f"GENERIC-{match.group(1).replace('.', '-')}-001",
                    title=title[:100],
                    category="Generic",
                    severity=Severity.MEDIUM,
                    description=title,
                    remediation="Review and address this security concern.",
                )
                rules.append(rule)

        return rules

    @staticmethod
    def _owasp_severity(category_num: str) -> Severity:
        """Map OWASP category number to severity."""
        critical_categories = {"01", "02", "03", "07"}
        high_categories = {"04", "05", "08"}
        if category_num in critical_categories:
            return Severity.CRITICAL
        elif category_num in high_categories:
            return Severity.HIGH
        return Severity.MEDIUM
