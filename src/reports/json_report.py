"""JSON report generator for scan results."""

import json
from pathlib import Path

from loguru import logger

from src.models import ScanResult


class JsonReportGenerator:
    """Generates formatted JSON report files from scan results."""

    def generate(self, result: ScanResult, output_path: Path) -> Path:
        """Write a scan result as a formatted JSON report.

        Args:
            result: The scan result to export.
            output_path: Path to write the JSON file.

        Returns:
            The path to the generated report file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = result.model_dump(mode="json")
        output_path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )

        logger.info(
            "JSON report written to {} ({} findings)",
            output_path,
            result.summary.total_findings,
        )
        return output_path
