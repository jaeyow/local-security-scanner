"""Report orchestrator — dispatches to format-specific generators."""

from pathlib import Path
from typing import Dict, List

from loguru import logger

from src.config import get_settings
from src.models import ScanResult
from src.reports.json_report import JsonReportGenerator
from src.reports.markdown_report import MarkdownReportGenerator


class ReportManager:
    """Generates reports in multiple formats for a scan result.

    Dispatches to format-specific generators and returns
    a mapping of format -> output file path.
    """

    def __init__(self, output_dir: str = "") -> None:
        """Initialize the report manager.

        Args:
            output_dir: Directory for generated reports.
                Defaults to settings.output_dir.
        """
        settings = get_settings()
        self._output_dir = Path(output_dir) if output_dir else settings.output_dir
        self._json_gen = JsonReportGenerator()
        self._markdown_gen = MarkdownReportGenerator()

    def generate_reports(
        self,
        result: ScanResult,
        formats: List[str] = None,
    ) -> Dict[str, str]:
        """Generate reports in the specified formats.

        Args:
            result: The scan result to report on.
            formats: List of formats to generate (e.g. ['json', 'markdown']).
                Defaults to settings.output_formats_list.

        Returns:
            Dict mapping format name to output file path.
        """
        if formats is None:
            settings = get_settings()
            formats = settings.output_formats_list

        self._output_dir.mkdir(parents=True, exist_ok=True)

        scan_id = result.metadata.scan_id
        report_paths: Dict[str, str] = {}

        for fmt in formats:
            fmt = fmt.strip().lower()
            try:
                if fmt == "json":
                    path = self._output_dir / f"{scan_id}.json"
                    self._json_gen.generate(result, path)
                    report_paths["json"] = str(path)

                elif fmt in ("markdown", "md"):
                    path = self._output_dir / f"{scan_id}.md"
                    self._markdown_gen.generate(result, path)
                    report_paths["markdown"] = str(path)

                else:
                    logger.warning("Unsupported report format: {}", fmt)

            except Exception as e:
                logger.error("Failed to generate {} report: {}", fmt, e)

        logger.info(
            "Generated {} reports for scan {}: {}",
            len(report_paths),
            scan_id,
            list(report_paths.keys()),
        )
        return report_paths
