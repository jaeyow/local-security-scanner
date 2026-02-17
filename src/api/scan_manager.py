"""In-memory scan state manager for background scan tracking."""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional

from loguru import logger

from src.core.analyzer import CodeAnalyzer
from src.core.llm_client import OllamaClient
from src.core.pdf_parser import PDFParser
from src.core.rule_loader import RuleLoader
from src.models import ScanResult, ScanStatus
from src.reports.report_manager import ReportManager


class ScanState:
    """Holds the mutable state for a single scan."""

    def __init__(self, scan_id: str, codebase_path: str) -> None:
        """Initialize scan state.

        Args:
            scan_id: Unique identifier for this scan.
            codebase_path: Path to the codebase being scanned.
        """
        self.scan_id: str = scan_id
        self.codebase_path: str = codebase_path
        self.status: ScanStatus = ScanStatus.PENDING
        self.progress: int = 0
        self.result: Optional[ScanResult] = None
        self.report_paths: Dict[str, str] = {}
        self.error: Optional[str] = None
        self.created_at: datetime = datetime.utcnow()


class ScanManager:
    """Manages scan lifecycle, state tracking, and core component access.

    Provides an in-memory dict of scan_id -> ScanState for MVP.
    Thread-safe via asyncio (single event loop).
    """

    MAX_SCANS = 100

    def __init__(self) -> None:
        """Initialize with core components."""
        self._scans: Dict[str, ScanState] = {}
        self._analyzer = CodeAnalyzer()
        self._ollama_client = OllamaClient()
        self._pdf_parser = PDFParser()
        self._rule_loader = RuleLoader()
        self._rule_loader.load_builtin_rules()
        self._report_manager = ReportManager()

    @property
    def rules_loaded(self) -> int:
        """Number of security rules currently loaded."""
        return len(self._rule_loader.rules)

    @property
    def rule_loader(self) -> RuleLoader:
        """Access the rule loader instance."""
        return self._rule_loader

    @property
    def pdf_parser(self) -> PDFParser:
        """Access the PDF parser instance."""
        return self._pdf_parser

    def check_ollama(self) -> bool:
        """Check if the Ollama LLM is reachable.

        Returns:
            True if Ollama server responds and model is loaded.
        """
        try:
            return self._ollama_client.is_available()
        except Exception as e:
            logger.warning("Ollama health check failed: {}", e)
            return False

    def get_scan(self, scan_id: str) -> Optional[ScanState]:
        """Retrieve a scan by its ID.

        Args:
            scan_id: The scan identifier.

        Returns:
            ScanState if found, None otherwise.
        """
        return self._scans.get(scan_id)

    def list_scans(self) -> List[ScanState]:
        """Return all tracked scans, newest first."""
        return sorted(
            self._scans.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )

    def create_scan(self, scan_id: str, codebase_path: str) -> ScanState:
        """Create and register a new scan.

        Args:
            scan_id: Unique scan identifier.
            codebase_path: Path to scan.

        Returns:
            The new ScanState.
        """
        state = ScanState(scan_id=scan_id, codebase_path=codebase_path)
        self._scans[scan_id] = state
        self._evict_old_scans()
        return state

    async def run_scan(
        self,
        scan_state: ScanState,
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        """Execute a scan in the background.

        Runs the synchronous CodeAnalyzer in a thread pool executor
        to avoid blocking the async event loop.

        Args:
            scan_state: The scan state to update during execution.
            exclude_patterns: Glob patterns for files to skip.
        """
        scan_state.status = ScanStatus.RUNNING
        scan_state.progress = 10

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._analyzer.scan_codebase(
                    scan_state.codebase_path,
                    exclude_patterns=exclude_patterns,
                ),
            )
            scan_state.result = result
            scan_state.progress = 90

            # Generate reports
            try:
                report_paths = self._report_manager.generate_reports(result)
                scan_state.report_paths = report_paths
                logger.info(
                    "Reports generated for scan {}: {}",
                    scan_state.scan_id,
                    list(report_paths.keys()),
                )
            except Exception as e:
                logger.warning(
                    "Report generation failed for scan {}: {}",
                    scan_state.scan_id, e,
                )

            scan_state.status = ScanStatus.COMPLETED
            scan_state.progress = 100
            logger.info(
                "Scan {} completed: {} findings",
                scan_state.scan_id,
                result.summary.total_findings,
            )
        except Exception as e:
            logger.error("Scan {} failed: {}", scan_state.scan_id, e)
            scan_state.status = ScanStatus.FAILED
            scan_state.error = str(e)

    def _evict_old_scans(self) -> None:
        """Remove the oldest scan when the limit is exceeded."""
        if len(self._scans) > self.MAX_SCANS:
            oldest_key = min(
                self._scans, key=lambda k: self._scans[k].created_at
            )
            del self._scans[oldest_key]
