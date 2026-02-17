"""API route handlers for the security scanner."""

import time
from pathlib import Path

from fastapi import (
    APIRouter,
    BackgroundTasks,
    HTTPException,
    Request,
    UploadFile,
    File,
    status,
)
from loguru import logger

from src.config import get_settings
from src.models import (
    HealthResponse,
    RuleUploadResponse,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanStatusResponse,
)
from src.utils.helpers import generate_scan_id, sanitize_path

router = APIRouter()


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> ScanResponse:
    """Start a new security scan as a background task.

    Validates the codebase path, creates a scan record,
    and queues the analysis as a background task.
    """
    manager = request.app.state.scan_manager

    # Validate and sanitize path
    try:
        safe_path = sanitize_path(scan_request.codebase_path)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid codebase path: {e}",
        )

    if not safe_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Path is not a directory: {scan_request.codebase_path}",
        )

    scan_id = generate_scan_id()
    scan_state = manager.create_scan(scan_id, str(safe_path))

    background_tasks.add_task(
        manager.run_scan,
        scan_state,
        scan_request.exclude_patterns,
    )

    logger.info("Scan {} queued for {}", scan_id, safe_path)

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        message="Scan queued successfully",
    )


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, request: Request) -> ScanStatusResponse:
    """Get the status and results of a scan."""
    manager = request.app.state.scan_manager
    scan_state = manager.get_scan(scan_id)

    if not scan_state:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found: {scan_id}",
        )

    return ScanStatusResponse(
        scan_id=scan_state.scan_id,
        status=scan_state.status,
        progress=scan_state.progress,
        result=scan_state.result,
        report_urls=scan_state.report_paths,
    )


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    """Health check: scanner status, Ollama connectivity, rules loaded."""
    settings = get_settings()
    manager = request.app.state.scan_manager

    ollama_connected = manager.check_ollama()

    return HealthResponse(
        status="healthy" if ollama_connected else "degraded",
        ollama_connected=ollama_connected,
        scanner_version=settings.app_version,
        rules_loaded=manager.rules_loaded,
    )


@router.post("/rules/upload", response_model=RuleUploadResponse)
async def upload_rules(
    request: Request,
    file: UploadFile = File(...),
) -> RuleUploadResponse:
    """Upload a PDF file to extract security rules.

    Accepts a multipart PDF upload, saves it to the rules directory,
    and parses it for security rules using the PDF parser.
    """
    manager = request.app.state.scan_manager
    settings = get_settings()

    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are accepted",
        )

    start_time = time.time()

    # Save uploaded PDF to rules directory
    upload_path = settings.rules_dir / file.filename
    content = await file.read()
    upload_path.write_bytes(content)

    try:
        rules = manager.pdf_parser.parse_pdf_to_rules(str(upload_path))
        processing_time = time.time() - start_time

        return RuleUploadResponse(
            status="success",
            rules_extracted=len(rules),
            processing_time=round(processing_time, 2),
            message=f"Extracted {len(rules)} rules from {file.filename}",
        )
    except Exception as e:
        logger.error("PDF parsing failed for {}: {}", file.filename, e)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse PDF: {e}",
        )


@router.get("/rules")
async def list_rules(request: Request) -> dict:
    """List all loaded security rules (summary view)."""
    manager = request.app.state.scan_manager
    rules = manager.rule_loader.rules

    return {
        "total": len(rules),
        "rules": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity.value,
                "owasp_category": r.owasp_category,
            }
            for r in rules
        ],
    }
