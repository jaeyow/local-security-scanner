"""FastAPI application entrypoint for the security scanner."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from src.api.routes import router as api_router
from src.api.scan_manager import ScanManager
from src.config import get_settings
from src.utils.logger import setup_logger


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown hooks."""
    setup_logger()
    settings = get_settings()
    settings.ensure_directories()

    # Initialize the shared ScanManager and attach to app.state
    scan_manager = ScanManager()
    app.state.scan_manager = scan_manager

    logger.info(
        "Security Scanner v{} started — {} rules loaded",
        settings.app_version,
        scan_manager.rules_loaded,
    )
    yield
    logger.info("Security Scanner shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Local AI-powered security code scanner. "
        "Analyzes Python codebases against OWASP, ISO 27001, PCI DSS, "
        "and SOC 2 compliance frameworks using Ollama + DeepSeek-Coder.",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routes under /api/v1
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()
