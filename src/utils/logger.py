"""Logging configuration using loguru."""

import sys

from loguru import logger

from src.config import get_settings


def setup_logger() -> None:
    """Configure loguru logger based on application settings."""
    settings = get_settings()

    logger.remove()

    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    logger.add(
        sys.stderr,
        format=log_format,
        level=settings.log_level,
        colorize=True,
    )

    logger.add(
        "logs/scanner.log",
        format=log_format,
        level="DEBUG",
        rotation="10 MB",
        retention="7 days",
        compression="gz",
    )

    # Suppress sensitive data in logs
    logger.info("Logger initialized at level: {}", settings.log_level)
