"""Application configuration using pydantic-settings."""

from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "Security Scanner"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # Ollama / LLM
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "deepseek-coder:6.7b"
    ollama_timeout: int = 30
    ollama_max_retries: int = 3
    llm_context_window: int = 8000
    llm_max_tokens: int = 2000
    embedding_batch_size: int = 32

    # Paths
    data_dir: Path = Path("./data")
    output_dir: Path = Path("./outputs")
    rules_dir: Path = Path("./data/security_rules")
    vector_db_dir: Path = Path("./data/vector_db")

    # Scanning
    max_file_size_mb: int = 10
    scan_timeout_seconds: int = 3600
    max_concurrent_files: int = 5

    # Reporting
    default_output_formats: str = "json,markdown"
    include_code_snippets: bool = True
    max_snippet_lines: int = 10

    # Security
    api_key: str = ""
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"

    @property
    def output_formats_list(self) -> List[str]:
        """Parse comma-separated output formats into a list."""
        return [f.strip() for f in self.default_output_formats.split(",")]

    @property
    def allowed_origins_list(self) -> List[str]:
        """Parse comma-separated allowed origins into a list."""
        return [o.strip() for o in self.allowed_origins.split(",")]

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        for directory in [self.data_dir, self.output_dir, self.rules_dir, self.vector_db_dir]:
            directory.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    """Create and return application settings singleton."""
    return Settings()
