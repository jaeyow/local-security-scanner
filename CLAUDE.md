# CLAUDE.md - Project Conventions & Guidelines

## Project Overview

Local AI-powered security code scanner that analyzes Python codebases against ISO 27001, PCI DSS, and SOC 2 compliance frameworks. Runs 100% locally using Ollama + DeepSeek-Coder LLM.

## Tech Stack

- **Language**: Python 3.11+
- **Web Framework**: FastAPI 0.109+
- **LLM Runtime**: Ollama (native macOS, Metal GPU acceleration)
- **LLM Model**: DeepSeek-Coder (6.7b dev / 33b prod) - configurable via .env
- **Vector DB**: ChromaDB 0.4.22
- **Code Parsing**: tree-sitter
- **PDF Processing**: PyMuPDF (fitz)
- **Report Generation**: Jinja2, WeasyPrint, matplotlib, plotly
- **Containerization**: Docker (FastAPI only; Ollama runs native)

## Project Structure

```
src/                    # Application source code
  main.py              # FastAPI app entrypoint
  config.py            # Settings via pydantic-settings + .env
  models.py            # Pydantic data models
  api/                 # FastAPI route handlers
  core/                # Business logic (parser, analyzer, LLM, vector store)
  reports/             # Report generators (JSON, Markdown, PDF, HTML, CSV)
  utils/               # Logging, helpers
data/                  # Runtime data (PDFs, vector DB, rules)
tests/                 # pytest test suite
outputs/               # Generated scan reports
docs/                  # PRD and supporting documentation
```

## Coding Standards

- **Formatting**: black (line length 88)
- **Linting**: flake8, mypy (strict)
- **Type hints**: Required on all public functions and methods
- **Docstrings**: Google-style, required on all public classes and functions
- **Imports**: isort, stdlib -> third-party -> local, absolute imports only
- **Naming**: snake_case for functions/variables, PascalCase for classes, UPPER_SNAKE for constants

## Development Practices

- **Git workflow**: Feature branches off main, commit per day-plan milestone
- **Branch naming**: `feature/<description>`, `fix/<description>`, `refactor/<description>`
- **Commit messages**: Conventional commits style (feat:, fix:, refactor:, test:, docs:, chore:)
- **Testing**: pytest + pytest-asyncio, target >70% coverage
- **Async**: Use async/await for all I/O-bound operations (LLM calls, file I/O, DB queries)

## Key Architectural Decisions

1. **Hybrid Docker**: Ollama runs native (Metal GPU), FastAPI in Docker container
2. **Ollama connection**: Container connects via `host.docker.internal:11434`
3. **Hardcoded rules first**: JSON rule set built-in for MVP; PDF parsing is supplemental
4. **Configurable LLM**: Model name in .env, defaults to smaller model for dev
5. **Pydantic models**: All data structures use Pydantic v2 for validation
6. **Background scanning**: Long scans run as FastAPI BackgroundTasks

## Environment Variables

Key settings in `.env`:
- `OLLAMA_HOST` - Ollama server URL (default: http://localhost:11434)
- `OLLAMA_MODEL` - Model name (default: deepseek-coder:6.7b)
- `DEBUG` - Enable debug mode (default: false)
- `LOG_LEVEL` - Logging level (default: INFO)
- `DATA_DIR`, `OUTPUT_DIR`, `RULES_DIR`, `VECTOR_DB_DIR` - Path configuration

## Running the Application

```bash
# Development
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Testing
pytest tests/ -v --cov=src --cov-report=term-missing

# Linting
black src/ tests/
flake8 src/ tests/
mypy src/

# Docker
docker-compose up --build
```

## Important Notes

- All processing must remain 100% local - no external API calls
- Never log sensitive data (credentials, PII, scan contents)
- Validate all file paths to prevent directory traversal
- Rate limit API endpoints
- LLM responses must be parsed defensively (handle hallucinations/malformed JSON)
