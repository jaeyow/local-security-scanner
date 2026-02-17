FROM python:3.11-slim

WORKDIR /app

# System dependencies for tree-sitter, WeasyPrint, PyMuPDF
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY data/ ./data/

# Create output and log directories
RUN mkdir -p /app/outputs /app/logs

# Non-root user for security
RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
