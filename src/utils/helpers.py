"""Utility helpers for the security scanner."""

import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional


def generate_scan_id() -> str:
    """Generate a unique scan ID based on current timestamp."""
    now = datetime.utcnow()
    return f"scan_{now.strftime('%Y%m%d_%H%M%S')}"


def generate_finding_id(scan_id: str, index: int) -> str:
    """Generate a unique finding ID within a scan.

    Args:
        scan_id: The parent scan ID.
        index: Finding index number.

    Returns:
        Formatted finding ID string.
    """
    return f"FIND-{index:04d}"


def sanitize_path(path: str) -> Path:
    """Sanitize a file path to prevent directory traversal.

    Args:
        path: Raw file path string.

    Returns:
        Resolved, sanitized Path object.

    Raises:
        ValueError: If the path contains traversal attempts.
    """
    resolved = Path(path).resolve()
    if ".." in str(path):
        raise ValueError(f"Directory traversal detected in path: {path}")
    return resolved


def count_lines(file_path: Path) -> int:
    """Count lines of code in a file, excluding blank lines and comments.

    Args:
        file_path: Path to the source file.

    Returns:
        Number of non-blank, non-comment lines.
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
        return sum(
            1
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        )
    except (OSError, UnicodeDecodeError):
        return 0


def extract_code_snippet(
    file_path: Path,
    line_number: int,
    context_lines: int = 3,
    max_lines: int = 10,
) -> str:
    """Extract a code snippet around a specific line number.

    Args:
        file_path: Path to the source file.
        line_number: Target line number (1-indexed).
        context_lines: Number of context lines before and after.
        max_lines: Maximum total lines in snippet.

    Returns:
        Code snippet string with line numbers.
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        start = max(0, line_number - 1 - context_lines)
        end = min(len(lines), line_number + context_lines)

        if end - start > max_lines:
            end = start + max_lines

        snippet_lines = []
        for i in range(start, end):
            prefix = "→" if i == line_number - 1 else " "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
    except (OSError, UnicodeDecodeError):
        return f"[Could not read file: {file_path}]"


def file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file.

    Args:
        file_path: Path to the file.

    Returns:
        Hex digest of the file hash.
    """
    hasher = hashlib.sha256()
    try:
        content = file_path.read_bytes()
        hasher.update(content)
    except OSError:
        return ""
    return hasher.hexdigest()


def matches_glob_pattern(path: str, patterns: List[str]) -> bool:
    """Check if a file path matches any of the given glob patterns.

    Args:
        path: File path to check.
        patterns: List of glob patterns.

    Returns:
        True if the path matches any pattern.
    """
    from fnmatch import fnmatch

    return any(fnmatch(path, pattern) for pattern in patterns)


def detect_language(file_path: Path) -> Optional[str]:
    """Detect programming language from file extension.

    Args:
        file_path: Path to the source file.

    Returns:
        Language name or None if not recognized.
    """
    extension_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".jsx": "JavaScript",
        ".tsx": "TypeScript",
        ".java": "Java",
        ".go": "Go",
        ".rb": "Ruby",
        ".rs": "Rust",
        ".cpp": "C++",
        ".c": "C",
        ".cs": "C#",
        ".php": "PHP",
    }
    return extension_map.get(file_path.suffix.lower())
