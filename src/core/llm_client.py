"""Ollama LLM client for local AI-powered code analysis."""

import json
from typing import Any, Dict, List, Optional

from loguru import logger

from src.config import get_settings


class OllamaClient:
    """Client for communicating with a local Ollama LLM instance.

    Handles connection, prompt sending, response parsing, and
    defensive handling of malformed or hallucinated LLM output.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize the Ollama client.

        Args:
            host: Ollama server URL. Defaults to settings.
            model: Model name. Defaults to settings.
            timeout: Request timeout in seconds. Defaults to settings.
        """
        settings = get_settings()
        self._host = host or settings.ollama_host
        self._model = model or settings.ollama_model
        self._timeout = timeout or settings.ollama_timeout
        self._max_retries = settings.ollama_max_retries
        self._context_window = settings.llm_context_window
        self._max_tokens = settings.llm_max_tokens
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazy-initialize the Ollama client."""
        if self._client is None:
            try:
                import ollama
                self._client = ollama.Client(host=self._host)
                logger.info(
                    "Ollama client initialized: {} @ {}",
                    self._model,
                    self._host,
                )
            except ImportError:
                raise ImportError(
                    "ollama package is required. "
                    "Install with: pip install ollama"
                )
        return self._client

    def is_available(self) -> bool:
        """Check if Ollama server is reachable and model is loaded.

        Returns:
            True if the server responds and the model exists.
        """
        try:
            client = self._get_client()
            models = client.list()
            model_names = [
                m.get("name", "") if isinstance(m, dict) else getattr(m, "model", "")
                for m in (models.get("models", []) if isinstance(models, dict) else getattr(models, "models", []))
            ]
            available = any(self._model in name for name in model_names)
            logger.info(
                "Ollama available: {}, model '{}' loaded: {}",
                True,
                self._model,
                available,
            )
            return available
        except Exception as e:
            logger.warning("Ollama not available: {}", e)
            return False

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Send a prompt to the LLM and return the text response.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system-level instruction.

        Returns:
            The LLM's text response.

        Raises:
            RuntimeError: If the LLM call fails after retries.
        """
        client = self._get_client()

        # Truncate prompt if it exceeds context window
        if len(prompt) > self._context_window * 4:  # rough char-to-token ratio
            logger.warning(
                "Prompt too long ({} chars), truncating to fit context window",
                len(prompt),
            )
            prompt = prompt[: self._context_window * 4]

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        last_error: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                response = client.chat(
                    model=self._model,
                    messages=messages,
                    options={
                        "num_predict": self._max_tokens,
                        "temperature": 0.1,
                    },
                )
                content = (
                    response.get("message", {}).get("content", "")
                    if isinstance(response, dict)
                    else getattr(getattr(response, "message", None), "content", "")
                )
                logger.debug(
                    "LLM response ({} chars) on attempt {}",
                    len(content),
                    attempt,
                )
                return content

            except Exception as e:
                last_error = e
                logger.warning(
                    "LLM call failed (attempt {}/{}): {}",
                    attempt,
                    self._max_retries,
                    e,
                )

        raise RuntimeError(
            f"LLM call failed after {self._max_retries} attempts: {last_error}"
        )

    def generate_json(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> Optional[Dict]:
        """Send a prompt and parse the response as JSON.

        Handles common LLM issues: markdown code fences, trailing text,
        malformed JSON. Returns None if parsing fails.

        Args:
            prompt: The user prompt.
            system_prompt: Optional system instruction.

        Returns:
            Parsed JSON dict, or None if parsing fails.
        """
        raw = self.generate(prompt, system_prompt)
        return self._parse_json_response(raw)

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string.

        Uses a rough heuristic of 1 token per 4 characters for code.

        Args:
            text: The text to estimate.

        Returns:
            Estimated token count.
        """
        return len(text) // 4

    def fits_context(self, text: str) -> bool:
        """Check if text fits within the model's context window.

        Args:
            text: Text to check.

        Returns:
            True if the text fits.
        """
        return self.estimate_tokens(text) <= self._context_window

    def truncate_to_fit(self, text: str, reserve_tokens: int = 500) -> str:
        """Truncate text to fit within the context window.

        Args:
            text: Text to potentially truncate.
            reserve_tokens: Tokens to reserve for the prompt and response.

        Returns:
            Truncated text that fits within the context window.
        """
        max_chars = (self._context_window - reserve_tokens) * 4
        if len(text) <= max_chars:
            return text

        logger.debug(
            "Truncating text from {} to {} chars",
            len(text),
            max_chars,
        )
        return text[:max_chars] + "\n\n[... truncated due to context limit]"

    @staticmethod
    def _parse_json_response(raw: str) -> Optional[Dict]:
        """Defensively parse JSON from an LLM response.

        Handles markdown code fences, extra text, and common formatting issues.

        Args:
            raw: Raw LLM response text.

        Returns:
            Parsed dict or None.
        """
        if not raw or not raw.strip():
            return None

        text = raw.strip()

        # Strip markdown code fences
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start) if "```" in text[start:] else len(text)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start) if "```" in text[start:] else len(text)
            text = text[start:end].strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in the text
        for i, char in enumerate(text):
            if char == "{":
                # Find matching closing brace
                depth = 0
                for j in range(i, len(text)):
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(text[i : j + 1])
                            except json.JSONDecodeError:
                                break
                break

        logger.warning("Failed to parse JSON from LLM response")
        return None
