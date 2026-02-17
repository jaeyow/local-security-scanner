"""ChromaDB vector store for semantic security rule matching."""

from typing import Dict, List, Optional

from loguru import logger

from src.config import get_settings
from src.models import SecurityRule


class VectorStore:
    """Embeds security rules into ChromaDB and retrieves relevant rules
    for a given code snippet using semantic similarity search.

    This enables the LLM analyzer to focus only on rules that are
    semantically relevant to the code being scanned, rather than
    brute-forcing every rule through the LLM.
    """

    COLLECTION_NAME = "security_rules"

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        embedding_model: Optional[str] = None,
    ) -> None:
        """Initialize the vector store.

        Args:
            persist_dir: Directory for ChromaDB persistence.
                Defaults to settings.vector_db_dir.
            embedding_model: Sentence-transformer model name for embeddings.
                Defaults to 'all-MiniLM-L6-v2' (fast, small, good quality).
        """
        settings = get_settings()
        self._persist_dir = persist_dir or str(settings.vector_db_dir)
        self._embedding_model = embedding_model or "all-MiniLM-L6-v2"
        self._client = None
        self._collection = None
        self._rule_map: Dict[str, SecurityRule] = {}

    def _ensure_initialized(self) -> None:
        """Lazy-initialize ChromaDB client and collection."""
        if self._client is not None:
            return

        try:
            import chromadb
        except ImportError:
            raise ImportError(
                "chromadb is required. Install with: pip install chromadb"
            )

        # ChromaDB 0.4.x uses PersistentClient for on-disk storage
        self._client = chromadb.PersistentClient(
            path=self._persist_dir,
        )
        self._collection = self._client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            "ChromaDB initialized at {} (collection: {}, {} existing docs)",
            self._persist_dir,
            self.COLLECTION_NAME,
            self._collection.count(),
        )

    def index_rules(self, rules: List[SecurityRule]) -> int:
        """Embed and store security rules in the vector database.

        Each rule is converted to a text document combining its title,
        description, category, and remediation for rich semantic matching.

        Args:
            rules: Security rules to index.

        Returns:
            Number of rules indexed.
        """
        self._ensure_initialized()

        documents: List[str] = []
        metadatas: List[Dict] = []
        ids: List[str] = []

        for rule in rules:
            doc_text = self._rule_to_document(rule)
            documents.append(doc_text)
            metadatas.append(
                {
                    "rule_id": rule.rule_id,
                    "severity": rule.severity.value,
                    "category": rule.category,
                    "owasp_category": rule.owasp_category or "",
                    "has_pattern": "true" if rule.detection.pattern else "false",
                    "has_llm_prompt": "true" if rule.detection.llm_prompt else "false",
                }
            )
            ids.append(rule.rule_id)
            self._rule_map[rule.rule_id] = rule

        if not documents:
            return 0

        # Upsert to handle re-indexing gracefully
        settings = get_settings()
        batch_size = settings.embedding_batch_size

        indexed = 0
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i : i + batch_size]
            batch_meta = metadatas[i : i + batch_size]
            batch_ids = ids[i : i + batch_size]

            self._collection.upsert(
                documents=batch_docs,
                metadatas=batch_meta,
                ids=batch_ids,
            )
            indexed += len(batch_docs)

        logger.info(
            "Indexed {} security rules into ChromaDB", indexed
        )
        return indexed

    def query_relevant_rules(
        self,
        code_snippet: str,
        n_results: int = 5,
        severity_filter: Optional[str] = None,
    ) -> List[SecurityRule]:
        """Find the most relevant security rules for a code snippet.

        Uses semantic similarity to match code against rule descriptions,
        returning the top N most relevant rules.

        Args:
            code_snippet: Source code to find relevant rules for.
            n_results: Maximum number of rules to return.
            severity_filter: Optional severity level to filter by.

        Returns:
            List of SecurityRule objects ranked by relevance.
        """
        self._ensure_initialized()

        if self._collection.count() == 0:
            logger.warning("Vector store is empty — no rules indexed")
            return []

        # Limit query text size to avoid embedding issues
        query_text = code_snippet[:2000]

        where_filter = None
        if severity_filter:
            where_filter = {"severity": severity_filter.upper()}

        try:
            results = self._collection.query(
                query_texts=[query_text],
                n_results=min(n_results, self._collection.count()),
                where=where_filter,
            )
        except Exception as e:
            logger.error("ChromaDB query failed: {}", e)
            return []

        if not results or not results.get("ids"):
            return []

        matched_rules: List[SecurityRule] = []
        rule_ids = results["ids"][0]
        distances = results.get("distances", [[]])[0]

        for idx, rule_id in enumerate(rule_ids):
            rule = self._rule_map.get(rule_id)
            if rule:
                distance = distances[idx] if idx < len(distances) else None
                logger.debug(
                    "Matched rule {} (distance: {})",
                    rule_id,
                    f"{distance:.4f}" if distance is not None else "N/A",
                )
                matched_rules.append(rule)

        logger.debug(
            "Found {} relevant rules for code snippet ({} chars)",
            len(matched_rules),
            len(code_snippet),
        )
        return matched_rules

    def get_llm_only_rules(self) -> List[SecurityRule]:
        """Return rules that have no regex pattern (LLM-only detection).

        These rules require the LLM for detection since they can't be
        matched with simple regex patterns.

        Returns:
            List of rules with llm_prompt but no regex pattern.
        """
        return [
            rule
            for rule in self._rule_map.values()
            if rule.detection.llm_prompt and not rule.detection.pattern
        ]

    def clear(self) -> None:
        """Delete all data from the vector store collection."""
        self._ensure_initialized()
        self._client.delete_collection(self.COLLECTION_NAME)
        self._collection = self._client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        self._rule_map.clear()
        logger.info("Vector store cleared")

    @property
    def rule_count(self) -> int:
        """Number of rules currently in the vector store."""
        self._ensure_initialized()
        return self._collection.count()

    @staticmethod
    def _rule_to_document(rule: SecurityRule) -> str:
        """Convert a SecurityRule into a text document for embedding.

        Combines multiple fields to create a rich representation that
        captures the rule's semantic meaning for similarity search.

        Args:
            rule: The security rule to convert.

        Returns:
            Text document suitable for embedding.
        """
        parts = [
            f"Security Rule: {rule.title}",
            f"Category: {rule.category}",
            f"Severity: {rule.severity.value}",
            f"Description: {rule.description}",
        ]

        if rule.cwe_id:
            parts.append(f"CWE: {rule.cwe_id}")

        if rule.owasp_category:
            parts.append(f"OWASP: {rule.owasp_category}")

        if rule.remediation:
            parts.append(f"Remediation: {rule.remediation}")

        if rule.detection.llm_prompt:
            parts.append(f"Detection: {rule.detection.llm_prompt}")

        if rule.examples:
            parts.append(f"Vulnerable example: {rule.examples.vulnerable[:200]}")

        return "\n".join(parts)
