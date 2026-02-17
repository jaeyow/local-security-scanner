"""Tree-sitter based Python AST parser for structural code analysis."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger


@dataclass
class FunctionInfo:
    """Information about a parsed function definition."""

    name: str
    line_start: int
    line_end: int
    decorators: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    has_return_type: bool = False
    body_text: str = ""


@dataclass
class ImportInfo:
    """Information about an import statement."""

    module: str
    names: List[str] = field(default_factory=list)
    line_number: int = 0
    is_from_import: bool = False


@dataclass
class ClassInfo:
    """Information about a class definition."""

    name: str
    line_start: int
    line_end: int
    base_classes: List[str] = field(default_factory=list)
    methods: List[FunctionInfo] = field(default_factory=list)


@dataclass
class FileAnalysis:
    """Complete structural analysis of a Python file."""

    file_path: str
    functions: List[FunctionInfo] = field(default_factory=list)
    classes: List[ClassInfo] = field(default_factory=list)
    imports: List[ImportInfo] = field(default_factory=list)
    total_lines: int = 0
    has_parse_errors: bool = False


class TreeSitterParser:
    """Parses Python source code using tree-sitter for AST analysis."""

    def __init__(self) -> None:
        """Initialize the tree-sitter parser with Python language."""
        self._parser: Any = None
        self._language: Any = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Lazy-initialize tree-sitter parser on first use."""
        if self._initialized:
            return

        try:
            import tree_sitter_python as tspython
            from tree_sitter import Language, Parser

            self._language = Language(tspython.language())
            self._parser = Parser(self._language)
            self._initialized = True
            logger.info("Tree-sitter Python parser initialized")
        except ImportError as e:
            raise ImportError(
                "tree-sitter and tree-sitter-python are required. "
                "Install with: pip install tree-sitter tree-sitter-python"
            ) from e

    def parse_file(self, file_path: Path) -> FileAnalysis:
        """Parse a Python file and extract structural information.

        Args:
            file_path: Path to the Python source file.

        Returns:
            FileAnalysis with functions, classes, and imports.
        """
        self._ensure_initialized()

        try:
            source = file_path.read_bytes()
        except OSError as e:
            logger.error("Cannot read file {}: {}", file_path, e)
            return FileAnalysis(file_path=str(file_path), has_parse_errors=True)

        return self._parse_source(source, str(file_path))

    def parse_text(self, source: str, source_name: str = "<string>") -> FileAnalysis:
        """Parse Python source text and extract structural information.

        Args:
            source: Python source code as string.
            source_name: Label for the source.

        Returns:
            FileAnalysis with functions, classes, and imports.
        """
        self._ensure_initialized()
        return self._parse_source(source.encode("utf-8"), source_name)

    def _parse_source(self, source: bytes, source_name: str) -> FileAnalysis:
        """Parse source bytes and extract all structural info."""
        tree = self._parser.parse(source)
        root = tree.root_node

        analysis = FileAnalysis(
            file_path=source_name,
            total_lines=source.count(b"\n") + 1,
            has_parse_errors=root.has_error if hasattr(root, "has_error") else False,
        )

        for child in root.children:
            node_type = child.type

            if node_type == "function_definition":
                func = self._extract_function(child, source)
                analysis.functions.append(func)

            elif node_type == "class_definition":
                cls = self._extract_class(child, source)
                analysis.classes.append(cls)

            elif node_type == "import_statement":
                imp = self._extract_import(child, source)
                analysis.imports.append(imp)

            elif node_type == "import_from_statement":
                imp = self._extract_from_import(child, source)
                analysis.imports.append(imp)

            elif node_type == "decorated_definition":
                # Handle decorated functions/classes
                self._extract_decorated(child, source, analysis)

        return analysis

    def _extract_function(
        self, node: Any, source: bytes
    ) -> FunctionInfo:
        """Extract function information from a function_definition node."""
        name = ""
        params: List[str] = []
        has_return = False

        for child in node.children:
            if child.type == "identifier":
                name = self._node_text(child, source)
            elif child.type == "parameters":
                params = self._extract_parameters(child, source)
            elif child.type == "type":
                has_return = True

        body_text = self._node_text(node, source)

        return FunctionInfo(
            name=name,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            parameters=params,
            has_return_type=has_return,
            body_text=body_text,
        )

    def _extract_class(self, node: Any, source: bytes) -> ClassInfo:
        """Extract class information from a class_definition node."""
        name = ""
        bases: List[str] = []
        methods: List[FunctionInfo] = []

        for child in node.children:
            if child.type == "identifier":
                name = self._node_text(child, source)
            elif child.type == "argument_list":
                bases = [
                    self._node_text(arg, source)
                    for arg in child.children
                    if arg.type == "identifier"
                ]
            elif child.type == "block":
                for block_child in child.children:
                    if block_child.type == "function_definition":
                        methods.append(
                            self._extract_function(block_child, source)
                        )
                    elif block_child.type == "decorated_definition":
                        for dec_child in block_child.children:
                            if dec_child.type == "function_definition":
                                func = self._extract_function(dec_child, source)
                                func.decorators = self._extract_decorators(
                                    block_child, source
                                )
                                methods.append(func)

        return ClassInfo(
            name=name,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            base_classes=bases,
            methods=methods,
        )

    def _extract_import(self, node: Any, source: bytes) -> ImportInfo:
        """Extract import info from an import_statement node."""
        names: List[str] = []
        for child in node.children:
            if child.type == "dotted_name":
                names.append(self._node_text(child, source))

        return ImportInfo(
            module=names[0] if names else "",
            names=names,
            line_number=node.start_point[0] + 1,
            is_from_import=False,
        )

    def _extract_from_import(self, node: Any, source: bytes) -> ImportInfo:
        """Extract import info from an import_from_statement node."""
        module = ""
        names: List[str] = []

        found_from = False
        found_import = False
        for child in node.children:
            if child.type == "from":
                found_from = True
            elif child.type == "import":
                found_import = True
            elif child.type == "dotted_name" and found_from and not found_import:
                module = self._node_text(child, source)
            elif child.type in ("dotted_name", "identifier") and found_import:
                names.append(self._node_text(child, source))
            elif child.type == "import_from_list":
                for item in child.children:
                    if item.type in ("dotted_name", "identifier"):
                        names.append(self._node_text(item, source))

        return ImportInfo(
            module=module,
            names=names,
            line_number=node.start_point[0] + 1,
            is_from_import=True,
        )

    def _extract_decorated(
        self, node: Any, source: bytes, analysis: FileAnalysis
    ) -> None:
        """Extract a decorated function or class definition."""
        decorators = self._extract_decorators(node, source)

        for child in node.children:
            if child.type == "function_definition":
                func = self._extract_function(child, source)
                func.decorators = decorators
                analysis.functions.append(func)
            elif child.type == "class_definition":
                cls = self._extract_class(child, source)
                analysis.classes.append(cls)

    def _extract_decorators(self, node: Any, source: bytes) -> List[str]:
        """Extract decorator names from a decorated_definition node."""
        decorators: List[str] = []
        for child in node.children:
            if child.type == "decorator":
                dec_text = self._node_text(child, source).lstrip("@").strip()
                decorators.append(dec_text)
        return decorators

    def _extract_parameters(self, node: Any, source: bytes) -> List[str]:
        """Extract parameter names from a parameters node."""
        params: List[str] = []
        for child in node.children:
            if child.type == "identifier":
                params.append(self._node_text(child, source))
            elif child.type in ("typed_parameter", "default_parameter"):
                for sub in child.children:
                    if sub.type == "identifier":
                        params.append(self._node_text(sub, source))
                        break
        return params

    @staticmethod
    def _node_text(node: Any, source: bytes) -> str:
        """Extract text content of a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
