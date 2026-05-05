from __future__ import annotations

import re
from pathlib import Path

from cryptograph.models import GraphEdge, GraphNode, NormalizedGraph
from cryptograph.utils import as_posix_relative


_CALL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bOpenSSL::Cipher\.new\s*\("), "OpenSSL::Cipher.new"),
    (re.compile(r"\bOpenSSL::Digest\.new\s*\("), "OpenSSL::Digest.new"),
    (re.compile(r"\bDigest::MD5\.(?:hexdigest|digest)\s*\("), "Digest::MD5.hexdigest"),
    (re.compile(r"\bDigest::SHA1\.(?:hexdigest|digest)\s*\("), "Digest::SHA1.hexdigest"),
    (re.compile(r"\bDigest::SHA256\.(?:hexdigest|digest)\s*\("), "Digest::SHA256.hexdigest"),
    (re.compile(r"\bDigest::SHA512\.(?:hexdigest|digest)\s*\("), "Digest::SHA512.hexdigest"),
    (re.compile(r"\bOpenSSL::HMAC\.(?:digest|hexdigest)\s*\("), "OpenSSL::HMAC.digest"),
    (re.compile(r"\bOpenSSL::KDF\.pbkdf2_hmac\s*\("), "OpenSSL::KDF.pbkdf2_hmac"),
    (re.compile(r"\bOpenSSL::PKey::RSA\.generate\s*\("), "OpenSSL::PKey::RSA.generate"),
    (re.compile(r"\bOpenSSL::PKey::EC\.generate\s*\("), "OpenSSL::PKey::EC.generate"),
    (re.compile(r"\bSecureRandom\.(?:bytes|random_bytes|hex|uuid)\s*\("), "SecureRandom.bytes"),
    (re.compile(r"(?<![A-Za-z0-9_:])rand\s*\("), "Random.rand"),
    (re.compile(r"\bRandom\.rand\s*\("), "Random.rand"),
    (re.compile(r"\bOpenSSL::SSL::SSLContext\.new\s*\("), "OpenSSL::SSL::SSLContext.new"),
    (re.compile(r"\bBCrypt::Password\.create\s*\("), "BCrypt::Password.create"),
]

_CRYPTO_MARKERS = (
    "OpenSSL::",
    "Digest::",
    "SecureRandom",
    "Random.rand",
    "rand(",
    "BCrypt::",
)


def build_ruby_lite_graph(input_path: Path) -> NormalizedGraph:
    root = input_path.resolve()
    files = [root] if root.is_file() else sorted(root.rglob("*.rb"))
    graph = NormalizedGraph(backend="ruby-lite", root=root.as_posix())
    scan_root = root if root.is_dir() else root.parent

    for file_path in files:
        relative_parts = file_path.relative_to(scan_root).parts
        if any(part.startswith(".") for part in relative_parts):
            continue
        source = file_path.read_text(encoding="utf-8")
        if not _contains_crypto_marker(source):
            continue
        visitor = _RubyLiteVisitor(file_path, scan_root)
        visitor.visit(source)
        graph.nodes.extend(visitor.nodes)
        graph.edges.extend(visitor.edges)

    return graph


def _contains_crypto_marker(source: str) -> bool:
    return any(marker in source for marker in _CRYPTO_MARKERS)


class _RubyLiteVisitor:
    def __init__(self, file_path: Path, root: Path) -> None:
        self.file_path = file_path
        self.root = root
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self.function_stack: list[str] = []
        self.module_name = file_path.stem
        self._function_nodes: dict[str, str] = {}

    def visit(self, source: str) -> None:
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            self._maybe_enter_function(stripped, lineno, line)
            self._emit_calls(stripped, lineno, line)
            if stripped == "end" and self.function_stack:
                self.function_stack.pop()

    def _maybe_enter_function(self, stripped: str, lineno: int, raw_line: str) -> None:
        match = re.match(r"^def\s+([A-Za-z_][A-Za-z0-9_!?=]*)", stripped)
        if not match:
            return
        function_name = f"{self.module_name}.{match.group(1)}"
        function_id = f"{self.file_path.as_posix()}:{lineno}:function:{match.group(1)}"
        self._function_nodes[function_name] = function_id
        self.nodes.append(
            GraphNode(
                id=function_id,
                kind="function",
                name=function_name,
                file=as_posix_relative(self.file_path, self.root),
                line=lineno,
                function=function_name,
                properties={"code": raw_line.strip()},
            )
        )
        self.function_stack.append(function_name)

    def _emit_calls(self, stripped: str, lineno: int, raw_line: str) -> None:
        if not _contains_crypto_marker(stripped):
            return
        for pattern, api_name in _CALL_PATTERNS:
            for match in pattern.finditer(stripped):
                args = _extract_arguments(stripped[match.end() - 1 :])
                node_id = f"{self.file_path.as_posix()}:{lineno}:{match.start()}"
                current_function = self.function_stack[-1] if self.function_stack else None
                function_id = self._function_nodes.get(current_function or "")
                self.nodes.append(
                    GraphNode(
                        id=node_id,
                        kind="call",
                        name=api_name,
                        file=as_posix_relative(self.file_path, self.root),
                        line=lineno,
                        function=current_function,
                        properties={
                            "arguments": args,
                            "keywords": {},
                            "resolved_name": api_name,
                            "callee": api_name,
                            "literal_arguments": [arg for arg in args if _looks_literal(arg)],
                            "raw_code": raw_line.strip(),
                        },
                    )
                )
                if function_id:
                    self.edges.append(GraphEdge(source=function_id, target=node_id, kind="AST_FUNCTION"))


def _extract_arguments(call_text: str) -> list[str]:
    start = call_text.find("(")
    if start == -1:
        return []
    depth = 0
    args_chars: list[str] = []
    for ch in call_text[start + 1 :]:
        if ch == "(":
            depth += 1
            args_chars.append(ch)
            continue
        if ch == ")" and depth == 0:
            break
        if ch == ")":
            depth -= 1
            args_chars.append(ch)
            continue
        args_chars.append(ch)
    args_text = "".join(args_chars).strip()
    if not args_text:
        return []
    return [part.strip() for part in _split_args(args_text)]


def _split_args(args_text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    for ch in args_text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
            current.append(ch)
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            piece = "".join(current).strip()
            if piece:
                args.append(piece)
            current = []
            continue
        current.append(ch)
    piece = "".join(current).strip()
    if piece:
        args.append(piece)
    return args


def _looks_literal(value: str) -> bool:
    return bool(re.match(r"^(['\"]).*\1$", value)) or value.isdigit()
