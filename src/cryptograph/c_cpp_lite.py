from __future__ import annotations

import re
from pathlib import Path

from cryptograph.models import GraphEdge, GraphNode, NormalizedGraph
from cryptograph.utils import as_posix_relative


_SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}

_CRYPTO_CALLS = {
    "BIO_new",
    "BIO_new_file",
    "BIO_new_socket",
    "BIO_push",
    "BIO_read",
    "BIO_write",
    "DH_free",
    "ERR_load_BIO_strings",
    "EVP_PKEY_base_id",
    "EVP_PKEY_bits",
    "EVP_PKEY_free",
    "EVP_PKEY_type",
    "HMAC",
    "MD5",
    "OpenSSL_add_all_algorithms",
    "OPENSSL_free",
    "OPENSSL_malloc",
    "OPENSSL_malloc_init",
    "PEM_read_bio_DHparams",
    "PEM_read_PrivateKey",
    "RAND_bytes",
    "RAND_pseudo_bytes",
    "RAND_seed",
    "RSA_generate_key_ex",
    "SHA1",
    "SHA256",
    "SSL_accept",
    "SSL_clear",
    "SSL_connect",
    "SSL_CTX_check_private_key",
    "SSL_CTX_free",
    "SSL_CTX_get_cert_store",
    "SSL_CTX_load_verify_locations",
    "SSL_CTX_new",
    "SSL_CTX_set_cipher_list",
    "SSL_CTX_set_ciphersuites",
    "SSL_CTX_set_client_CA_list",
    "SSL_CTX_set_default_passwd_cb",
    "SSL_CTX_set_default_passwd_cb_userdata",
    "SSL_CTX_set_default_verify_paths",
    "SSL_CTX_set_mode",
    "SSL_CTX_set_options",
    "SSL_CTX_set_session_cache_mode",
    "SSL_CTX_set_tmp_dh",
    "SSL_CTX_set_tmp_dh_callback",
    "SSL_CTX_set_tmp_ecdh",
    "SSL_CTX_set_verify",
    "SSL_CTX_use_PrivateKey",
    "SSL_CTX_use_RSAPrivateKey",
    "SSL_CTX_use_certificate",
    "SSL_ERROR_WANT_READ",
    "SSL_ERROR_WANT_WRITE",
    "SSL_free",
    "SSL_get_error",
    "SSL_get_peer_certificate",
    "SSL_get_privatekey",
    "SSL_get_verify_result",
    "SSL_library_init",
    "SSL_load_error_strings",
    "SSL_new",
    "SSL_pending",
    "SSL_read",
    "SSL_set_app_data",
    "SSL_set_bio",
    "SSL_set_shutdown",
    "SSL_set_tlsext_host_name",
    "SSL_shutdown",
    "SSL_write",
    "TLS_client_method",
    "TLS_server_method",
    "X509_CRL_verify",
    "X509_NAME_oneline",
    "X509_STORE_CTX_get_current_cert",
    "X509_STORE_CTX_get_error",
    "X509_STORE_CTX_get_error_depth",
    "X509_STORE_CTX_set_error",
    "X509_STORE_CTX_set_verify",
    "X509_STORE_free",
    "X509_STORE_load_locations",
    "X509_STORE_new",
    "X509_STORE_set_flags",
    "X509_cmp_current_time",
    "X509_free",
    "X509_get_issuer_name",
    "X509_get_pubkey",
    "X509_get_serialNumber",
    "X509_get_subject_name",
}

_CALL_RE = re.compile(r"(?<![A-Za-z0-9_:~])(?:::)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FUNCTION_RE = re.compile(
    r"^\s*(?:[A-Za-z_][\w:<>,~*&\s]+\s+)?([A-Za-z_][\w:~]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:\{|$)"
)


def build_c_cpp_lite_graph(input_path: Path) -> NormalizedGraph:
    root = input_path.resolve()
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.suffix.lower() in _SOURCE_EXTENSIONS)
    scan_root = root if root.is_dir() else root.parent
    graph = NormalizedGraph(backend="c-cpp-lite", root=root.as_posix())

    for file_path in files:
        try:
            relative_parts = file_path.relative_to(scan_root).parts
        except ValueError:
            relative_parts = file_path.parts
        if any(part.startswith(".") for part in relative_parts):
            continue
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not _contains_crypto_marker(source):
            continue
        visitor = _CppLiteVisitor(file_path, scan_root)
        visitor.visit(source)
        graph.nodes.extend(visitor.nodes)
        graph.edges.extend(visitor.edges)

    return graph


def looks_like_c_cpp(input_path: Path) -> bool:
    root = input_path.resolve()
    if root.is_file():
        return root.suffix.lower() in _SOURCE_EXTENSIONS
    if not root.is_dir():
        return False
    return any(p.suffix.lower() in _SOURCE_EXTENSIONS for p in root.rglob("*") if p.is_file())


def _contains_crypto_marker(source: str) -> bool:
    return any(api_name in source for api_name in _CRYPTO_CALLS)


class _CppLiteVisitor:
    def __init__(self, file_path: Path, root: Path) -> None:
        self.file_path = file_path
        self.root = root
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self.current_function: str | None = None
        self.current_function_id: str | None = None
        self.current_function_line: int | None = None
        self.current_function_code: str | None = None
        self.emitted_function_ids: set[str] = set()
        self.brace_depth = 0

    def visit(self, source: str) -> None:
        in_block_comment = False
        for lineno, raw_line in enumerate(source.splitlines(), start=1):
            line, in_block_comment = _strip_comments(raw_line, in_block_comment)
            stripped = line.strip()
            if not stripped:
                continue

            self._maybe_enter_function(stripped, lineno)
            self._emit_calls(line, lineno, raw_line)

            self.brace_depth += line.count("{") - line.count("}")
            if self.current_function and self.brace_depth <= 0:
                self.current_function = None
                self.current_function_id = None
                self.current_function_line = None
                self.current_function_code = None
                self.brace_depth = 0

    def _maybe_enter_function(self, stripped: str, lineno: int) -> None:
        if self.current_function or stripped.startswith(("#", "if ", "for ", "while ", "switch ", "catch ")):
            return
        match = _FUNCTION_RE.match(stripped)
        if not match:
            return
        name = match.group(1)
        if name in _CRYPTO_CALLS or name in {"if", "for", "while", "switch", "return"}:
            return
        self.current_function = name
        self.current_function_id = f"{self.file_path.as_posix()}:{lineno}:function:{name}"
        self.current_function_line = lineno
        self.current_function_code = stripped
        self.brace_depth = stripped.count("{") - stripped.count("}")

    def _emit_calls(self, line: str, lineno: int, raw_line: str) -> None:
        for match in _CALL_RE.finditer(line):
            name = match.group(1)
            if name not in _CRYPTO_CALLS:
                continue
            args = _extract_arguments(line[match.end() - 1 :])
            node_id = f"{self.file_path.as_posix()}:{lineno}:{match.start()}:call:{name}"
            self.nodes.append(
                GraphNode(
                    id=node_id,
                    kind="call",
                    name=name,
                    file=as_posix_relative(self.file_path, self.root),
                    line=lineno,
                    function=self.current_function,
                    properties={
                        "arguments": args,
                        "keywords": {},
                        "resolved_name": name,
                        "callee": name,
                        "literal_arguments": [arg for arg in args if _looks_literal(arg)],
                        "raw_code": raw_line.strip(),
                    },
                )
            )
            if self.current_function_id:
                self._emit_current_function_node()
                self.edges.append(GraphEdge(source=self.current_function_id, target=node_id, kind="AST_FUNCTION"))

    def _emit_current_function_node(self) -> None:
        if not self.current_function_id or self.current_function_id in self.emitted_function_ids:
            return
        self.nodes.append(
            GraphNode(
                id=self.current_function_id,
                kind="function",
                name=self.current_function,
                file=as_posix_relative(self.file_path, self.root),
                line=self.current_function_line,
                function=self.current_function,
                properties={"code": self.current_function_code},
            )
        )
        self.emitted_function_ids.add(self.current_function_id)


def _strip_comments(line: str, in_block_comment: bool) -> tuple[str, bool]:
    result: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            result.append(ch)
            if ch == "\\":
                if i + 1 < len(line):
                    result.append(line[i + 1])
                    i += 2
                    continue
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in {'"', "'"}:
            quote = ch
            result.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            break
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        result.append(ch)
        i += 1
    return "".join(result), in_block_comment


def _extract_arguments(call_text: str) -> list[str]:
    start = call_text.find("(")
    if start == -1:
        return []
    depth = 0
    quote: str | None = None
    escaped = False
    chars: list[str] = []
    for ch in call_text[start + 1 :]:
        if quote:
            chars.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
            chars.append(ch)
            continue
        if ch in "([{":
            depth += 1
            chars.append(ch)
            continue
        if ch in ")]}":
            if depth == 0 and ch == ")":
                break
            depth = max(0, depth - 1)
            chars.append(ch)
            continue
        chars.append(ch)
    return [part.strip() for part in _split_args("".join(chars).strip()) if part.strip()]


def _split_args(args_text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for ch in args_text:
        if quote:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
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
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    args.append("".join(current).strip())
    return args


def _looks_literal(value: str) -> bool:
    stripped = value.strip()
    return bool(re.match(r"^(['\"]).*\1$", stripped)) or bool(re.match(r"^[0-9]+[uUlL]*$", stripped))
