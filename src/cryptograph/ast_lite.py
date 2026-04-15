from __future__ import annotations

import ast
from pathlib import Path

from cryptograph.models import GraphEdge, GraphNode, NormalizedGraph
from cryptograph.utils import as_posix_relative


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, root: Path) -> None:
        self.file_path = file_path
        self.root = root
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self.import_aliases: dict[str, str] = {}
        self.function_stack: list[str] = []
        self.function_node_ids: dict[str, str] = {}
        self.module_name = file_path.stem

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.import_aliases[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.import_aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        function_name = f"{self.module_name}.{node.name}"
        function_id = f"{self.file_path.as_posix()}:{node.lineno}:function:{node.name}"
        self.function_node_ids[function_name] = function_id
        self.nodes.append(
            GraphNode(
                id=function_id,
                kind="function",
                name=function_name,
                file=as_posix_relative(self.file_path, self.root),
                line=node.lineno,
                function=function_name,
                properties={
                    "parameters": [arg.arg for arg in node.args.args],
                    "code": self._safe_unparse(node),
                },
            )
        )
        self.function_stack.append(function_name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._call_name(node.func)
        node_id = f"{self.file_path.as_posix()}:{node.lineno}:{node.col_offset}"
        args = [self._safe_unparse(arg) for arg in node.args]
        keywords = {
            keyword.arg: self._safe_unparse(keyword.value)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        self.nodes.append(
            GraphNode(
                id=node_id,
                kind="call",
                name=call_name,
                file=as_posix_relative(self.file_path, self.root),
                line=node.lineno,
                function=self.function_stack[-1] if self.function_stack else None,
                properties={
                    "arguments": args,
                    "keywords": keywords,
                    "resolved_name": self._resolve_name(call_name),
                    "callee": self._resolve_name(call_name),
                    "literal_arguments": [
                        arg.value for arg in node.args if isinstance(arg, ast.Constant)
                    ],
                },
            )
        )
        if self.function_stack:
            function_id = self.function_node_ids.get(self.function_stack[-1])
            if function_id:
                self.edges.append(GraphEdge(source=function_id, target=node_id, kind="AST_FUNCTION"))
        self.generic_visit(node)

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return self._safe_unparse(node)

    def _resolve_name(self, call_name: str) -> str:
        first, _, rest = call_name.partition(".")
        mapped = self.import_aliases.get(first)
        if not mapped:
            return call_name
        return f"{mapped}.{rest}" if rest else mapped

    @staticmethod
    def _safe_unparse(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return node.__class__.__name__


def build_ast_lite_graph(input_path: Path) -> NormalizedGraph:
    root = input_path.resolve()
    files = [root] if root.is_file() else sorted(root.rglob("*.py"))
    graph = NormalizedGraph(backend="ast-lite", root=root.as_posix())
    scan_root = root if root.is_dir() else root.parent

    for file_path in files:
        relative_parts = file_path.relative_to(scan_root).parts
        if any(part.startswith(".") for part in relative_parts):
            continue
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=file_path.as_posix())
        visitor = _CallVisitor(file_path, scan_root)
        visitor.visit(tree)
        graph.nodes.extend(visitor.nodes)
        graph.edges.extend(visitor.edges)

    _add_synthetic_call_edges(graph)
    return graph


def _add_synthetic_call_edges(graph: NormalizedGraph) -> None:
    function_nodes = {node.name: node for node in graph.nodes if node.kind == "function" and node.name}
    function_by_short_name = {
        name.rsplit(".", 1)[-1]: node for name, node in function_nodes.items()
    }
    caller_nodes = {node.name: node for node in graph.nodes if node.kind == "function" and node.name}
    existing = {(edge.source, edge.target, edge.kind) for edge in graph.edges}

    for call in graph.nodes:
        if call.kind != "call" or not call.function:
            continue
        callee = _local_call_target(call)
        target = function_nodes.get(callee) or function_by_short_name.get(callee.rsplit(".", 1)[-1])
        caller = caller_nodes.get(call.function)
        if not caller or not target or caller.id == target.id:
            continue
        edge = (caller.id, target.id, "CALLS")
        if edge not in existing:
            graph.edges.append(GraphEdge(source=caller.id, target=target.id, kind="CALLS"))
            existing.add(edge)


def _local_call_target(call: GraphNode) -> str:
    resolved = str(call.properties.get("resolved_name") or call.name or "")
    if "." in resolved:
        return resolved
    module = call.function.rsplit(".", 1)[0] if call.function else ""
    return f"{module}.{resolved}" if module else resolved
