"""Bounded DFG path observations, separate from ultimate key-origin claims.

A path from a nominal syntactic seed is not proof that its bytes are the key:
unresolved-call inference, path feasibility and transformations remain unchecked.
"""
from __future__ import annotations

import ast
import hashlib
from collections import deque
from functools import lru_cache
from pathlib import Path

from cryptograph.models import NormalizedGraph


def directed_path(graph: NormalizedGraph, source: str, target: str, max_hops=16):
    """Return one forward DFG witness, or an explicitly bounded non-result."""
    nodes = {node.id for node in graph.nodes}
    if source not in nodes or target not in nodes:
        raise ValueError('Path endpoints must belong to the exported graph')
    outgoing = {}
    for edge in graph.edges:
        if edge.kind == 'DFG' and edge.source in nodes and edge.target in nodes:
            outgoing.setdefault(edge.source, []).append(edge)
    queue, seen = deque([(source, [])]), {source}
    limited = False
    while queue:
        current, path = queue.popleft()
        if current == target:
            return {'status': 'same_node' if not path else 'exported_path', 'edges': [edge.model_dump() for edge in path]}
        if len(path) >= max_hops:
            limited |= any(edge.target not in seen for edge in outgoing.get(current, []))
            continue
        for edge in sorted(outgoing.get(current, []), key=lambda edge: edge.target):
            if edge.target not in seen:
                seen.add(edge.target)
                queue.append((edge.target, path + [edge]))
    return {'status': 'search_limit' if limited else 'inconclusive_truncated_export' if graph.export_metadata.get('dfg_truncated') else 'no_exported_path', 'edges': []}


def probe_key_paths(path: Path, entry: dict, graph: NormalizedGraph, max_hops=16):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry['source_sha256']:
        raise ValueError('DFG probe source snapshot mismatch')
    result = {'kind': 'bounded_exported_dfg_paths_not_origin_inference', 'case_id': entry['case_id'],
              'export_metadata': graph.export_metadata, 'max_hops': max_hops,
              'scope': 'Syntactic seeds and exported value-dependency paths only; no feasible-path, complete-origin or security claim.'}
    if graph.backend != 'fraunhofer-cpg':
        return dict(result, status='unsupported_backend', seeds=[])
    source = raw.decode('utf-8-sig')
    tree = ast.parse(source)
    target = entry['target']
    call = next((node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset) ==
                 (target['line'], target['column'], target['end_line'], target['end_column'])), None)
    if call is None:
        raise ValueError('DFG target is not a source call')
    root = Path(graph.root)
    root = root.parent if root.is_file() else root
    source_path = path.resolve()

    @lru_cache(maxsize=None)
    def same_file_name(filename):
        candidate = Path(filename)
        return bool(filename) and (candidate if candidate.is_absolute() else root / candidate).resolve() == source_path

    def same_file(node):
        return same_file_name(node.file)

    def code(node):
        return node.properties.get('raw_code') or node.properties.get('code')

    @lru_cache(maxsize=None)
    def compact(text):
        # Token structure, including literal contents, remains significant.
        try:
            return ast.dump(ast.parse(text, mode='eval'), include_attributes=False)
        except (ValueError, SyntaxError, TypeError):
            return text.strip() if isinstance(text, str) else None

    def anchors(node, only_calls=False):
        text = compact(ast.get_source_segment(source, node))
        return [item for item in graph.nodes if same_file(item) and item.line == node.lineno
                and (not only_calls or item.kind == 'call') and compact(code(item)) == text]

    targets = anchors(call, only_calls=True)
    if len(targets) != 1:
        return dict(result, status='missing_target_anchor' if not targets else 'ambiguous_target_anchor', seeds=[])
    key = call.args[0] if call.args else next((kw.value for kw in call.keywords if kw.arg == 'key'), None)
    if key is None or any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
        return dict(result, status='dynamic_key_binding', seeds=[])
    argument_edges = [edge for edge in graph.edges if edge.source == targets[0].id and edge.kind.startswith('AST_ARGUMENT_')]
    by_id = {node.id: node for node in graph.nodes}
    key_nodes = [by_id[edge.target] for edge in argument_edges if edge.target in by_id and same_file(by_id[edge.target])
                 and by_id[edge.target].line == key.lineno and compact(code(by_id[edge.target])) == compact(ast.get_source_segment(source, key))]
    if len(key_nodes) != 1:
        return dict(result, status='missing_key_anchor' if not key_nodes else 'ambiguous_key_anchor', seeds=[])
    aliases = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            aliases.update({a.asname or a.name.split('.')[0]: a.name if a.asname else a.name.split('.')[0] for a in node.names})
        elif isinstance(node, ast.ImportFrom) and not node.level:
            aliases.update({a.asname or a.name: f'{node.module}.{a.name}' for a in node.names if a.name != '*'})
    masked = {node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)}
    masked |= {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))}

    def nominal(node):
        if isinstance(node, ast.Name) and node.id not in masked:
            return aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = nominal(node.value)
            return f'{base}.{node.attr}' if base else None
        return None

    docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                  if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body
                  and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)
                  and isinstance(node.body[0].value.value, str)}
    seeds = []
    for node in ast.walk(tree):
        category = ('literal' if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)) and id(node) not in docstrings
                    else 'nominal_csprng_api' if isinstance(node, ast.Call) and nominal(node.func) in {'os.urandom', 'secrets.token_bytes'} else None)
        if category is None:
            continue
        matches = anchors(node, only_calls=category == 'nominal_csprng_api')
        observation = {'category': category, 'line': node.lineno, 'column': node.col_offset,
                       'status': 'missing_seed_anchor' if not matches else 'ambiguous_seed_anchor'}
        if len(matches) == 1:
            observation.update(directed_path(graph, matches[0].id, key_nodes[0].id, max_hops), source_node=matches[0].id)
        seeds.append(observation)
    return dict(result, status='observed', target_node=targets[0].id, key_argument_node=key_nodes[0].id, seeds=seeds)
