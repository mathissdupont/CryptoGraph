"""Restricted direct-expression comparator over a frozen candidate population.

No assignment propagation, helper expansion or graph traversal is performed.
Import identity is nominal and flow-insensitive; this is a transparent reference
condition, not an independently validated external detector.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from cryptograph.key_origin import EvidenceStep, KeyOriginClaim, RANDOM_APIS, Span, TARGETS


def direct_expression_claim(path: Path, entry: dict) -> KeyOriginClaim | None:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != entry["source_sha256"]:
        raise ValueError("Baseline source snapshot mismatch")
    tree = ast.parse(raw.decode("utf-8-sig"))
    target = Span.model_validate(entry["target"])

    def span(node):
        return Span(file=path.name, line=node.lineno, column=node.col_offset,
                    end_line=node.end_lineno, end_column=node.end_col_offset)

    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and span(node) == target]
    if len(calls) != 1:
        raise ValueError("Baseline target is not a unique source call")
    call = calls[0]
    imports = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split('.')[0]] = (alias.name if alias.asname else alias.name.split('.')[0], node)
        elif isinstance(node, ast.ImportFrom) and not node.level:
            for alias in node.names:
                if alias.name != '*':
                    imports[alias.asname or alias.name] = (f"{node.module}.{alias.name}", node)
    owners = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.lineno <= call.lineno <= node.end_lineno]
    function = min(owners, key=lambda node: node.end_lineno - node.lineno) if owners else None
    local_names, parameters = set(), set()
    if function:
        parameters = {arg.arg for arg in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]}
        if function.args.vararg:
            parameters.add(function.args.vararg.arg)
        if function.args.kwarg:
            parameters.add(function.args.kwarg.arg)
        local_names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))}
        local_names |= parameters
        for node in ast.walk(function):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                local_names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
    # Mask any module assignment/function/class binding of an imported root.
    masked = {node.id for statement in tree.body if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
              for node in ast.walk(statement) if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))}
    masked.update(node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    for owner in owners:
        if owner is not function:
            masked.update(arg.arg for arg in [*owner.args.posonlyargs, *owner.args.args, *owner.args.kwonlyargs])
            masked.update(node.id for node in ast.walk(owner) if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)))

    def nominal(node):
        if isinstance(node, ast.Name) and node.id not in local_names | masked:
            return imports.get(node.id, (None, None))
        if isinstance(node, ast.Attribute):
            base, binding = nominal(node.value)
            return (f"{base}.{node.attr}", binding) if base else (None, None)
        return None, None

    api, target_binding = nominal(call.func)
    if api not in TARGETS or api != entry["target_api"]:
        return None  # failed target binding is missing detection, not abstention
    key = call.args[0] if call.args else next((kw.value for kw in call.keywords if kw.arg == 'key'), call)
    dynamic = any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords)
    duplicate = bool(call.args) and any(kw.arg == 'key' for kw in call.keywords)
    boundary = 'literal' if isinstance(key, ast.Constant) else 'return_value' if isinstance(key, ast.Call) else 'parameter' if isinstance(key, ast.Name) and key.id in parameters else 'local_assignment' if isinstance(key, ast.Name) and key.id in local_names else 'expression'
    origins, reason, source_binding = [], 'not_a_direct_supported_source_expression', None
    mutation = any(isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) for node in ast.walk(tree))
    if dynamic or duplicate:
        reason, boundary = 'dynamic_or_duplicate_key_binding', 'expression'
    elif mutation:
        reason = 'explicit_attribute_mutation'
    elif isinstance(key, ast.Constant) and isinstance(key.value, (bytes, str)):
        origins = ['literal']
    elif isinstance(key, ast.Call):
        source_api, source_binding = nominal(key.func)
        if source_api in RANDOM_APIS:
            origins = ['csprng_api']
    evidence = []

    def step(node, kind, detail, parents=()):
        identifier = 'direct-' + hashlib.sha256(f'{digest}:{node.lineno}:{node.col_offset}:{kind}:{detail}:{parents}'.encode()).hexdigest()[:20]
        evidence.append(EvidenceStep(id=identifier, kind=kind, span=span(node), detail=detail, parents=list(parents)))
        return identifier

    target_id = step(target_binding, 'import_binding', api)
    parents = []
    if origins and source_binding:
        parents.append(step(source_binding, 'import_binding', 'nominal source API import'))
    source_id = step(key, 'literal' if origins == ['literal'] else 'api_contract' if origins else 'unresolved',
                     origins[0] if origins else reason, parents)
    key_id = step(call, 'key_argument', api, [target_id, source_id])
    step(call, 'origin_claim', 'direct-expression reference', [key_id])
    return KeyOriginClaim(operation_id='key-' + hashlib.sha256(f'{path.name}:{digest}:{call.lineno}:{call.col_offset}'.encode()).hexdigest()[:20],
        target_api=api, target=target, source_sha256=digest, context_backend='direct-expression',
        immediate_boundary=boundary, status='resolved' if origins else 'abstained', origins=origins,
        origin_set_complete=bool(origins), modality='must' if origins else 'unknown',
        unresolved_reasons=[] if origins else [reason],
        assumptions=['Nominal imports identify intended libraries and APIs retain their documented contracts at the site.',
                     'No assignment propagation, effect analysis, helper expansion or graph recovery is performed.',
                     'Target execution and valid inputs are assumed; this comparator does not establish key security.'],
        evidence=evidence)
