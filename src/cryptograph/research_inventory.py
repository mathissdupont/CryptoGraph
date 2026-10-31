"""Nominal candidate indexing; never a verified binding or an origin label.

The selector is intentionally separate from the origin interpreter. Imports in
conditional/nested scopes may identify candidates, but require source review.
Indirect dispatch/aliases are reported separately rather than claimed covered.
"""
from __future__ import annotations

import ast
import hashlib
from collections import defaultdict

from cryptograph.key_origin import MODEL, TARGETS


def index_python_source(raw: bytes, source: str, project: str, split: str):
    tree = ast.parse(raw.decode('utf-8-sig'), filename=source)
    imports = defaultdict(set)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split('.')[0]].add(alias.name if alias.asname else alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom) and not node.level:
            for alias in node.names:
                if alias.name != '*':
                    imports[alias.asname or alias.name].add(f'{node.module}.{alias.name}')

    def names(node):
        if isinstance(node, ast.Name):
            return imports.get(node.id, set())
        if isinstance(node, ast.Attribute):
            return {f'{name}.{node.attr}' for name in names(node.value)}
        return set()

    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    callees = {id(node.func) for node in calls}
    digest = hashlib.sha256(raw).hexdigest()
    cases, indirect, ambiguous = [], [], []
    parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for call in sorted(calls, key=lambda node: (node.lineno,node.col_offset)):
        possible = sorted(names(call.func) & TARGETS)
        if len(possible) > 1:
            ambiguous.append({'line':call.lineno,'column':call.col_offset,'candidate_apis':possible,
                              'status':'ambiguous_import_identity_not_a_primary_candidate'})
            continue
        for api in possible:
            ancestry, node = [], call
            while id(node) in parents:
                node = parents[id(node)]
                if isinstance(node, (ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef,ast.Try,ast.If,ast.With)):
                    ancestry.append(type(node).__name__)
            cases.append({
                'case_id': f'{project}:{source.removeprefix(project+"/")}:{call.lineno}:{call.col_offset}',
                'project': project, 'source': source, 'source_sha256': digest,
                'split': split, 'scenario_family': project, 'target_api': api,
                'target': {'file': source.rsplit('/',1)[-1], 'line': call.lineno, 'column': call.col_offset,
                           'end_line': call.end_lineno, 'end_column': call.end_col_offset},
                'candidate_status': 'syntactic_import_candidate_not_verified_binding',
                'selector_limits': 'Imports are collected across scopes; rebinding, guards and key-role eligibility require human review. Indirect dispatch is not resolved.',
                'enclosing_constructs': ancestry,
                'independent_review': {'status':'pending','reviewer':None,'reviewed_reference':None,'notes':None},
            })
    for node in ast.walk(tree):
        if isinstance(node,(ast.Name,ast.Attribute)) and id(node) not in callees:
            for api in sorted(names(node) & TARGETS):
                indirect.append({'target_api': api,'line':node.lineno,'column':node.col_offset,
                                 'status':'noncallee_api_reference_not_a_primary_candidate'})
    return {'analysis_model': MODEL, 'cases': cases, 'indirect_references': indirect, 'ambiguous_import_calls': ambiguous}
