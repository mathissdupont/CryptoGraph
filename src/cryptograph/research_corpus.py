"""Validate and materialize pinned upstream source without executing it."""
from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from cryptograph.key_origin import Span, TARGETS


def corpus_resources(manifest: dict):
    projects = set()
    for project in manifest['projects']:
        ident, repository, revision = project['id'], project['repository'], project['revision']
        if not re.fullmatch(r'[a-z][a-z0-9_]*', ident) or ident in projects:
            raise ValueError('Invalid or duplicate project identifier')
        projects.add(ident)
        if not re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('Sources must identify a GitHub repository and full pinned commit')
        paths = set()
        for resource in project['resources']:
            path = PurePosixPath(resource['path'])
            if path.is_absolute() or '..' in path.parts or '\\' in resource['path'] or ':' in resource['path'] or path.as_posix() in paths:
                raise ValueError('Invalid or duplicate resource path')
            paths.add(path.as_posix())
            expected = f"https://raw.githubusercontent.com/{repository.removeprefix('https://github.com/')}/{revision}/{quote(path.as_posix(), safe='/')}"
            if resource['url'] != expected or not re.fullmatch(r'[0-9a-f]{64}', resource['sha256']):
                raise ValueError('Resource URL or source fingerprint is not pinned')
            if resource['kind'] not in {'source', 'license'}:
                raise ValueError('Unknown resource kind')
            yield project, resource, Path(ident, *path.parts)


def materialize_corpus(manifest: dict, root: Path, fetch=None) -> dict:
    resources = list(corpus_resources(manifest))  # validate all paths before writes/network
    root = root.resolve()
    records = []
    for project, resource, relative in resources:
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            raise ValueError('Resource escaped corpus root')
        if path.exists():
            raw = path.read_bytes()
            origin = 'verified_cache'
        elif fetch is not None:
            raw = fetch(resource['url'])
            origin = 'downloaded'
        else:
            raise ValueError(f'Missing pinned resource: {relative}; opt in to --fetch to download')
        if hashlib.sha256(raw).hexdigest() != resource['sha256'] or len(raw) != resource['bytes']:
            raise ValueError(f'Pinned resource content mismatch: {relative}')
        if resource['kind'] == 'source':
            ast.parse(raw.decode('utf-8-sig'), filename=str(relative))
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        records.append({'project': project['id'], 'path': relative.as_posix(), 'sha256': resource['sha256'], 'origin': origin})
    return {'status': 'verified', 'target_execution': False, 'resources': records}


def validate_candidate_inventory(manifest: dict, packet: dict, root: Path | None = None):
    """Validate source/site identities, never claim that nominal APIs are true.

    Human candidate rejection stays possible. This checks that every proposed
    site is one call in the acquired, fingerprinted population before graph or
    origin analysis, including when annotation JSON comes from another directory.
    """
    resources = {relative.as_posix(): resource for _, resource, relative in corpus_resources(manifest)
                 if resource['kind'] == 'source'}
    projects = {project['id']: project for project in manifest['projects']}
    ids, sites, positions = set(), set(), {}
    for entry in packet['cases']:
        source = entry['source']
        if source not in resources or entry['project'] not in projects or not source.startswith(entry['project']+'/'):
            raise ValueError('Candidate source/project is outside the pinned source population')
        if entry['source_sha256'] != resources[source]['sha256']:
            raise ValueError('Candidate and manifest source fingerprints differ')
        span = Span.model_validate(entry['target'])
        if span.file != PurePosixPath(source).name or entry['target_api'] not in TARGETS:
            raise ValueError('Candidate file/API identity is outside the declared contract')
        site = (source,span.line,span.column,span.end_line,span.end_column)
        if entry['case_id'] in ids or site in sites:
            raise ValueError('Duplicate candidate identity or source operation')
        ids.add(entry['case_id']);sites.add(site)
        if entry['split'] != projects[entry['project']].get('split','development'):
            raise ValueError('Candidate and project split differ')
        if root is not None:
            path = (root/source).resolve()
            if not path.is_relative_to(root.resolve()):
                raise ValueError('Candidate source escaped the acquisition root')
            if source not in positions:
                raw = path.read_bytes()
                if hashlib.sha256(raw).hexdigest() != entry['source_sha256']:
                    raise ValueError('Candidate source bytes changed since acquisition')
                tree = ast.parse(raw.decode('utf-8-sig'))
                positions[source] = {(node.lineno,node.col_offset,node.end_lineno,node.end_col_offset)
                                     for node in ast.walk(tree) if isinstance(node,ast.Call)}
            if site[1:] not in positions[source]:
                raise ValueError('Candidate span is not an acquired source call')
    return {'candidate_sites': len(ids), 'binding_verification': 'not_performed'}
