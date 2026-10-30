"""Validate and materialize pinned upstream source without executing it."""
from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path, PurePosixPath
from urllib.parse import quote


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
