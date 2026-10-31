"""Direct-expression comparison and acquisition integrity, not research labels."""
import ast
import hashlib
import json
from pathlib import Path

import pytest

from cryptograph.key_origin import TARGETS, audit_claim_structure
from cryptograph.research_baselines import direct_expression_claim
from cryptograph.research_corpus import materialize_corpus
from cryptograph.cpg_loader import load_graph
from cryptograph.cpg_visualizer import write_graph_json
from cryptograph.utils import load_json


def baseline(tmp_path, source):
    path = tmp_path / 'example.py'
    path.write_bytes(source.encode())
    call = next(node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and ast.unparse(node.func) == 'AES.new')
    entry = dict(source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), target_api='Crypto.Cipher.AES.new',
                 target=dict(file=path.name, line=call.lineno, column=call.col_offset, end_line=call.end_lineno, end_column=call.end_col_offset))
    claim = direct_expression_claim(path, entry)
    if claim:
        assert audit_claim_structure(claim, path) == []
    return claim


@pytest.mark.parametrize('body,origins', [
    ('def f():\n    return AES.new(b"fixed", 1)\n', ['literal']),
    ('def f():\n    return AES.new(os.urandom(16), 1)\n', ['csprng_api']),
    ('def f():\n    key = os.urandom(16)\n    return AES.new(key, 1)\n', []),
    ('def f(os):\n    return AES.new(os.urandom(16), 1)\n', []),
    ('def outer(os):\n    def inner():\n        return AES.new(os.urandom(16), 1)\n', []),
    ('def f(options):\n    return AES.new(**options)\n', []),
])
def test_direct_comparator_does_not_propagate_assignments_or_shadowed_sources(tmp_path, body, origins):
    claim = baseline(tmp_path, 'import os\nfrom Crypto.Cipher import AES\n' + body)
    assert claim.origins == origins and claim.graph_features_used == []


def test_direct_comparator_does_not_treat_shadowed_constructor_as_abstention(tmp_path):
    assert baseline(tmp_path, 'from Crypto.Cipher import AES\ndef f(AES):\n    return AES.new(b"fixed", 1)\n') is None


def test_graph_artifact_preserves_non_utf8_binary_literals(tmp_path):
    path = tmp_path / 'binary.py'
    path.write_text('from Crypto.Cipher import AES\nAES.new(b"\\xff\\x00", 1)\n')
    graph = load_graph(path, 'ast-lite')
    output = tmp_path / 'graph.json'
    write_graph_json(graph, output)
    raw = load_json(output)
    literals = [item['properties'].get('literal_arguments', []) for item in raw['nodes']]
    assert any({'python_literal_type': 'bytes', 'hex': 'ff00'} in values for values in literals)


def manifest(raw=b'import os\n'):
    revision = 'a' * 40
    return {'projects': [{'id': 'example', 'repository': 'https://github.com/example/source', 'revision': revision,
                         'resources': [{'path': 'module.py', 'kind': 'source', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                        'url': f'https://raw.githubusercontent.com/example/source/{revision}/module.py'}]}]}


def test_acquisition_does_not_execute_source_and_verifies_cache(tmp_path):
    raw = b'raise RuntimeError("never execute target")\n'
    called = []
    result = materialize_corpus(manifest(raw), tmp_path, lambda url: called.append(url) or raw)
    assert result['status'] == 'verified' and len(called) == 1
    result = materialize_corpus(manifest(raw), tmp_path)
    assert result['resources'][0]['origin'] == 'verified_cache'
    (tmp_path / 'example/module.py').write_bytes(b'# modified\n')
    with pytest.raises(ValueError, match='content mismatch'):
        materialize_corpus(manifest(raw), tmp_path, lambda url: raw)


@pytest.mark.parametrize('change', ['traversal', 'moving_ref', 'wrong_host', 'wrong_hash', 'missing'])
def test_acquisition_rejects_unpinned_or_invalid_inputs(tmp_path, change):
    data = manifest()
    entry = data['projects'][0]['resources'][0]
    if change == 'traversal':
        entry['path'] = '../outside.py'
    elif change == 'moving_ref':
        data['projects'][0]['revision'] = 'main'
    elif change == 'wrong_host':
        entry['url'] = 'https://example.com/module.py'
    elif change == 'wrong_hash':
        entry['sha256'] = '0' * 64
    with pytest.raises(ValueError):
        materialize_corpus(data, tmp_path, None if change == 'missing' else lambda url: b'import os\n')


def test_development_and_reserved_project_inventories_are_disjoint_and_unreviewed():
    root=Path(__file__).parents[1]/'research/python-key-origin'
    development=json.loads((root/'project-corpus.json').read_text())
    reserved=json.loads((root/'reserved-corpus.json').read_text())
    dev_ids={project['id'] for project in development['projects']}
    reserved_ids={project['id'] for project in reserved['projects']}
    assert len(dev_ids)==4 and len(reserved_ids)==2 and dev_ids.isdisjoint(reserved_ids)
    for filename,manifest in [('project-review-template.json',development),('reserved-review-template.json',reserved)]:
        packet=json.loads((root/filename).read_text())
        resources={(project['id']+'/'+resource['path']):resource['sha256'] for project in manifest['projects'] for resource in project['resources'] if resource['kind']=='source'}
        assert len({case['case_id'] for case in packet['cases']})==len(packet['cases'])
        for case in packet['cases']:
            assert case['target_api'] in TARGETS
            assert resources[case['source']]==case['source_sha256']
            assert case['independent_review']['status']=='pending' and case['independent_review']['reviewed_reference'] is None
