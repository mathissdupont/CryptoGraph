"""Opt-in Python/JEP regression controls, not independent research labels."""
import json
import os
from pathlib import Path

import pytest

from cryptograph.cpg_loader import load_graph
from cryptograph.dfg_probe import probe_key_paths
from cryptograph.key_origin import analyze_key_origins

pytestmark=pytest.mark.skipif(os.environ.get('CRYPTOGRAPH_TEST_PYTHON_CPG')!='1',reason='Requires the Python/JEP Docker runtime.')
ROOT=Path(__file__).parents[1]/'research/python-key-origin'


@pytest.fixture(scope='module')
def context():
    graph=load_graph(ROOT/'cases','fraunhofer-strict')
    assert graph.export_metadata['dfg_backward_depth']==12
    packet=json.loads((ROOT/'review-template.json').read_text())
    return graph,{entry['case_id']:entry for entry in packet['cases']}


def test_unused_random_value_has_no_exported_path_to_literal_key(context):
    graph,entries=context;entry=entries['unrelated_random']
    result=probe_key_paths(ROOT/entry['source'],entry,graph)
    assert result['status']=='observed'
    rng=[seed for seed in result['seeds'] if seed['category']=='nominal_csprng_api']
    assert rng and all(seed['status'] not in {'exported_path','same_node'} for seed in rng)
    assert any(seed['category']=='literal' and seed['status']=='exported_path' for seed in result['seeds'])


def test_salt_dependency_path_does_not_promote_a_key_origin_claim(context):
    graph,entries=context;entry=entries['kdf_random_salt'];path=ROOT/entry['source']
    result=probe_key_paths(path,entry,graph)
    assert any(seed['category']=='nominal_csprng_api' and seed['status']=='exported_path' for seed in result['seeds'])
    claim=analyze_key_origins(path,graph)[0]
    assert claim.status=='abstained' and claim.origins==[]


def test_nested_python_aes_constructor_has_an_authoritative_call_anchor(context):
    graph,entries=context;entry=entries['pyca_nested_constructor'];path=ROOT/entry['source']
    result=probe_key_paths(path,entry,graph)
    assert result['status']=='observed'
    assert next(node for node in graph.nodes if node.id==result['target_node']).kind=='call'
    assert analyze_key_origins(path,graph)[0].origins==['csprng_api']
