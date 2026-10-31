"""Synthetic failure controls, never real-project labels or review approvals."""
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from cryptograph.cpg_loader import CpgLoadError
from cryptograph.research_corpus import validate_candidate_inventory
from cryptograph.research_inventory import index_python_source

ROOT=Path(__file__).parents[1]


@pytest.fixture
def study(tmp_path):
    source=b'from Crypto.Cipher import AES\ndef build():\n    return AES.new(b"0123456789abcdef",1)\n'
    cache=tmp_path/'sources';(cache/'example').mkdir(parents=True)
    (cache/'example/module.py').write_bytes(source)
    manifest={'projects':[{'id':'example','repository':'https://github.com/example/project','revision':'a'*40,'split':'development',
        'resources':[{'path':'module.py','kind':'source','sha256':hashlib.sha256(source).hexdigest(),'bytes':len(source),
                      'url':'https://raw.githubusercontent.com/example/project/'+('a'*40)+'/module.py'}]}]}
    packet=index_python_source(source,'example/module.py','example','development')
    definition=tmp_path/'manifest.json';annotations=tmp_path/'annotations.json'
    definition.write_text(json.dumps(manifest),encoding='utf-8');annotations.write_text(json.dumps(packet),encoding='utf-8')
    spec=importlib.util.spec_from_file_location('study_runner_test',ROOT/'scripts/run-project-key-origin.py')
    runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
    output=tmp_path/'results'
    argv=['study','--manifest',str(definition),'--annotations',str(annotations),'--source-root',str(cache),
          '--backend','fraunhofer-strict','--out-dir',str(output)]
    return runner,argv,cache,output,manifest,packet


def test_graph_failure_preserves_independent_source_results(study,monkeypatch):
    runner,argv,_,output,_,_=study
    monkeypatch.setattr(sys,'argv',argv)
    def unavailable(*args,**kwargs):
        raise CpgLoadError('Synthetic unavailable CPG')
    monkeypatch.setattr(runner,'load_graph',unavailable)
    assert runner.main()==2
    for condition in ('source_only','direct_expression'):
        row=json.loads((output/'conditions'/condition/'observations.json').read_text())['cases'][0]
        assert row['scan_status']=='completed'
        assert row['evidence_policy'][0]['claim']['origins']==['literal']
    graph_row=json.loads((output/'conditions/graph_context/observations.json').read_text())['cases'][0]
    assert graph_row['scan_status']=='failed' and graph_row['evidence_policy']==[]
    assert json.loads((output/'conditions/graph_context/graph-index.json').read_text())['graphs']=={}


def test_probe_failure_does_not_destroy_origin_claims(study,monkeypatch):
    runner,argv,_,output,_,_=study
    argv[argv.index('fraunhofer-strict')]='ast-lite';argv.append('--dfg-probe')
    monkeypatch.setattr(sys,'argv',argv)
    def unavailable(*args,**kwargs):
        raise ValueError('Synthetic failed path probe')
    monkeypatch.setattr(runner,'probe_key_paths',unavailable)
    assert runner.main()==2
    row=json.loads((output/'example/sites.json').read_text())['cases'][0]
    assert all(result['outcome']=='resolved' for result in row['conditions'].values())
    record=json.loads((output/'run.json').read_text())
    assert record['projects']['example']['probe_error']=='Synthetic failed path probe'
    assert record['external_inputs_sha256']  # Annotation files outside the checkout are supported.


@pytest.mark.parametrize('mutation',['traversal','wrong_project','wrong_hash','wrong_api','wrong_span','duplicate','wrong_split'])
def test_invalid_candidate_inventory_is_rejected_before_graph_analysis(study,mutation):
    _,_,cache,_,manifest,original=study
    packet=copy.deepcopy(original);entry=packet['cases'][0]
    if mutation=='traversal':entry['source']='../outside.py'
    elif mutation=='wrong_project':entry['project']='unacquired'
    elif mutation=='wrong_hash':entry['source_sha256']='0'*64
    elif mutation=='wrong_api':entry['target_api']='lookalike.AES'
    elif mutation=='wrong_span':entry['target']['line']=999
    elif mutation=='duplicate':packet['cases'].append(copy.deepcopy(entry))
    elif mutation=='wrong_split':entry['split']='evaluation_reserved'
    with pytest.raises(ValueError):
        validate_candidate_inventory(manifest,packet,cache)


def test_inventory_checks_identity_without_promoting_nominal_binding(study):
    _,_,cache,_,manifest,packet=study
    result=validate_candidate_inventory(manifest,packet,cache)
    assert result=={'candidate_sites':1,'binding_verification':'not_performed'}
    assert packet['cases'][0]['independent_review']['status']=='pending'
