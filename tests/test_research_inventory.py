"""Candidate population integrity, not independently reviewed research labels."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptograph.research_inventory import index_python_source


def index(source):
    raw=source.encode()
    return raw,index_python_source(raw,'example/pkg/mod.py','example','development')


def test_index_retains_guarded_class_calls_without_claiming_a_verified_binding():
    raw,result=index('try:\n    from Crypto.Cipher import AES\nexcept ImportError:\n    pass\nclass C:\n    def f(self,key):\n        return AES.new(key,1)\n')
    case,=result['cases']
    assert case['source_sha256']==hashlib.sha256(raw).hexdigest()
    assert case['independent_review']['status']=='pending'
    assert 'ClassDef' in case['enclosing_constructs']
    assert 'not_verified_binding' in case['candidate_status']


def test_indirect_dispatch_is_visible_without_inflating_primary_calls():
    _,result=index('from cryptography.hazmat.primitives.ciphers import algorithms\nfactory=algorithms.AES\nvalue=factory(b"key")\n')
    assert not result['cases']
    assert len(result['indirect_references'])==1


def test_conflicting_library_imports_do_not_duplicate_one_source_operation():
    _,result=index('from Crypto.Cipher import AES\nfrom cryptography.hazmat.primitives.ciphers.algorithms import AES\nvalue=AES(b"key")\n')
    assert len(result['cases'])==1
    _,result=index('import Crypto.Cipher as c\nimport Cryptodome.Cipher as c\nvalue=c.AES.new(b"key",1)\n')
    assert not result['cases']
    assert len(result['ambiguous_import_calls'])==1


def test_index_never_executes_source(tmp_path):
    sentinel=tmp_path/'executed'
    _,result=index(f'open({str(sentinel)!r},"w").write("bad")\nfrom Crypto.Cipher import AES\nx=AES.new(b"key",1)\n')
    assert len(result['cases'])==1 and not sentinel.exists()


def test_development_runner_refuses_reserved_origins_before_source_acquisition(tmp_path):
    root=Path(__file__).parents[1]
    output=tmp_path/'forbidden-run'
    result=subprocess.run([sys.executable,str(root/'scripts/run-project-key-origin.py'),
        '--manifest',str(root/'research/python-key-origin/expanded-2026-10-30/evaluation_reserved-corpus.json'),
        '--annotations',str(root/'research/python-key-origin/expanded-2026-10-30/evaluation_reserved-review-template.json'),
        '--source-root',str(tmp_path/'absent'),'--backend','ast-lite','--out-dir',str(output)],capture_output=True,text=True)
    assert result.returncode==2 and 'refuses reserved' in result.stderr
    assert not output.exists()


def test_expanded_populations_are_disjoint_and_keep_review_pending():
    root=Path(__file__).parents[1]/'research/python-key-origin/expanded-2026-10-30'
    repositories=set()
    for split in ('development','evaluation_reserved'):
        manifest=json.loads((root/(split+'-corpus.json')).read_text(encoding='utf-8'))
        packet=json.loads((root/(split+'-review-template.json')).read_text(encoding='utf-8'))
        hashes={project['id']+'/'+resource['path']:resource['sha256'] for project in manifest['projects'] for resource in project['resources'] if resource['kind']=='source'}
        for project in manifest['projects']:
            assert project['repository'] not in repositories
            repositories.add(project['repository'])
        assert len({entry['case_id'] for entry in packet['cases']})==len(packet['cases'])
        for entry in packet['cases']:
            assert entry['split']==split and entry['source_sha256']==hashes[entry['source']]
            assert entry['independent_review']['status']=='pending'


def test_explicit_evaluation_still_requires_completed_review_before_loading_sources(tmp_path):
    root=Path(__file__).parents[1]
    output=tmp_path/'refused-evaluation'
    from cryptograph.research_freeze import candidate_fingerprint
    packet_path=root/'research/python-key-origin/expanded-2026-10-30/evaluation_reserved-review-template.json'
    frozen={'candidate_fingerprint':candidate_fingerprint(json.loads(packet_path.read_text(encoding='utf-8'))),
            'method_inputs_sha256':{'scripts/run-project-key-origin.py':hashlib.sha256((root/'scripts/run-project-key-origin.py').read_bytes().replace(b'\r\n',b'\n')).hexdigest()},
            'reserved_manifest_file':'research/python-key-origin/expanded-2026-10-30/evaluation_reserved-corpus.json'}
    snapshot=tmp_path/'synthetic-gate-snapshot.json';snapshot.write_text(json.dumps(frozen),encoding='utf-8')
    result=subprocess.run([sys.executable,str(root/'scripts/run-project-key-origin.py'),
        '--manifest',str(root/'research/python-key-origin/expanded-2026-10-30/evaluation_reserved-corpus.json'),
        '--annotations',str(root/'research/python-key-origin/expanded-2026-10-30/evaluation_reserved-review-template.json'),
        '--phase','reviewed-evaluation','--freeze',str(snapshot),
        '--source-root',str(tmp_path/'absent'),'--backend','ast-lite','--out-dir',str(output)],capture_output=True,text=True)
    assert result.returncode==2 and 'no completed independent' in result.stderr
    assert not output.exists()
