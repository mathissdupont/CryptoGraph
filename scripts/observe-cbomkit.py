"""Reproduce a pinned CBOMkit inventory; preserve its native claim granularity."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from cryptograph.research_corpus import materialize_corpus
from cryptograph.utils import load_json, write_json

IMAGE='ghcr.io/cbomkit/cbomkit-action@sha256:7dfc905c614549fdb630d41a33b34a039af7f60c982501c6d74dfc63ef700512'
REVISION='847c980e33b166603b39578472c9a04bbea238e2'
ROOT=Path(__file__).resolve().parents[1]
CONTROL='from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\ndef build():\n    return Cipher(algorithms.AES(b"0123456789abcdef"), modes.CBC(b"0123456789abcdef"))\n'


def calibration_sources():
    header='from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n'
    literal='algorithms.AES(b"0123456789abcdef"), modes.CBC(b"0123456789abcdef")'
    return {
        'assigned_literal':header+'def build():\n    cipher = Cipher('+literal+')\n    return cipher\n',
        'backend_keyword':header+'from cryptography.hazmat.backends import default_backend\ndef build():\n    cipher = Cipher('+literal+', backend=default_backend())\n    return cipher\n',
        'backend_positional':header+'from cryptography.hazmat.backends import default_backend\ndef build():\n    cipher = Cipher('+literal+', default_backend())\n    return cipher\n',
        'parameter_key':header+'def build(key, iv):\n    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))\n    return cipher\n',
        'random_key':header+'import os\ndef build():\n    key = os.urandom(16)\n    iv = os.urandom(16)\n    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))\n    return cipher\n',
    }


def run_scan(source, output):
    output.mkdir(parents=True)
    command=['docker','run','--rm','--network','none',
             '-e','GITHUB_WORKSPACE=/workspace','-e','GITHUB_OUTPUT=/results/github-output.txt',
             '-e','CBOMKIT_OUTPUT_DIR=/results/cbom','-e','CBOMKIT_LANGUAGES=python',
             '-e','CBOMKIT_EXCLUDE=(?!)','-e','CBOMKIT_GENERATE_MODULE_CBOMS=false',
             '--mount',f'type=bind,source={source.resolve()},target=/workspace,readonly',
             '--mount',f'type=bind,source={output.resolve()},target=/results',
             IMAGE,'java','-Xmx2g','-jar','/cbomkit-action/CBOMkit-action.jar']
    with (output/'tool.log').open('wb') as log:
        process=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=180)
    text=(output/'tool.log').read_text(encoding='utf-8',errors='replace')
    scanned=re.findall(r'Scanned (\d+) files with (\d+) lines',text)
    result={'returncode':process.returncode,'scanned_files':int(scanned[-1][0]) if scanned else None,
            'scanned_lines':int(scanned[-1][1]) if scanned else None}
    native=output/'cbom/cbom.json'
    if process.returncode or not native.is_file():
        return dict(result,status='failed_native_scan')
    cbom=load_json(native)
    assets=[item for item in cbom.get('components',[]) if item.get('type')=='cryptographic-asset']
    return dict(result,status='native_scan_completed',native_sha256=hashlib.sha256(native.read_bytes()).hexdigest(),
                bom_format=cbom.get('bomFormat'),spec_version=cbom.get('specVersion'),cryptographic_assets=len(assets),
                asset_names=[item.get('name') for item in assets],
                native_occurrences=[{'asset_name':item.get('name'),'occurrence':occurrence}
                    for item in assets for occurrence in item.get('evidence',{}).get('occurrences',[])])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--out-dir',type=Path,required=True)
    parser.add_argument('--pull',action='store_true',help='Fetch the exact public image digest if needed.')
    args=parser.parse_args()
    if args.out_dir.exists():
        parser.error('Use a fresh result directory.')
    definition=ROOT/'research/python-key-origin/project-corpus.json'
    manifest=load_json(definition)
    verified=materialize_corpus(manifest,args.source_root)
    if args.pull:
        subprocess.run(['docker','pull',IMAGE],check=True)
    info=json.loads(subprocess.check_output(['docker','image','inspect',IMAGE],text=True))[0]
    labels=info['Config'].get('Labels',{})
    if labels.get('org.opencontainers.image.revision')!=REVISION:
        parser.error('The pinned image does not declare the inspected source revision.')
    out=args.out_dir.resolve();out.mkdir(parents=True)
    record={'status':'started','image':IMAGE,'image_id':info['Id'],'declared_source_revision':REVISION,
            'parameters':{'languages':'python','exclude':'(?!)','generate_module_cboms':False,'java_max_heap':'2g','network':'none'},
            'scope':'Native inventory observations on development source slices; no key-origin score or reviewed detection accuracy.',
            'manifest_sha256':hashlib.sha256(definition.read_bytes()).hexdigest(),
            'adapter_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'verified_resources':verified['resources'],'key_origin_score':None,'projects':{}}
    write_json(out/'run.json',record)
    control=out/'control-source';control.mkdir();(control/'__init__.py').write_bytes(CONTROL.encode())
    try:
        smoke=run_scan(control,out/'control-result')
        record['positive_control']=dict(smoke,source_sha256=hashlib.sha256(CONTROL.encode()).hexdigest())
        if smoke['status']!='native_scan_completed' or smoke['scanned_files']!=1 or not any('AES' in name for name in smoke.get('asset_names',[]) if name):
            record['status']='failed_positive_control';write_json(out/'run.json',record);return 2
        record['exploratory_calibration_controls']={}
        for name,text in calibration_sources().items():
            directory=out/'calibration-sources'/name;directory.mkdir(parents=True)
            (directory/'__init__.py').write_bytes(text.encode())
            result=run_scan(directory,out/'calibration-results'/name)
            record['exploratory_calibration_controls'][name]=dict(result,source_sha256=hashlib.sha256(text.encode()).hexdigest())
            if result['status']!='native_scan_completed' or result['scanned_files']!=1:
                record['status']='failed_calibration_scan';write_json(out/'run.json',record);return 2
        incomplete=False
        for project in manifest['projects']:
            expected=sum(item['kind']=='source' and item['path'].endswith('.py') for item in project['resources'])
            observation=run_scan(args.source_root/project['id'],out/project['id'])
            observation['expected_source_files']=expected
            observation['complete_file_coverage']=observation.get('scanned_files')==expected
            incomplete |= observation['status']!='native_scan_completed' or not observation['complete_file_coverage']
            record['projects'][project['id']]=observation
            write_json(out/'run.json',record)
            print(f"{project['id']}: {observation.get('scanned_files')}/{expected} source files; {observation.get('cryptographic_assets')} native crypto assets",flush=True)
        record['status']='incomplete' if incomplete else 'completed'
        write_json(out/'run.json',record)
        return 2 if incomplete else 0
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        record.update(status='failed',error=str(exc));write_json(out/'run.json',record);return 2


if __name__=='__main__':
    raise SystemExit(main())
