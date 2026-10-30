"""Exercise the actual form export JavaScript on synthetic review fixtures."""
import hashlib
import copy
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cryptograph.research_eval import independent_review_ready

ROOT=Path(__file__).parents[1]
pytestmark=pytest.mark.skipif(shutil.which('node') is None,reason='Form export check requires Node 18+; Python scoring tests remain independent.')


@pytest.mark.parametrize('role,decision',[('project_author','eligible'),('independent','ineligible')])
def test_form_download_preserves_review_role_and_valid_json(tmp_path,role,decision):
    raw=b'from Crypto.Cipher import AES\nvalue=AES.new(b"key",1)\n'
    source=tmp_path/'sources'/'example.py';source.parent.mkdir();source.write_bytes(raw)
    entry={'case_id':'fixture<only','source':'example.py','source_sha256':hashlib.sha256(raw).hexdigest(),
           'target_api':'Crypto.Cipher.AES.new','target':{'file':'example.py','line':2,'column':6,'end_line':2,'end_column':24},
           'candidate_status':'synthetic_fixture','independent_review':{'status':'pending'}}
    packet={'cases':[entry]}
    (tmp_path/'annotations.json').write_text(json.dumps(packet),encoding='utf-8')
    subprocess.run([sys.executable,str(ROOT/'scripts/render-key-origin-review.py'),'--bundle',str(tmp_path),'--role',role],check=True,capture_output=True)
    page=(tmp_path/'review.html').read_text(encoding='utf-8')
    embedded=re.search(r'<script type="application/json" id="packet">(.*?)</script>',page,re.S).group(1)
    assert json.loads(embedded)==packet
    script=re.search(r'</script><script>(.*?)</script>',page,re.S).group(1)
    harness='''const vm=require('node:vm');let exported;
const fields={decision:{value:DECISION},complete:{value:'yes'},boundary:{value:'literal'},rationale:{value:'Synthetic unit fixture, not real source review.'},confirmed:{checked:true}};
const origins=[{value:'literal',checked:true}];
const box={dataset:{case:'fixture<only'},querySelector(s){return fields[s.match(/name="(.*?)"/)[1]]},querySelectorAll(){return origins}};
const elements={packet:{textContent:PACKET},reviewer:{value:'unit-fixture-not-a-person'},save:{},restore:{},status:{}};
const document={getElementById(id){return elements[id]},querySelectorAll(){return [box]},createElement(){return {click(){}}}};
const context={document,Blob,URL:{createObjectURL(blob){exported=blob;return 'blob:synthetic'},revokeObjectURL(){}},setTimeout(){}};
vm.runInNewContext(SCRIPT,context);elements.save.onclick();exported.text().then(text=>process.stdout.write(text));'''
    harness=harness.replace('DECISION',json.dumps(decision)).replace('PACKET',json.dumps(json.dumps(packet))).replace('SCRIPT',json.dumps(script))
    result=subprocess.run(['node','-e',harness],capture_output=True,text=True,check=True)
    review=json.loads(result.stdout)['cases'][0]
    field='author_review' if role=='project_author' else 'independent_review'
    assert review[field]['status']=='approved'
    assert review[field]['reviewer_role']==role
    if role=='project_author':
        assert review['independent_review']=={'status':'pending'}
        assert not independent_review_ready(review)
    else:
        assert independent_review_ready(review)
        assert review[field]['reviewed_reference'] is None


@pytest.mark.parametrize('mutation',['none','reordered_keys','api_mismatch','late_source_mismatch','malformed_late_reference','invalid_late_note'])
def test_restoring_a_draft_checks_all_identities_before_changing_the_form(tmp_path,mutation):
    raw=b'from Crypto.Cipher import AES\nvalue=AES.new(b"key",1)\n'
    source=tmp_path/'sources/example.py';source.parent.mkdir();source.write_bytes(raw)
    entry={'case_id':'first','source':'example.py','source_sha256':hashlib.sha256(raw).hexdigest(),
           'target_api':'Crypto.Cipher.AES.new','split':'development',
           'target':{'file':'example.py','line':2,'column':6,'end_line':2,'end_column':24},'independent_review':{'status':'pending'}}
    second=copy.deepcopy(entry);second['case_id']='second'
    packet={'analysis_model':'python-key-origin-subset-v0.1','cases':[entry,second]}
    (tmp_path/'annotations.json').write_text(json.dumps(packet),encoding='utf-8')
    subprocess.run([sys.executable,str(ROOT/'scripts/render-key-origin-review.py'),'--bundle',str(tmp_path),'--role','project_author'],check=True,capture_output=True)
    script=re.search(r'</script><script>(.*?)</script>',(tmp_path/'review.html').read_text(encoding='utf-8'),re.S).group(1)
    draft=copy.deepcopy(packet);draft['review_form_role']='project_author'
    for case in draft['cases']:
        case['author_review']={'status':'pending','reviewer':'synthetic-reviewer','reviewer_role':'project_author',
                              'candidate_decision':'eligible','candidate_rationale':'new draft text','reviewed_reference':None}
    if mutation=='reordered_keys':draft['cases'][1]['target']=dict(reversed(list(entry['target'].items())))
    elif mutation=='api_mismatch':draft['cases'][1]['target_api']='fake.AES'
    elif mutation=='late_source_mismatch':draft['cases'][1]['source_sha256']='0'*64
    elif mutation=='malformed_late_reference':draft['cases'][1]['author_review']['reviewed_reference']={'origins':42}
    elif mutation=='invalid_late_note':draft['cases'][1]['author_review']['candidate_rationale']={'invalid':'not text'}
    harness='''const vm=require('node:vm');const controls=[];
const boxes=['first','second'].map(id=>{const fields={decision:{value:'pending'},boundary:{value:''},complete:{value:''},rationale:{value:'existing unsaved text'},confirmed:{checked:false}};controls.push(fields);return {dataset:{case:id},querySelector(s){return fields[s.match(/name="(.*?)"/)[1]]},querySelectorAll(){return []}}});
const elements={packet:{textContent:PACKET},reviewer:{value:'existing reviewer'},save:{},restore:{},status:{}};
const document={getElementById(id){return elements[id]},querySelectorAll(){return boxes}};
vm.runInNewContext(SCRIPT,{document,Blob,URL,setTimeout});
elements.restore.onchange({target:{files:[{text:async()=>DRAFT}]}}).then(()=>process.stdout.write(JSON.stringify({controls,status:elements.status.textContent,reviewer:elements.reviewer.value})));'''
    harness=harness.replace('PACKET',json.dumps(json.dumps(packet))).replace('SCRIPT',json.dumps(script)).replace('DRAFT',json.dumps(json.dumps(draft)))
    result=json.loads(subprocess.run(['node','-e',harness],capture_output=True,text=True,check=True).stdout)
    if mutation in {'none','reordered_keys'}:
        assert result['controls'][0]['rationale']['value']=='new draft text'
        assert result['reviewer']=='synthetic-reviewer'
    else:
        assert all(control['rationale']['value']=='existing unsaved text' for control in result['controls'])
        assert result['reviewer']=='existing reviewer'
