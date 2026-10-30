"""Exercise the actual form export JavaScript on synthetic review fixtures."""
import hashlib
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
