"""Freeze/review mechanics on synthetic fixtures, not approved corpus labels."""
import hashlib

import pytest

from cryptograph.research_eval import ReviewPending
from cryptograph.research_freeze import candidate_fingerprint, check_freeze


@pytest.fixture
def frozen(tmp_path):
    path=tmp_path/'method.py';path.write_bytes(b'# synthetic method\n')
    packet={'cases':[dict(case_id='fixture',project='example',source='f.py',source_sha256='source',split='evaluation_reserved',scenario_family='example',target_api='AES',target={'line':1},independent_review={'status':'pending'})]}
    record={'candidate_fingerprint':candidate_fingerprint(packet),'method_inputs_sha256':{'method.py':hashlib.sha256(path.read_bytes()).hexdigest()}}
    return tmp_path,record,packet


def test_frozen_snapshot_can_be_checked_without_claiming_review(frozen):
    root,record,packet=frozen
    assert check_freeze(record,packet,root,False)['evaluation_executed'] is False
    with pytest.raises(ReviewPending):
        check_freeze(record,packet,root)


def test_method_changes_require_a_new_snapshot(frozen):
    root,record,packet=frozen
    (root/'method.py').write_bytes(b'# changed\n')
    with pytest.raises(ValueError,match='Method snapshot'):
        check_freeze(record,packet,root,False)


def test_method_text_fingerprint_is_portable_across_line_endings(frozen):
    root,record,packet=frozen
    (root/'method.py').write_bytes(b'# synthetic method\r\n')
    check_freeze(record,packet,root,False)


def test_review_fields_can_change_but_candidate_locations_cannot(frozen):
    root,record,packet=frozen
    packet['cases'][0]['independent_review']['notes']='synthetic reviewer note'
    check_freeze(record,packet,root,False)
    packet['cases'][0]['target']['line']=2
    with pytest.raises(ValueError,match='population changed'):
        check_freeze(record,packet,root,False)
