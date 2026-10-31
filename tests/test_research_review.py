"""Synthetic human-review fixtures; these are not approved research labels."""
import copy

import pytest

from cryptograph.research_inventory import index_python_source
from cryptograph.research_review import audit_review, compare_reviews, require_blank_review_population, validate_review_sources


@pytest.fixture
def review_data(tmp_path):
    raw=b'from Crypto.Cipher import AES\nAES.new(b"synthetic",1)\n'
    (tmp_path/'example').mkdir();(tmp_path/'example/module.py').write_bytes(raw)
    population=index_python_source(raw,'example/module.py','example','development')
    submitted=copy.deepcopy(population);submitted['review_form_role']='project_author'
    submitted['cases'][0]['author_review']={'status':'approved','reviewer':'unit-fixture-author','reviewer_role':'project_author',
        'candidate_decision':'eligible','candidate_verified':True,'candidate_rationale':'Synthetic unit data, not a real review.',
        'reviewed_reference':{'status':'resolved','origins':['literal'],'origin_set_complete':True,'modality':'must','immediate_boundary':'literal'}}
    return tmp_path,population,submitted


def test_historical_review_source_audit_keeps_its_model(review_data):
    root,population,submitted=review_data
    population['analysis_model']='python-key-origin-subset-v0.1'
    submitted['analysis_model']='python-key-origin-subset-v0.1'
    validate_review_sources(population,root)
    assert audit_review(population,submitted)['completed']==1
    assert submitted['analysis_model']=='python-key-origin-subset-v0.1'
    submitted['analysis_model']='python-key-origin-subset-v0.2'
    with pytest.raises(ValueError):
        audit_review(population,submitted)


def independent(submitted):
    result=copy.deepcopy(submitted);result['review_form_role']='independent'
    review=result['cases'][0].pop('author_review');review['reviewer_role']='independent';review['reviewer']='unit-fixture-independent'
    result['cases'][0]['independent_review']=review
    return result


def test_audit_preserves_author_role_and_original_pending_references(review_data):
    root,population,submitted=review_data;before=copy.deepcopy(population)
    validate_review_sources(population,root)
    result=audit_review(population,submitted)
    assert result['completed']==1 and result['independence']=='author_review_only'
    assert population==before and population['cases'][0]['independent_review']['status']=='pending'


@pytest.mark.parametrize('mutation',['role','source','api','split','missing_case','invalid_reference','missing_reason'])
def test_review_cannot_silently_change_population_or_approval_requirements(review_data,mutation):
    _,population,submitted=review_data;entry=submitted['cases'][0]
    if mutation=='role':entry['author_review']['reviewer_role']='independent'
    elif mutation=='source':entry['source_sha256']='0'*64
    elif mutation=='api':entry['target_api']='fake.AES'
    elif mutation=='split':entry['split']='evaluation_reserved'
    elif mutation=='missing_case':submitted['cases']=[]
    elif mutation=='invalid_reference':entry['author_review']['reviewed_reference']['origins']=['invented_category']
    elif mutation=='missing_reason':entry['author_review']['candidate_rationale']=''
    with pytest.raises(ValueError):audit_review(population,submitted)


def test_changed_raw_source_rejects_review_audit(review_data):
    root,population,_=review_data;(root/'example/module.py').write_bytes(b'# changed\n')
    with pytest.raises(ValueError,match='snapshot changed'):validate_review_sources(population,root)


def test_disagreements_remain_pending_without_silent_adjudication(review_data):
    _,population,submitted=review_data;other=independent(submitted)
    other['cases'][0]['independent_review']['reviewed_reference']['origins']=['csprng_api']
    result=compare_reviews(audit_review(population,submitted),audit_review(population,other))
    assert result['counts']=={'origin_reference_disagreement':1}
    assert result['cases'][0]['adjudication']['status']=='pending'


def test_shared_identity_cannot_be_reported_as_independent_confirmation(review_data):
    _,population,submitted=review_data;other=independent(submitted)
    other['cases'][0]['independent_review']['reviewer']='unit-fixture-author'
    result=compare_reviews(audit_review(population,submitted),audit_review(population,other))
    assert result['counts']=={'exact_reference_agreement':1}
    assert result['independence']=='not_established_shared_identifier'


def test_pending_draft_is_not_a_completed_reference(review_data):
    _,population,submitted=review_data;other=independent(submitted)
    other['cases'][0]['independent_review']['status']='pending'
    result=compare_reviews(audit_review(population,submitted),audit_review(population,other))
    assert result['counts']=={'awaiting_completed_pair':1}


def test_fresh_review_materials_cannot_contain_previous_answers(review_data):
    _,population,submitted=review_data
    require_blank_review_population(population)
    with pytest.raises(ValueError,match='blank population'):
        require_blank_review_population(submitted)
    contaminated=copy.deepcopy(population)
    contaminated['cases'][0]['proposed_reference']={'origins':['literal']}
    with pytest.raises(ValueError,match='labels or predictions'):
        require_blank_review_population(contaminated)


def test_author_exports_cannot_modify_independent_review_records(review_data):
    _,population,submitted=review_data
    submitted['cases'][0]['independent_review']['status']='approved'
    with pytest.raises(ValueError,match='author export changed'):
        audit_review(population,submitted)
