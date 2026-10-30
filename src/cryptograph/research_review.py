"""Audit human review files and preserve disagreements without adjudicating them."""
from __future__ import annotations

import ast
import hashlib
from collections import Counter
from pathlib import Path

from cryptograph.key_origin import MODEL
from cryptograph.research_eval import OriginReference

IDENTITY_FIELDS=('source','source_sha256','target_api','target','split','scenario_family','project')


def require_blank_review_population(packet):
    """Withhold labels and previous reviewer notes from fresh source-only forms."""
    if packet.get('review_form_role'):
        raise ValueError('Use the original blank population template; load a saved draft through the review form instead')
    for entry in packet['cases']:
        if any(entry.get(field) is not None for field in ('author_review','proposed_reference','evidence_policy','observed')):
            raise ValueError('Source-only review materials must not contain labels or predictions')
        review=entry.get('independent_review',{})
        if (review.get('status','pending')!='pending' or review.get('reviewed_reference') is not None
            or review.get('reviewer') or review.get('notes') or review.get('candidate_rationale')):
            raise ValueError('Source-only review materials must start from blank reviewer records')


def validate_review_sources(packet, source_root):
    if packet.get('analysis_model') != MODEL:
        raise ValueError('Review population uses a different analysis model')
    entries=packet['cases']
    if not entries or len({entry['case_id'] for entry in entries})!=len(entries):
        raise ValueError('Review population is empty or contains duplicate cases')
    positions={}
    for entry in entries:
        path=(source_root/entry['source']).resolve()
        if not path.is_relative_to(source_root.resolve()):
            raise ValueError('Review source escaped the population root')
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=entry['source_sha256']:
            raise ValueError('Review source snapshot changed: '+entry['case_id'])
        if path not in positions:
            tree=ast.parse(raw.decode('utf-8-sig'))
            positions[path]={(node.lineno,node.col_offset,node.end_lineno,node.end_col_offset)
                             for node in ast.walk(tree) if isinstance(node,ast.Call)}
        target=entry['target']
        if target['file']!=path.name or tuple(target[key] for key in ('line','column','end_line','end_column')) not in positions[path]:
            raise ValueError('Review target is not a frozen source call')


def audit_review(population, submitted):
    role=submitted.get('review_form_role')
    if role not in {'project_author','independent'} or submitted.get('analysis_model')!=population.get('analysis_model'):
        raise ValueError('Review must declare the population model and project_author/independent role')
    expected={entry['case_id']:entry for entry in population['cases']}
    supplied=submitted['cases']
    if len(supplied)!=len(expected) or {entry['case_id'] for entry in supplied}!=set(expected):
        raise ValueError('Review must preserve every candidate identity, including pending/rejected cases')
    field='author_review' if role=='project_author' else 'independent_review'
    rows=[];reviewers=set()
    for entry in supplied:
        original=expected[entry['case_id']]
        if any(entry.get(key)!=original.get(key) for key in IDENTITY_FIELDS):
            raise ValueError('Review changed a source/API/split identity: '+entry['case_id'])
        review=entry.get(field,{})
        if role=='project_author' and entry.get('independent_review')!=original.get('independent_review'):
            raise ValueError('An author export changed independent review records')
        if review.get('status','pending') not in {'pending','approved'}:
            raise ValueError('Unknown review completion status')
        if review.get('reviewer_role',role)!=role:
            raise ValueError('Per-case and declared review roles differ')
        completed=review.get('status')=='approved'
        decision=review.get('candidate_decision','pending')
        if decision not in {'eligible','ineligible','pending','uncertain'}:
            raise ValueError('Unknown candidate decision')
        reference=None
        if completed:
            if (not isinstance(review.get('reviewer'),str) or not review['reviewer'].strip()
                or not isinstance(review.get('candidate_rationale'),str) or not review['candidate_rationale'].strip()):
                raise ValueError('A completed source review needs a reviewer identifier and rationale')
            if decision=='eligible':
                if review.get('candidate_verified') is not True:
                    raise ValueError('Eligible completed review needs explicit candidate verification')
                reference=OriginReference.model_validate(review.get('reviewed_reference')).model_dump()
                reference['origins']=sorted(reference['origins'])
            elif decision=='ineligible':
                if review.get('reviewed_reference') is not None or review.get('candidate_verified') is True:
                    raise ValueError('Rejected candidates must not carry an invented origin reference/verification')
            else:
                raise ValueError('Uncertain or pending candidate decisions cannot be approved')
            reviewers.add(review['reviewer'].strip())
        rows.append({'case_id':entry['case_id'],'completed':completed,'candidate_decision':decision,
                     'reviewed_reference':reference,'rationale':review.get('candidate_rationale'),
                     'reviewer':review.get('reviewer')})
    return {'role':role,'reviewer_identifiers':sorted(reviewers),'completed':sum(row['completed'] for row in rows),
            'pending':sum(not row['completed'] for row in rows),'cases':rows,
            'independence':'author_review_only' if role=='project_author' else 'declared_not_verified_by_software'}


def compare_reviews(left, right):
    right_rows={row['case_id']:row for row in right['cases']}
    if {row['case_id'] for row in left['cases']}!=set(right_rows):
        raise ValueError('Compared reviews have different candidate populations')
    rows=[];counts=Counter()
    for first in left['cases']:
        second=right_rows[first['case_id']]
        if not first['completed'] or not second['completed']:
            outcome='awaiting_completed_pair'
        elif first['candidate_decision']!=second['candidate_decision']:
            outcome='candidate_eligibility_disagreement'
        elif first['candidate_decision']=='ineligible':
            outcome='both_reject_candidate'
        elif first['reviewed_reference']!=second['reviewed_reference']:
            outcome='origin_reference_disagreement'
        else:
            outcome='exact_reference_agreement'
        counts[outcome]+=1
        rows.append({'case_id':first['case_id'],'outcome':outcome,
                     'left':first,'right':second,
                     'adjudication':{'status':'pending','reviewer':None,'reason':None,'reference':None}})
    overlap=sorted(set(left['reviewer_identifiers']) & set(right['reviewer_identifiers']))
    return {'status':'comparison_only_no_references_approved','counts':dict(counts),'cases':rows,
            'shared_reviewer_identifiers':overlap,
            'independence':'not_established_shared_identifier' if overlap else 'not_verifiable_from_identifiers',
            'scope':'Human review agreement/disagreement only; not analyzer accuracy, validated truth or automatic adjudication.'}
