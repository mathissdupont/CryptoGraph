"""Check reserved candidate/method snapshots without running an analyzer."""
import hashlib
import json
from pathlib import Path

from cryptograph.research_eval import OriginReference, ReviewPending


def candidate_fingerprint(packet):
    fields=('case_id','project','source','source_sha256','split','scenario_family','target_api','target')
    identities=[{field:entry[field] for field in fields} for entry in packet['cases']]
    return hashlib.sha256(json.dumps(sorted(identities,key=lambda entry:entry['case_id']),sort_keys=True).encode()).hexdigest()


def check_freeze(freeze, packet, root: Path, require_review=True):
    root=root.resolve()
    for name,expected in freeze['method_inputs_sha256'].items():
        path=(root/name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=expected:
            raise ValueError(f'Method snapshot changed: {name}')
    if candidate_fingerprint(packet)!=freeze['candidate_fingerprint']:
        raise ValueError('Reserved candidate population changed')
    if not packet['cases'] or any(entry['split']!='evaluation_reserved' for entry in packet['cases']):
        raise ValueError('Expected a nonempty reserved candidate inventory')
    if require_review:
        pending=[]
        for entry in packet['cases']:
            review=entry.get('independent_review',{})
            if (review.get('status')!='approved' or not review.get('reviewer')
                or review.get('candidate_verified') is not True or review.get('reviewer_role')!='independent'):
                pending.append(entry['case_id'])
            else:
                OriginReference.model_validate(review.get('reviewed_reference'))
        if pending:
            raise ReviewPending('Reserved evaluation has no completed independent source/candidate review: '+', '.join(pending))
    return {'status':'snapshot_verified','evaluation_executed':False,
            'review_independence':'declared_not_verified_by_software' if require_review else 'not_checked'}
