"""Audit source-review exports and prepare disagreements without auto-approval."""
import argparse
import hashlib
from itertools import combinations
from pathlib import Path

from cryptograph.research_review import audit_review, compare_reviews, validate_review_sources
from cryptograph.utils import load_json, write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--annotations',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--review',type=Path,action='append',default=[])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Use a new report path; review inputs are never edited')
    try:
        population=load_json(args.annotations)
        validate_review_sources(population,args.source_root)
        audits=[dict(audit_review(population,load_json(path)),file=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in args.review]
        result={'status':'human_review_audit_not_research_accuracy','candidate_sites':len(population['cases']),
                'annotation_sha256':hashlib.sha256(args.annotations.read_bytes()).hexdigest(),
                'submitted_review_files':len(audits),'reviews':audits,
                'comparisons':[dict(compare_reviews(audits[a],audits[b]),review_files=[audits[a]['file'],audits[b]['file']])
                               for a,b in combinations(range(len(audits)),2)],
                'references_auto_approved':False,'analyzer_executed':False,
                'next_action':'Collect human source reviews; no submitted records.' if not audits else 'Resolve reported disagreements with human source-based reasons; keep originals.'}
        write_json(args.output,result)
    except (ValueError,OSError,KeyError,SyntaxError,TypeError) as exc:
        parser.exit(3,f'Invalid source review: {exc}\n')
    print(f'Audited {len(audits)} human review files at {len(population["cases"])} frozen sites; no labels were approved or scored.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
