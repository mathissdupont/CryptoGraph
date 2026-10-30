"""Check frozen methods/candidates and review readiness; never execute evaluation."""
import argparse
from pathlib import Path

from cryptograph.research_eval import ReviewPending
from cryptograph.research_freeze import check_freeze
from cryptograph.utils import load_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze',type=Path,default=Path('research/python-key-origin/evaluation-freeze.json'))
    parser.add_argument('--annotations',type=Path)
    parser.add_argument('--snapshot-only',action='store_true',help='Check identities/code only, without claiming annotation readiness.')
    args=parser.parse_args()
    try:
        root=Path(__file__).resolve().parents[1]
        freeze=load_json(args.freeze)
        annotations=args.annotations or root/freeze.get('annotation_file','research/python-key-origin/reserved-review-template.json')
        check_freeze(freeze,load_json(annotations),root,not args.snapshot_only)
    except ReviewPending as exc:
        parser.exit(2,str(exc)+'\n')
    except (ValueError,OSError,KeyError) as exc:
        parser.exit(3,f'Invalid frozen evaluation inputs: {exc}\n')
    print('Snapshot verified; no analyzer or evaluation was executed.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
