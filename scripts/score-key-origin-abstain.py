"""Score a zero-coverage reference only after the same source-review gate."""
import argparse
import hashlib
import json
from pathlib import Path

from cryptograph.research_eval import ReviewPending, always_abstain_reference, score_reviewed
from cryptograph.utils import load_json, write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--annotations',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Use a fresh output path')
    try:
        annotations=load_json(args.annotations)
        observations=always_abstain_reference(annotations)
        result=score_reviewed(annotations,observations,args.source_root)
    except ReviewPending as exc:
        parser.exit(2,str(exc)+'\n')
    except (ValueError,OSError,KeyError) as exc:
        parser.exit(3,str(exc)+'\n')
    result['reference_note']='Always abstains at reviewed eligible sites; no binding/origin/evidence claims are emitted. Zero coverage does not establish a useful detector.'
    result['inputs_sha256']={'annotations':hashlib.sha256(args.annotations.read_bytes()).hexdigest(),
        'generated_observations':hashlib.sha256(json.dumps(observations,sort_keys=True).encode()).hexdigest()}
    write_json(args.output,result)
    print('Reviewed zero-coverage reference written; no analyzer ran.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
