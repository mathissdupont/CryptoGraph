"""Compute reviewed diagnostics, or opt in to provisional development agreement."""
import argparse
import hashlib
import sys
from pathlib import Path

from cryptograph.research_eval import ReviewPending, score_provisional, score_reviewed
from cryptograph.models import NormalizedGraph
from cryptograph.utils import load_json, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--annotations", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provisional-proposals", type=Path,
                        help="Explicit opt-in: check development agreement against unreviewed assistant proposals; never research accuracy.")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output path so an older score cannot be confused with this run.")
    try:
        graph_path = args.observations.parent / "graph.json"
        graph = NormalizedGraph.model_validate(load_json(graph_path)) if graph_path.exists() else None
        annotations, observations = load_json(args.annotations), load_json(args.observations)
        if args.provisional_proposals:
            result = score_provisional(annotations, load_json(args.provisional_proposals), observations, args.annotations.parent, graph)
        else:
            result = score_reviewed(annotations, observations, args.annotations.parent, graph)
    except ReviewPending as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print(f"Invalid evaluation inputs: {exc}", file=sys.stderr)
        return 3
    result["inputs_sha256"] = {
        "annotations": hashlib.sha256(args.annotations.read_bytes()).hexdigest(),
        "observations": hashlib.sha256(args.observations.read_bytes()).hexdigest(),
        "graph": hashlib.sha256(graph_path.read_bytes()).hexdigest() if graph_path.exists() else None,
    }
    if args.provisional_proposals:
        result["inputs_sha256"]["provisional_proposals"] = hashlib.sha256(args.provisional_proposals.read_bytes()).hexdigest()
    write_json(args.output, result)
    print(f"Wrote {result['status']} to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
