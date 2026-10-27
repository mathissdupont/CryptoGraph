"""Score key-origin outputs only after a completed review record is supplied."""
import argparse
import hashlib
import sys
from pathlib import Path

from cryptograph.research_eval import ReviewPending, score_reviewed
from cryptograph.models import NormalizedGraph
from cryptograph.utils import load_json, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--annotations", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output path so an older score cannot be confused with this run.")
    try:
        graph_path = args.observations.parent / "graph.json"
        graph = NormalizedGraph.model_validate(load_json(graph_path)) if graph_path.exists() else None
        result = score_reviewed(load_json(args.annotations), load_json(args.observations), args.annotations.parent, graph)
    except ReviewPending as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (ValueError, KeyError) as exc:
        print(f"Invalid evaluation inputs: {exc}", file=sys.stderr)
        return 3
    result["inputs_sha256"] = {
        "annotations": hashlib.sha256(args.annotations.read_bytes()).hexdigest(),
        "observations": hashlib.sha256(args.observations.read_bytes()).hexdigest(),
        "graph": hashlib.sha256(graph_path.read_bytes()).hexdigest() if graph_path.exists() else None,
    }
    write_json(args.output, result)
    print(f"Wrote review-recorded diagnostics to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
