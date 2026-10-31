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
    parser.add_argument('--source-root', type=Path, help='Root of downloaded project sources; defaults to the annotation directory.')
    parser.add_argument("--provisional-proposals", type=Path,
                        help="Explicit opt-in: check development agreement against unreviewed assistant proposals; never research accuracy.")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output path so an older score cannot be confused with this run.")
    try:
        graph_path = args.observations.parent / "graph.json"
        graph = NormalizedGraph.model_validate(load_json(graph_path)) if graph_path.exists() else None
        index_path = args.observations.parent / 'graph-index.json'
        graph_files = {}
        if index_path.exists():
            if graph_path.exists():
                raise ValueError('Provide either a single graph or a project graph index, not both')
            if args.observations.parent.parent.name != 'conditions':
                raise ValueError('Project graph indexes must belong to an experiment conditions directory')
            experiment_root = args.observations.parent.parent.parent.resolve()
            for project, relative in load_json(index_path)['graphs'].items():
                path = (index_path.parent / relative).resolve()
                if not path.is_relative_to(experiment_root):
                    raise ValueError('Project graph escaped the experiment directory')
                graph_files[project] = path
            graph = {project: NormalizedGraph.model_validate(load_json(path)) for project,path in graph_files.items()}
        annotations, observations = load_json(args.annotations), load_json(args.observations)
        source_root = args.source_root or args.annotations.parent
        if args.provisional_proposals:
            result = score_provisional(annotations, load_json(args.provisional_proposals), observations, source_root, graph)
        else:
            result = score_reviewed(annotations, observations, source_root, graph)
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
    if index_path.exists():
        result['inputs_sha256']['graph_index'] = hashlib.sha256(index_path.read_bytes()).hexdigest()
        result['inputs_sha256']['project_graphs'] = {project:hashlib.sha256(path.read_bytes()).hexdigest() for project,path in graph_files.items()}
    write_json(args.output, result)
    print(f"Wrote {result['status']} to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
