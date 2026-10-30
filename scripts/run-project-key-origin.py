"""Observe pinned real-project candidate sites without executing target programs."""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
import platform
import shutil
import sys
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from cryptograph.cpg_loader import CpgLoadError, load_graph
from cryptograph.cpg_visualizer import write_graph_json
from cryptograph.key_origin import analyze_key_origins, audit_claim_structure
from cryptograph.research_baselines import direct_expression_claim
from cryptograph.research_corpus import materialize_corpus
from cryptograph.utils import load_json, write_json
from cryptograph.dfg_probe import probe_key_paths
from cryptograph.research_eval import ReviewPending
from cryptograph.research_freeze import check_freeze

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path('output/python-project-sources'))
    parser.add_argument('--backend', choices=['ast-lite', 'fraunhofer-strict'], required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--dfg-probe', action='store_true')
    parser.add_argument('--manifest', type=Path, default=ROOT/'research/python-key-origin/project-corpus.json')
    parser.add_argument('--annotations', type=Path, default=ROOT/'research/python-key-origin/project-review-template.json')
    parser.add_argument('--graph-scope', choices=['project','candidate-files'], default='project')
    parser.add_argument('--phase', choices=['development','reviewed-evaluation'], default='development')
    parser.add_argument('--freeze', type=Path, help='Required for explicit reviewed evaluation; source/candidate/method review gates run before acquisition.')
    args = parser.parse_args()
    out = args.out_dir.resolve()
    if out.exists():
        parser.error('Use a new output directory.')
    definition = args.manifest.resolve()
    packet_path = args.annotations.resolve()
    manifest, packet = load_json(definition), load_json(packet_path)
    if args.phase == 'development':
        if any(entry['split'] != 'development' for entry in packet['cases']) or any(project.get('split', 'development') != 'development' for project in manifest['projects']):
            parser.error('This development runner refuses reserved/evaluation projects and annotations.')
    else:
        if not args.freeze:
            parser.error('Reviewed evaluation requires an explicit frozen method/candidate snapshot.')
        try:
            frozen=load_json(args.freeze)
            check_freeze(frozen,packet,ROOT,require_review=True)
            if definition != (ROOT/frozen['reserved_manifest_file']).resolve():
                raise ValueError('Evaluation manifest differs from the frozen reserved population')
            if any(project['split'] != 'evaluation_reserved' for project in manifest['projects']):
                raise ValueError('Reviewed evaluation may not mix development projects')
        except ReviewPending as exc:
            parser.exit(2,str(exc)+'\n')
        except (ValueError,OSError,KeyError) as exc:
            parser.exit(3,f'Invalid reviewed-evaluation inputs: {exc}\n')
    materialize_corpus(manifest, args.source_root)  # offline verification, no implicit fetching
    out.mkdir(parents=True)
    inputs = [definition, packet_path, Path(__file__).resolve(), *ROOT.joinpath('src/cryptograph').glob('*.py'),
              *ROOT.joinpath('config').glob('*.json'), ROOT/'pyproject.toml',
              ROOT/'tools/fraunhofer-exporter/src/main/kotlin/io/cryptograph/exporter/Main.kt',
              ROOT/'tools/fraunhofer-exporter/build.gradle.kts']
    hashes = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    exporter = Path(os.environ.get('CRYPTOGRAPH_FRAUNHOFER_EXPORTER', ''))
    record = {'status': 'started', 'scope': 'Convenience development sample; candidate matching is not reviewed detection recall or origin accuracy.',
              'generated_at': datetime.now(UTC).isoformat(),
              'phase': args.phase,
              'python': sys.version, 'platform': platform.platform(), 'requested_backend': args.backend, 'graph_scope': args.graph_scope,
              'dependencies': {name: version(name) for name in ('cryptograph','networkx','pydantic')},
              'exporter_sha256': hashlib.sha256(exporter.read_bytes()).hexdigest() if exporter.is_file() else None,
              'inputs_sha256': hashes, 'projects': {}}
    write_json(out / 'run.json', record)
    failures = False
    condition_outputs = {name: [] for name in ('direct_expression','source_only','graph_context')}
    graph_index = {}
    for project in manifest['projects']:
        ident = project['id']
        project_out = out / ident
        project_out.mkdir()
        write_json(project_out/'provenance.json', project)
        for resource in project['resources']:
            original=args.source_root/ident/resource['path']
            if resource['kind']=='license':
                destination=project_out/'attribution'/resource['path']
                destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(original,destination)
            elif resource['kind']=='source':
                raw=original.read_bytes();tree=ast.parse(raw.decode('utf-8-sig'))
                first=tree.body[0] if tree.body else None
                end=(first.end_lineno if isinstance(first,ast.Expr) and isinstance(first.value,ast.Constant) and isinstance(first.value.value,str)
                     else first.lineno-1 if first is not None else len(raw.splitlines()))
                destination=project_out/'attribution/source-notices'/Path(resource['path']+'.txt')
                destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(b''.join(raw.splitlines(keepends=True)[:end]))
        entries = [entry for entry in packet['cases'] if entry['project'] == ident]
        if not entries:
            record['projects'][ident] = {'status': 'no_candidates', 'eligible_candidates': 0, 'origin_analysis_executed': False}
            write_json(out/'run.json',record)
            print(f'{ident}: no primary candidates; retained without origin analysis',flush=True)
            continue
        try:
            if args.graph_scope == 'project':
                graph = load_graph(args.source_root / ident, args.backend)
            else:
                from cryptograph.models import NormalizedGraph
                fragments = []
                paths_ = {(args.source_root/entry['source']).resolve() for entry in entries}
                units = {(args.source_root/ident).resolve() if path.name=='__init__.py' else path for path in paths_}
                units = {path for path in units if not any(parent!=path and parent.is_dir() and path.is_relative_to(parent) for parent in units)}
                for unit in sorted(units):
                    fragment = load_graph(unit,args.backend)
                    if not fragment.nodes:
                        raise CpgLoadError(f'Empty graph for candidate-bearing translation unit: {unit}')
                    fragment_root = unit if unit.is_dir() else unit.parent
                    for node in fragment.nodes:
                        if node.file and not Path(node.file).is_absolute():
                            node.file = (fragment_root/node.file).as_posix()
                    fragments.append(fragment)
                if len({fragment.backend for fragment in fragments}) != 1:
                    raise ValueError('Mixed backend fragments cannot form one condition')
                graph = NormalizedGraph(backend=fragments[0].backend,root=(args.source_root/ident).resolve().as_posix(),
                    nodes=[node for fragment in fragments for node in fragment.nodes],
                    edges=[edge for fragment in fragments for edge in fragment.edges],
                    export_metadata={'graph_scope':'candidate-files','cross_file_edges':False,
                                     'translation_units':[unit.relative_to(args.source_root.resolve()).as_posix() for unit in sorted(units)],
                                     'dfg_truncated':any(fragment.export_metadata.get('dfg_truncated',False) for fragment in fragments),
                                     'fragment_metadata':[fragment.export_metadata for fragment in fragments]})
            if not graph.nodes:
                raise CpgLoadError('Empty graph for a project with declared candidate sites')
            write_graph_json(graph, project_out / 'graph.json')
            graph_index[ident] = f'../../{ident}/graph.json'
            paths = {entry['source']: args.source_root / entry['source'] for entry in entries}
            source_only = {source: analyze_key_origins(path) for source, path in paths.items()}
            with_graph = {source: analyze_key_origins(path, graph) for source, path in paths.items()}
            rows = []
            for entry in entries:
                path = paths[entry['source']]
                direct = direct_expression_claim(path, entry)
                conditions = {'direct_expression': [direct] if direct else [],
                              'source_only': source_only[entry['source']], 'graph_context': with_graph[entry['source']]}
                row = {'case_id': entry['case_id'], 'target': entry['target'], 'target_api': entry['target_api'], 'conditions': {}}
                for condition, claims in conditions.items():
                    selected = [claim for claim in claims if claim.target.model_dump() == entry['target'] and claim.target_api == entry['target_api']]
                    row['conditions'][condition] = {'outcome': selected[0].status if len(selected) == 1 else 'missing' if not selected else 'ambiguous',
                        'claims': [{'claim': claim.model_dump(), 'structural_errors': audit_claim_structure(claim, path, graph if condition == 'graph_context' else None)} for claim in selected]}
                rows.append(row)
                for condition, result in row['conditions'].items():
                    condition_outputs[condition].append({'case_id': entry['case_id'], 'scan_status': 'completed', 'evidence_policy': result['claims']})
            write_json(project_out / 'sites.json', {'annotation_status': 'pending', 'cases': rows})
            if args.dfg_probe:
                probes = [probe_key_paths(paths[entry['source']], entry, graph) for entry in entries]
                write_json(project_out / 'dfg-probes.json', {'scope': 'Syntactic seeds and bounded exported dependency paths only.', 'cases': probes})
            counts = {condition: dict(Counter(row['conditions'][condition]['outcome'] for row in rows)) for condition in ('direct_expression', 'source_only', 'graph_context')}
            record['projects'][ident] = {'status': 'completed', 'actual_backend': graph.backend, 'eligible_candidates': len(entries), 'conditions': counts,
                                         'export_metadata': graph.export_metadata}
            print(f'{ident}: {counts}', flush=True)
        except (CpgLoadError, ValueError, OSError, SyntaxError, TypeError, KeyError) as exc:
            failures = True
            graph_index.pop(ident, None)
            record['projects'][ident] = {'status': 'failed', 'error': str(exc), 'eligible_candidates': len(entries)}
            for condition in condition_outputs:
                # Discard any partial records from this failed project.
                condition_outputs[condition] = [item for item in condition_outputs[condition] if item['case_id'] not in {entry['case_id'] for entry in entries}]
                condition_outputs[condition].extend({'case_id': entry['case_id'], 'scan_status': 'failed', 'evidence_policy': []} for entry in entries)
            print(f'{ident}: scan failed; see run.json', file=sys.stderr, flush=True)
        write_json(out / 'run.json', record)
    changed = [name for name, digest in hashes.items() if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest]
    if changed:
        failures = True
        record['changed_inputs_during_run'] = changed
    record['status'] = 'failed' if failures else 'completed'
    for condition, cases in condition_outputs.items():
        folder=out/'conditions'/condition
        write_json(folder/'observations.json', {'analysis_model': packet['analysis_model'], 'policy': 'direct' if condition=='direct_expression' else 'evidence',
                                               'annotation_status': 'review_recorded_not_verified_by_software' if args.phase=='reviewed-evaluation' else 'pending_candidate_and_origin_review', 'cases': cases})
        if condition=='graph_context':
            write_json(folder/'graph-index.json', {'graphs': graph_index})
    write_json(out / 'run.json', record)
    return 2 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
