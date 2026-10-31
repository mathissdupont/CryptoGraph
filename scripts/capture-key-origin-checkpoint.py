"""Capture completed development runs without turning predictions into labels."""
from __future__ import annotations

import argparse
import hashlib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from cryptograph.utils import load_json, write_json

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_inputs(record):
    for name, expected in record['inputs_sha256'].items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or digest(path) != expected:
            raise ValueError(f'Run does not match the current source snapshot: {name}')


def project_observations(folder, backend):
    record = load_json(folder/'run.json')
    if record['status'] != 'completed' or record['requested_backend'] != backend:
        raise ValueError('Expected a completed project run with the declared backend')
    current_inputs(record)
    cases = []
    totals = {name: Counter() for name in ('direct_expression','source_only','graph_context')}
    for project, details in record['projects'].items():
        expected = 'ast-lite' if backend == 'ast-lite' else 'fraunhofer-cpg'
        if details['status'] != 'completed' or details['actual_backend'] != expected:
            raise ValueError('A failed project or backend substitution cannot be a completed observation')
        for row in load_json(folder/project/'sites.json')['cases']:
            results = {}
            for name, result in row['conditions'].items():
                totals[name][result['outcome']] += 1
                results[name] = {
                    'outcome': result['outcome'],
                    'claims': [{key: item['claim'][key] for key in (
                        'status','origins','origin_set_complete','modality',
                        'immediate_boundary','unresolved_reasons','graph_features_used')}
                        | {'structural_errors': item['structural_errors']} for item in result['claims']],
                }
            cases.append({'case_id': row['case_id'], 'conditions': results})
    return {'run': record, 'totals': {name: dict(counts) for name, counts in totals.items()}, 'cases': cases}


def path_observations(folder):
    # Omit raw node IDs/code; complete paths remain in the hashed raw artifacts.
    observations = load_json(folder/'dfg-probes.json')
    return [{'case_id': row['case_id'], 'status': row['status'],
             'export_metadata': row['export_metadata'],
             'seeds': [{key: seed[key] for key in ('category','line','column','status')}
                       | {'path_edges': len(seed.get('edges', []))} for seed in row['seeds']]}
            for row in observations['cases']]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('matrix','project-ast','project-cpg','cbomkit','exporter'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--runtime-image-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Use a new checkpoint path; do not overwrite a previous experiment.')
    try:
        matrix = load_json(args.matrix/'matrix.json')
        if matrix['status'] != 'completed' or not matrix['matched_input_hashes'] or not matrix['matched_candidate_sites']:
            raise ValueError('Expected completed, matched development conditions')
        current_inputs(matrix)
        if digest(ROOT/'scripts/run-key-origin-matrix.py') != matrix['matrix_script_sha256']:
            raise ValueError('Matrix runner changed after the experiment')
        projects = {name: project_observations(folder, backend) for name, folder, backend in (
            ('ast',args.project_ast,'ast-lite'),('cpg',args.project_cpg,'fraunhofer-strict'))}
        candidate_ids = {entry['case_id'] for entry in load_json(ROOT/'research/python-key-origin/project-review-template.json')['cases']}
        for observation in projects.values():
            ids = [row['case_id'] for row in observation['cases']]
            if len(ids) != len(set(ids)) or set(ids) != candidate_ids:
                raise ValueError('Project observations do not match the candidate inventory')
        jar_hash = digest(args.exporter)
        if (matrix['cells']['cpg_calls']['exporter_sha256'] != jar_hash
            or projects['cpg']['run']['exporter_sha256'] != jar_hash):
            raise ValueError('The project/matrix exporter snapshots differ')
        native = load_json(args.cbomkit/'run.json')
        if (native['status'] != 'completed'
            or native['manifest_sha256'] != digest(ROOT/'research/python-key-origin/project-corpus.json')
            or native['adapter_sha256'] != digest(ROOT/'scripts/observe-cbomkit.py')):
            raise ValueError('Native inventory is incomplete or uses a different input/adapter snapshot')
        matrix_cases = {}
        for condition in matrix['cells']:
            observations = load_json(args.matrix/condition/'observations.json')
            matrix_cases[condition] = [
                {'case_id': row['case_id'], 'claims': [
                    {key: item['claim'][key] for key in (
                        'status','origins','origin_set_complete','modality','immediate_boundary',
                        'unresolved_reasons','graph_features_used')}
                    | {'structural_errors': item['structural_errors']} for item in row['evidence_policy']]}
                for row in observations['cases']]
        raw_artifacts = {}
        for name in ('matrix','project_ast','project_cpg','cbomkit'):
            folder = getattr(args,name)
            raw_artifacts[name] = {path.relative_to(folder).as_posix(): digest(path)
                                   for path in sorted(folder.rglob('*')) if path.is_file()}
        record = {
            'kind': 'unreviewed_development_feasibility_checkpoint',
            'generated_at': datetime.now(UTC).isoformat(),
            'scope': 'Designed programs and convenience project slices; no independent accuracy, held-out, generalization or novelty conclusion.',
            'independent_review': 'pending', 'reviewed_accuracy': None,
            'runtime_image_id': args.runtime_image_id,
            'runtime_note': 'Existing image with the current checkout mounted read only and its exporter overridden by the recorded JAR.',
            'exporter_sha256': jar_hash, 'matrix': matrix, 'matrix_cases': matrix_cases,
            'designed_dfg_observations': path_observations(args.matrix/'cpg_calls'),
            'project_observations': projects, 'native_inventory': native,
            'raw_artifacts_sha256': raw_artifacts,
        }
        write_json(args.output, record)
    except (ValueError, KeyError, OSError, TypeError) as exc:
        parser.exit(3, f'Invalid checkpoint inputs: {exc}\n')
    print(f'Captured unreviewed development observations in {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
