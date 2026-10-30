"""Freeze current methods and reserved candidate identities; run no analyzer."""
import argparse
import hashlib
from datetime import UTC, datetime
from pathlib import Path

from cryptograph.research_freeze import candidate_fingerprint, check_freeze
from cryptograph.utils import load_json, write_json

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--annotations',type=Path,default=ROOT/'research/python-key-origin/reserved-review-template.json')
    parser.add_argument('--development-manifest',type=Path,default=ROOT/'research/python-key-origin/project-corpus.json')
    parser.add_argument('--reserved-manifest',type=Path,default=ROOT/'research/python-key-origin/reserved-corpus.json')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Use a new freeze path; preserve previous snapshots.')
    packet = load_json(args.annotations)
    development = load_json(args.development_manifest)
    reserved = load_json(args.reserved_manifest)
    if {project['repository'] for project in development['projects']} & {project['repository'] for project in reserved['projects']}:
        parser.error('Development and reserved projects overlap.')
    inputs = [*ROOT.joinpath('src/cryptograph').glob('*.py'),
              *ROOT.joinpath('scripts').glob('*key-origin*.py'), ROOT/'scripts/research-pilot.py',
              ROOT/'scripts/observe-cbomkit.py', *ROOT.joinpath('config').glob('*.json'),
              ROOT/'Dockerfile', ROOT/'requirements.txt', ROOT/'pyproject.toml',
              ROOT/'tools/fraunhofer-exporter/src/main/kotlin/io/cryptograph/exporter/Main.kt',
              ROOT/'tools/fraunhofer-exporter/build.gradle.kts',
              ROOT/'tools/fraunhofer-exporter/settings.gradle.kts',
              ROOT/'docs/RESEARCH.md', ROOT/'research/python-key-origin/CONTRACT.md',
              ROOT/'research/python-key-origin/claim.schema.json',
              ROOT/'research/python-key-origin/project-corpus.json',
              ROOT/'research/python-key-origin/reserved-corpus.json']
    inputs.extend([args.development_manifest.resolve(),args.reserved_manifest.resolve(),
                   ROOT/'research/python-key-origin/repository-selection-2026-10-30.json'])
    record = {
        'status': 'methods_and_reserved_candidate_snapshot_only',
        'generated_at': datetime.now(UTC).isoformat(),
        'scope': 'Snapshot after development experiments and nominal reserved indexing; not a preregistration, reviewed test set or completed evaluation.',
        'reserved_origin_analysis_executed': False,
        'independent_review': 'pending',
        'reserved_candidate_count': len(packet['cases']),
        'annotation_file': args.annotations.resolve().relative_to(ROOT).as_posix(),
        'reserved_manifest_file': args.reserved_manifest.resolve().relative_to(ROOT).as_posix(),
        'candidate_fingerprint': candidate_fingerprint(packet),
        'method_fingerprint_encoding': 'SHA-256 of file bytes with CRLF normalized to LF; resource hashes remain raw bytes.',
        'method_inputs_sha256': {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes().replace(b'\r\n',b'\n')).hexdigest()
                                 for path in sorted(set(inputs))},
    }
    check_freeze(record, packet, ROOT, require_review=False)
    write_json(args.output, record)
    print('Methods and candidate identities frozen; no origin analyzer or evaluation ran.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
