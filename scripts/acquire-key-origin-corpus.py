"""Verify cached project files, or explicitly download their exact pinned bytes."""
import argparse
import hashlib
from pathlib import Path
from urllib.request import Request, urlopen

from cryptograph.research_corpus import materialize_corpus
from cryptograph.utils import load_json, write_json


def download(url):
    with urlopen(Request(url, headers={'User-Agent': 'CryptoGraph-research-corpus/0.1'}), timeout=45) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('Source resource exceeds the acquisition limit')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=Path('research/python-key-origin/project-corpus.json'))
    parser.add_argument('--root', type=Path, default=Path('output/python-project-sources'))
    parser.add_argument('--fetch', action='store_true', help='Allow downloads from the pinned raw GitHub URLs.')
    args = parser.parse_args()
    try:
        record = materialize_corpus(load_json(args.manifest), args.root, download if args.fetch else None)
    except (OSError, ValueError, SyntaxError, KeyError) as exc:
        parser.exit(2, f'Corpus acquisition failed: {exc}\n')
    record['manifest_sha256'] = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    write_json(args.root / 'acquisition.json', record)
    print(f"Verified {len(record['resources'])} pinned source/license files; target code was not executed.")


if __name__ == '__main__':
    main()
