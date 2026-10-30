"""Acquire pinned source blobs and index candidates without executing target code."""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from cryptograph.key_origin import MODEL
from cryptograph.research_inventory import index_python_source
from cryptograph.utils import load_json, write_json

EXCLUDED = {'test','tests','selftest','testing','docs','doc','examples','example','benchmarks','benchmark','vendor','vendored','_vendor'}


def git(repository, *arguments, input=None):
    return subprocess.run(['git','-c','core.hooksPath='+str(repository/'.disabled-hooks'),
                           '-c','core.fsmonitor=false','-C',str(repository),*arguments],
                          input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=180).stdout


def acquire(project, cache, fetch):
    ident, repository, revision = project['id'], project['repository'], project['revision']
    if not re.fullmatch(r'[a-z][a-z0-9_]*',ident) or not re.fullmatch(r'https://github.com/[\w.-]+/[\w.-]+',repository) or not re.fullmatch(r'[0-9a-f]{40}',revision):
        raise ValueError('Expected a safe identifier, public GitHub URL and full pinned commit')
    store = cache/'.git-stores'/ident
    if not store.resolve().is_relative_to(cache.resolve()):
        raise ValueError('Git store escaped source cache')
    if not store.exists():
        if not fetch:
            raise ValueError('Missing source store; use --fetch to acquire pinned public blobs')
        store.mkdir(parents=True)
        subprocess.run(['git','init','--bare',str(store)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        git(store,'cat-file','-e',revision+'^{commit}')
    except subprocess.CalledProcessError:
        if not fetch:
            raise ValueError('Pinned commit absent; use --fetch')
        git(store,'fetch','--depth=1','--no-tags',repository,revision)
    if git(store,'rev-parse',revision+'^{commit}').decode().strip() != revision:
        raise ValueError('Fetched commit differs from catalog')
    entries = git(store,'ls-tree','-rz','--long',revision).split(b'\0')
    selected, exclusions = [], Counter()
    for entry in entries:
        if not entry:
            continue
        header, name = entry.split(b'\t',1)
        mode, kind, blob, size = header.decode().split()
        name = name.decode('utf-8')
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
            raise ValueError('Unsafe repository path')
        if mode not in {'100644','100755'} or kind != 'blob':
            exclusions['nonregular_entry'] += 1
            continue
        license_file = len(path.parts)==1 and re.match(r'^(LICENSE|COPYING|NOTICE|AUTHORS)([._-].*)?$',path.name,re.I)
        source_file = name.endswith('.py') and any(name.startswith(prefix) for prefix in project['source_roots'])
        if source_file and (any(part.lower() in EXCLUDED for part in path.parts) or path.name.startswith('test_') or path.name.endswith('_test.py')):
            exclusions['test_documentation_or_vendor_python'] += 1
            source_file = False
        if not (source_file or license_file):
            continue
        if int(size)>2*1024*1024:
            raise ValueError('Selected source/license exceeds the declared 2 MiB resource limit')
        selected.append((name,blob,int(size),'source' if source_file else 'license'))
    if len(selected)>5000 or sum(item[2] for item in selected)>64*1024*1024:
        raise ValueError('Source population exceeds declared acquisition limits; do not silently truncate')
    raw = git(store,'cat-file','--batch',input=''.join(blob+'\n' for _,blob,_,_ in selected).encode())
    cursor, resources, cases, indirect, ambiguous, errors = 0, [], [], [], [], []
    for name,blob,size,kind in selected:
        end=raw.index(b'\n',cursor)
        actual_blob,actual_kind,actual_size=raw[cursor:end].decode().split()
        if (actual_blob,actual_kind,int(actual_size)) != (blob,'blob',size):
            raise ValueError('Blob stream disagrees with pinned tree')
        content=raw[end+1:end+1+size];cursor=end+size+2
        path=(cache/ident/name).resolve()
        if not path.is_relative_to((cache/ident).resolve()) or not path.is_relative_to(cache.resolve()):
            raise ValueError('Resource escaped source root')
        if path.exists() and path.read_bytes()!=content:
            raise ValueError('Changed cached source must not be overwritten')
        path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists():
            path.write_bytes(content)
        resources.append({'path':name,'kind':kind,'url':f'https://raw.githubusercontent.com/{repository.removeprefix("https://github.com/")}/{revision}/{quote(name,safe="/")}',
                          'sha256':hashlib.sha256(content).hexdigest(),'bytes':size})
        if kind=='source':
            try:
                indexed=index_python_source(content,ident+'/'+name,ident,project['split'])
                cases.extend(indexed['cases'])
                indirect.extend(dict(item,source=ident+'/'+name) for item in indexed['indirect_references'])
                ambiguous.extend(dict(item,source=ident+'/'+name) for item in indexed['ambiguous_import_calls'])
            except (SyntaxError,UnicodeError,ValueError) as exc:
                errors.append({'source':name,'error':str(exc)})
    if not any(resource['kind']=='license' for resource in resources):
        raise ValueError('No top-level license record acquired; catalog needs source/license review')
    return dict(project,resources=resources),cases,{
        'status':'indexed_with_parse_failures' if errors else 'indexed',
        'source_files':sum(item['kind']=='source' for item in resources),'license_files':sum(item['kind']=='license' for item in resources),
        'candidate_sites':len(cases),'indirect_references':indirect,'ambiguous_import_calls':ambiguous,'parse_failures':errors,'exclusions':dict(exclusions),
        'origin_analysis_executed':False,'target_execution':False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--out-dir',type=Path,required=True)
    parser.add_argument('--fetch',action='store_true')
    args=parser.parse_args()
    if args.out_dir.exists():
        parser.error('Use a fresh screening directory')
    catalog=load_json(args.catalog)
    args.out_dir.mkdir(parents=True)
    record={'status':'started','catalog_sha256':hashlib.sha256(args.catalog.read_bytes()).hexdigest(),
            'selector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scope':'Predeclared convenience projects/source roots; nominal candidate indexing only, not origin evaluation or exhaustive detection recall.',
            'projects':{},'excluded_projects':catalog.get('excluded_projects',[])}
    manifests={split:{'scope':'Pinned non-test Python source population from predeclared roots; not dependency-complete checkouts.', 'projects':[]}
               for split in ('development','evaluation_reserved')}
    packets={split:{'analysis_model':MODEL,'status':'candidate_inventory_not_ground_truth','cases':[]}
             for split in manifests}
    failed=False
    for project in catalog['projects']:
        try:
            manifest,cases,details=acquire(project,args.source_root.resolve(),args.fetch)
            split=project['split']
            manifests[split]['projects'].append(manifest);packets[split]['cases'].extend(cases)
            record['projects'][project['id']]=details
            print(f"{project['id']}: {details['source_files']} source files, {details['candidate_sites']} nominal call sites; no origin analysis",flush=True)
        except (ValueError,OSError,subprocess.SubprocessError) as exc:
            failed=True;record['projects'][project['id']]={'status':'failed','error':str(exc)}
            print(f"{project['id']}: acquisition/index failed; retained in screening log",flush=True)
        write_json(args.out_dir/'screening.json',record)
    for split in manifests:
        write_json(args.out_dir/(split+'-corpus.json'),manifests[split])
        write_json(args.out_dir/(split+'-review-template.json'),packets[split])
    record['status']='failed' if failed else 'completed'
    write_json(args.out_dir/'screening.json',record)
    return 2 if failed else 0


if __name__=='__main__':
    raise SystemExit(main())
