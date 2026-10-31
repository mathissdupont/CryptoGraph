"""Combine acquired populations without changing historical corpus records."""
import argparse
import hashlib
import shutil
from pathlib import Path

from cryptograph.key_origin import MODEL
from cryptograph.research_corpus import materialize_corpus
from cryptograph.utils import load_json, write_json

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--screening',type=Path,required=True)
    parser.add_argument('--screened-sources',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--out-dir',type=Path,required=True)
    args=parser.parse_args()
    if args.out_dir.exists():
        parser.error('Preserve previous dataset records; use a fresh output directory')
    screening=load_json(args.screening/'screening.json')
    if screening['status']!='completed':
        parser.error('Incomplete screening cannot silently become a complete study population')
    args.out_dir.mkdir(parents=True)
    repositories=set()
    summary={'scope':'Convenience development/reserved populations; older project slices and newly selected whole source roots are distinguished by provenance.',
             'independent_review':'pending','reserved_origin_analysis_executed':False,'splits':{}}
    for split,old_manifest,old_packet,old_sources in (
        ('development','project-corpus.json','project-review-template.json','output/python-project-sources'),
        ('evaluation_reserved','reserved-corpus.json','reserved-review-template.json','output/reserved-project-sources')):
        old=load_json(ROOT/'research/python-key-origin'/old_manifest)
        new=load_json(args.screening/(split+'-corpus.json'))
        packet={'analysis_model':MODEL,'status':'candidate_inventory_not_ground_truth','cases':
                load_json(ROOT/'research/python-key-origin'/old_packet)['cases']+load_json(args.screening/(split+'-review-template.json'))['cases']}
        manifest={'scope':summary['scope'],'projects':old['projects']+new['projects']}
        for subset,cache in ((old,ROOT/old_sources),(new,args.screened_sources)):
            for project in subset['projects']:
                if project['repository'] in repositories:
                    parser.error('Repository overlap between old/new projects or splits')
                repositories.add(project['repository'])
                project['split']=split
                project.setdefault('selection_unit','historically_selected_complete_files')
                if 'source_roots' in project:
                    project['selection_unit']='all_non_test_python_under_predeclared_roots'
                for resource in project['resources']:
                    original=cache/project['id']/resource['path']
                    if hashlib.sha256(original.read_bytes()).hexdigest()!=resource['sha256']:
                        parser.error('Source changed since acquisition')
                    destination=args.source_root/project['id']/resource['path']
                    if destination.exists() and destination.read_bytes()!=original.read_bytes():
                        parser.error('Changed source cache must not be overwritten')
                    destination.parent.mkdir(parents=True,exist_ok=True)
                    if not destination.exists():
                        shutil.copyfile(original,destination)
        materialize_corpus(manifest,args.source_root)
        write_json(args.out_dir/(split+'-corpus.json'),manifest)
        write_json(args.out_dir/(split+'-review-template.json'),packet)
        summary['splits'][split]={'projects':len(manifest['projects']),'nominal_candidates':len(packet['cases']),
            'source_files':sum(resource['kind']=='source' for project in manifest['projects'] for resource in project['resources'])}
    shutil.copyfile(args.screening/'screening.json',args.out_dir/'screening.json')
    write_json(args.out_dir/'population.json',summary)
    print(summary['splits'])
    return 0


if __name__=='__main__':
    raise SystemExit(main())
