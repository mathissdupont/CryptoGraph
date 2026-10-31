"""Capture expanded development diagnostics, keeping reserved predictions absent."""
import argparse
import hashlib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from cryptograph.utils import load_json, write_json

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,required=True)
    parser.add_argument('--ast',type=Path,required=True)
    parser.add_argument('--cpg',type=Path,required=True)
    parser.add_argument('--matrix',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Use a fresh record path')
    packet=load_json(args.dataset/'development-review-template.json')
    expected={entry['case_id'] for entry in packet['cases']}
    report={'kind':'expanded_unreviewed_development_observations','generated_at':datetime.now(UTC).isoformat(),
            'analysis_model':packet['analysis_model'],
            'scope':'Descriptive development output, not semantic accuracy, a generalization estimate or a completed comparative paper.',
            'population':load_json(args.dataset/'population.json'),
            'independent_review':'pending','reviewed_accuracy':None,'reserved_origin_analysis_executed':False,
            'conditions':{},'raw_artifacts_sha256':{}}
    for name,folder in [('ast',args.ast),('cpg',args.cpg)]:
        run=load_json(folder/'run.json')
        if run['status']!='completed' or run.get('graph_scope')!='candidate-files':
            parser.error('Expected completed matched candidate-translation-unit development scans')
        for filename,digest in run['inputs_sha256'].items():
            if hashlib.sha256((ROOT/filename).read_bytes()).hexdigest()!=digest:
                parser.error('Source/code changed after scan: '+filename)
        cases=[];counts={condition:Counter() for condition in ('direct_expression','source_only','graph_context')}
        reasons=Counter()
        for project,status in run['projects'].items():
            if status['status']=='no_candidates':
                continue
            for row in load_json(folder/project/'sites.json')['cases']:
                case={'case_id':row['case_id'],'conditions':{}}
                for condition,result in row['conditions'].items():
                    counts[condition][result['outcome']]+=1
                    summaries=[]
                    for item in result['claims']:
                        claim=item['claim']
                        if claim['analysis_model']!=packet['analysis_model']:
                            parser.error('Observation and candidate semantic models differ')
                        summaries.append({field:claim[field] for field in ('status','origins','origin_set_complete','modality','immediate_boundary','unresolved_reasons','graph_features_used')}
                                         | {'structural_errors':item['structural_errors']})
                        if condition=='source_only':
                            reasons.update(set(claim['unresolved_reasons']))
                    case['conditions'][condition]={'outcome':result['outcome'],'claims':summaries}
                cases.append(case)
        if len(cases)!=len(expected) or {case['case_id'] for case in cases}!=expected:
            parser.error('Observed cases differ from the fixed candidate inventory')
        report['conditions'][name]={'run':run,'outcomes':{condition:dict(counts[condition]) for condition in counts},
                                    'source_only_reason_counts':dict(reasons.most_common()),'cases':cases}
        report['raw_artifacts_sha256'][name]={path.relative_to(folder).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
                                               for path in sorted(folder.rglob('*')) if path.is_file()}
    ast_projects=report['conditions']['ast']['run']['projects']
    cpg_projects=report['conditions']['cpg']['run']['projects']
    if set(ast_projects)!=set(cpg_projects):
        parser.error('Backend project populations differ')
    for project in ast_projects:
        left=ast_projects[project];right=cpg_projects[project]
        if left.get('export_metadata',{}).get('translation_units') != right.get('export_metadata',{}).get('translation_units'):
            parser.error('AST/CPG translation units differ for '+project)
    matrix=load_json(args.matrix/'matrix.json')
    if matrix['status']!='completed' or not matrix['matched_input_hashes'] or not matrix['matched_candidate_sites']:
        parser.error('Expected a completed matched designed matrix')
    for filename,digest in matrix['inputs_sha256'].items():
        if hashlib.sha256((ROOT/filename).read_bytes()).hexdigest()!=digest:
            parser.error('Matrix source/code changed: '+filename)
    report['designed_matrix']=matrix
    report['raw_artifacts_sha256']['matrix']={path.relative_to(args.matrix).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
                                            for path in sorted(args.matrix.rglob('*')) if path.is_file()}
    write_json(args.output,report)
    print('Expanded development records captured; no reserved origin evaluation or accuracy calculation ran.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
