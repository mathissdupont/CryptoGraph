"""DFG direction, anchoring and truncation mechanics; not semantic ground truth."""
import ast
import hashlib

import pytest

from cryptograph.dfg_probe import directed_path, probe_key_paths
from cryptograph.models import GraphEdge, GraphNode, NormalizedGraph


def graph(edges=()):
    return NormalizedGraph(backend='fraunhofer-cpg', root='.', nodes=[GraphNode(id=name, kind='dfg', file='f.py') for name in ('source', 'middle', 'key')],
                           edges=[GraphEdge(source=a, target=b, kind=kind) for a,b,kind in edges])


def test_only_forward_dfg_paths_are_admissible():
    value = graph([('source','middle','DFG'),('middle','key','DFG')])
    assert len(directed_path(value, 'source','key')['edges']) == 2
    assert directed_path(value,'key','source')['status'] == 'no_exported_path'
    value.edges[0].kind = 'CALLS'
    assert directed_path(value,'source','key')['status'] == 'no_exported_path'


def test_dfg_cycles_and_search_limits_remain_explicit():
    value = graph([('source','middle','DFG'),('middle','source','DFG'),('middle','key','DFG')])
    assert directed_path(value,'source','key',max_hops=1)['status'] == 'search_limit'
    value.export_metadata['dfg_truncated'] = True
    assert directed_path(value,'key','source')['status'] == 'inconclusive_truncated_export'
    assert directed_path(value,'source','source')['status'] == 'same_node'
    with pytest.raises(ValueError):
        directed_path(value, 'outside','key')


def test_probe_requires_unique_source_call_and_argument_anchors(tmp_path):
    path = tmp_path/'f.py'
    path.write_bytes(b'from Crypto.Cipher import AES\nkey = b"fixed"\nAES.new(key, 1)\n')
    call = next(node for node in ast.walk(ast.parse(path.read_text())) if isinstance(node,ast.Call))
    entry = {'case_id':'fixture','source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
             'target':dict(file='f.py',line=3,column=0,end_line=3,end_column=15)}
    value = NormalizedGraph(backend='fraunhofer-cpg',root=str(tmp_path),nodes=[
        GraphNode(id='call',kind='call',file='f.py',line=3,properties={'raw_code':'AES.new(key, 1)'}),
        GraphNode(id='key',kind='argument',file='f.py',line=3,properties={'code':'key'}),
        GraphNode(id='literal',kind='dfg',file='f.py',line=2,properties={'code':'b"fixed"'}),
    ],edges=[GraphEdge(source='call',target='key',kind='AST_ARGUMENT_0'),GraphEdge(source='literal',target='key',kind='DFG')])
    result=probe_key_paths(path,entry,value)
    assert result['status']=='observed' and result['seeds'][0]['status']=='exported_path'
    value.nodes.append(value.nodes[0].model_copy(update={'id':'duplicate'}))
    assert probe_key_paths(path,entry,value)['status']=='ambiguous_target_anchor'
    value.nodes.pop()
    value.nodes[1].file='other.py'
    assert probe_key_paths(path,entry,value)['status']=='missing_key_anchor'


def test_probe_never_invents_dfg_support_for_ast_backend(tmp_path):
    path=tmp_path/'f.py'
    path.write_bytes(b'AES.new(key, 1)\n')
    entry={'case_id':'fixture','source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'target':{}}
    assert probe_key_paths(path,entry,NormalizedGraph(backend='ast-lite',root=str(tmp_path)))['status']=='unsupported_backend'
