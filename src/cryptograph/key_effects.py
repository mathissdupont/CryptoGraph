"""Bounded binding-effect summaries, separate from key-value inference.

These contracts assume plain builtin scalar inputs and nominal unmodified APIs.
They certify no modeled mutation of caller bindings, not a helper's return origin,
termination, graph completeness, arbitrary Python protocol effects or security.
"""
from __future__ import annotations

import ast

PRIMITIVE_CALLS={'builtin:len','builtin:bytes','builtin:str','builtin:range'}
HASH_PREFIX='cryptography.hazmat.primitives.hashes.'
HASH_ALGORITHMS={HASH_PREFIX+name for name in ('SHA1','SHA224','SHA256','SHA384','SHA512','MD5')}
BACKEND='cryptography.hazmat.backends.default_backend'


def safe_default(node):
    if isinstance(node,(ast.Constant,ast.Name)):
        return True
    if isinstance(node,ast.UnaryOp) and isinstance(node.op,(ast.UAdd,ast.USub)) and isinstance(node.operand,ast.Constant):
        return isinstance(node.operand.value,(int,float,complex))
    return False


def plain_class(node, postponed_annotations):
    if node.bases or node.keywords or node.decorator_list:
        return False
    for statement in node.body:
        if isinstance(statement,ast.Pass) or isinstance(statement,ast.Expr) and isinstance(statement.value,ast.Constant):
            continue
        if not isinstance(statement,ast.FunctionDef) or statement.decorator_list:
            return False
        defaults=[*statement.args.defaults,*[value for value in statement.args.kw_defaults if value is not None]]
        parameters=[*statement.args.posonlyargs,*statement.args.args,*statement.args.kwonlyargs]
        parameters.extend(arg for arg in (statement.args.vararg,statement.args.kwarg) if arg is not None)
        annotations=[statement.returns,*[arg.annotation for arg in parameters]]
        if any(not safe_default(value) for value in defaults):
            return False
        if not postponed_annotations and any(value is not None and not isinstance(value,(ast.Name,ast.Constant)) for value in annotations):
            return False
    return True


def binding_effect_summary(function, bindings, functions, active=()):
    if function.name in active or len(active)>=4 or function.decorator_list:
        return None
    parameters=[*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs]
    if function.args.vararg or function.args.kwarg:
        return None
    env=dict(bindings)
    for node in ast.walk(function):
        if isinstance(node,ast.Name) and isinstance(node.ctx,(ast.Store,ast.Del)):
            env[node.id]=None
    env.update({arg.arg:'primitive' for arg in parameters})
    contracts=set()

    def expression(node, scope):
        if node is None or isinstance(node,ast.Constant):
            return 'primitive'
        if isinstance(node,ast.Name):
            return scope.get(node.id)
        if isinstance(node,ast.Attribute):
            base=expression(node.value,scope)
            if base=='hash_object' and node.attr in {'update','finalize'}:
                return 'hash_method:'+node.attr
            if base and base not in {'primitive','hash_object','hash_algorithm','backend','pure_range'} and not base.startswith(('builtin:','local:')):
                return base+'.'+node.attr
            return None
        if isinstance(node,ast.BinOp):
            return 'primitive' if expression(node.left,scope)==expression(node.right,scope)=='primitive' else None
        if isinstance(node,ast.UnaryOp):
            return 'primitive' if expression(node.operand,scope)=='primitive' else None
        if isinstance(node,ast.Compare):
            return 'primitive' if all(expression(value,scope)=='primitive' for value in (node.left,*node.comparators)) else None
        if isinstance(node,ast.BoolOp):
            return 'primitive' if all(expression(value,scope)=='primitive' for value in node.values) else None
        if isinstance(node,ast.Call):
            if any(isinstance(arg,ast.Starred) for arg in node.args) or any(kw.arg is None for kw in node.keywords):
                return None
            callee=expression(node.func,scope)
            args=[expression(arg,scope) for arg in node.args]
            kwargs={kw.arg:expression(kw.value,scope) for kw in node.keywords}
            if None in args or None in kwargs.values():
                return None
            if callee in PRIMITIVE_CALLS and all(arg=='primitive' for arg in [*args,*kwargs.values()]):
                contracts.add(callee)
                return 'pure_range' if callee=='builtin:range' else 'primitive'
            if callee in HASH_ALGORITHMS and not args and not kwargs:
                contracts.add(callee);return 'hash_algorithm'
            if callee==BACKEND and not args and not kwargs:
                contracts.add(callee);return 'backend'
            if callee==HASH_PREFIX+'Hash' and args==['hash_algorithm'] and set(kwargs)<={'backend'} and all(value=='backend' for value in kwargs.values()):
                contracts.add(callee);return 'hash_object'
            if callee=='hash_method:update' and args==['primitive'] and not kwargs:
                contracts.add('Hash.update');return 'primitive'
            if callee=='hash_method:finalize' and not args and not kwargs:
                contracts.add('Hash.finalize');return 'primitive'
            if callee in {'os.urandom','secrets.token_bytes'} and all(value=='primitive' for value in [*args,*kwargs.values()]):
                contracts.add(callee);return 'primitive'
            if callee and callee.startswith('local:'):
                helper=functions.get(callee[6:])
                if helper is None or any(value!='primitive' for value in [*args,*kwargs.values()]):
                    return None
                nested=binding_effect_summary(helper,bindings,functions,active+(function.name,))
                if nested is not None:
                    contracts.update(nested);contracts.add(callee);return 'primitive'
            return None
        return None

    def block(body, scope):
        for statement in body:
            if isinstance(statement,(ast.Assign,ast.AnnAssign)):
                targets=statement.targets if isinstance(statement,ast.Assign) else [statement.target]
                value=expression(statement.value,scope)
                if value is None or any(not isinstance(target,ast.Name) for target in targets):
                    return False
                for target in targets:scope[target.id]=value
            elif isinstance(statement,ast.Expr):
                if expression(statement.value,scope) is None:return False
            elif isinstance(statement,ast.Return):
                if expression(statement.value,scope) is None:return False
            elif isinstance(statement,ast.For):
                if not isinstance(statement.target,ast.Name) or expression(statement.iter,scope)!='pure_range':return False
                scope[statement.target.id]='primitive'
                if not block(statement.body,scope) or not block(statement.orelse,scope):return False
            elif isinstance(statement,ast.If):
                if expression(statement.test,scope)!='primitive':return False
                left,right=dict(scope),dict(scope)
                if not block(statement.body,left) or not block(statement.orelse,right):return False
                scope.update({name:left.get(name) if left.get(name)==right.get(name) else None for name in set(left)|set(right)})
            elif not isinstance(statement,ast.Pass):
                return False
        return True

    return tuple(sorted(contracts)) if block(function.body,env) else None
