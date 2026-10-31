"""Bounded, source-aware key-origin inference for the research experiment.

This interpreter reads Python syntax; it never imports or executes target code.
It is deliberately separate from the legacy CBOM heuristic so both policies can
be recorded on the same inputs. Results are claims under a declared model, not
a soundness proof or an assessment that a key is secure.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cryptograph.models import GraphEdge, NormalizedGraph
from cryptograph.key_effects import PRIMITIVE_CALLS, binding_effect_summary, plain_class, safe_default


MODEL = "python-key-origin-subset-v0.2"
TARGETS = {
    "Crypto.Cipher.AES.new", "Cryptodome.Cipher.AES.new",
    "cryptography.hazmat.primitives.ciphers.algorithms.AES",
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
}
RANDOM_APIS = {"os.urandom", "secrets.token_bytes"}
ASSUMPTIONS = [
    "Functions are analyzed after supported module initialization.",
    "Recognized import names identify the intended standard/crypto libraries.",
    "Recognized library APIs obey their documented source/return contracts.",
    "No external monkey patching, concurrent mutation or import hooks are modeled.",
    "A claim is conditional on the target call being reached and its inputs being valid.",
    "Supported primitive guards/effect contracts use plain builtin inputs; custom special-method effects are outside this model.",
    "Function entries use module-initialization state; prior unmodeled entry-point mutations and reflective namespace mutation are outside the model.",
    "A unique imported binding with an unbound alternative denotes that API conditional on successful lookup and target execution.",
]


class Span(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    file: str
    line: int = Field(ge=1)
    column: int = Field(ge=0)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=0)


class EvidenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    kind: str
    span: Span
    detail: str
    parents: list[str] = Field(default_factory=list)
    graph_edge: GraphEdge | None = None


class KeyOriginClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["0.1"] = "0.1"
    analysis_model: Literal["python-key-origin-subset-v0.2"] = MODEL
    operation_id: str
    target_api: str
    target: Span
    source_sha256: str
    context_backend: str
    graph_features_used: list[Literal["CALLS"]] = Field(default_factory=list)
    immediate_boundary: str
    status: Literal["resolved", "partial", "abstained"]
    origins: list[Literal["literal", "csprng_api", "external_configuration"]]
    origin_set_complete: bool
    modality: Literal["must", "may", "unknown"]
    unresolved_reasons: list[str]
    assumptions: list[str]
    evidence: list[EvidenceStep]

    @model_validator(mode="after")
    def consistent(self):
        if self.status == "resolved" and (not self.origins or not self.origin_set_complete):
            raise ValueError("Resolved claims need a nonempty complete origin set")
        if self.status == "abstained" and self.origins:
            raise ValueError("Abstained claims cannot contain ultimate origins")
        if self.status == "abstained" and self.origin_set_complete:
            raise ValueError("Abstention cannot claim a complete origin set")
        if self.status == "partial" and (not self.origins or self.origin_set_complete):
            raise ValueError("Partial claims require known origins and an incomplete set")
        if len(self.origins) != len(set(self.origins)):
            raise ValueError("Origin categories must be unique")
        if self.modality == "must" and (len(self.origins) != 1 or self.status != "resolved"):
            raise ValueError("Must requires exactly one resolved category")
        expected = "unknown" if self.status == "abstained" else "must" if self.status == "resolved" and len(self.origins) == 1 else "may"
        if self.modality != expected:
            raise ValueError("Modality does not match the origin set and resolution status")
        features = ["CALLS"] if any(step.graph_edge is not None for step in self.evidence) else []
        if self.graph_features_used != features:
            raise ValueError("Declared graph features do not match the retained witnesses")
        identifiers = {step.id for step in self.evidence}
        if len(identifiers) != len(self.evidence):
            raise ValueError("Duplicate evidence identifiers")
        if any(parent not in identifiers for step in self.evidence for parent in step.parents):
            raise ValueError("Evidence parent is missing")
        return self


@dataclass(frozen=True)
class Value:
    origins: frozenset[str] = frozenset()
    complete: bool = False
    symbol: str | None = None
    evidence: tuple[str, ...] = ()
    reasons: frozenset[str] = frozenset()
    boundary: str = "expression"
    primitive: bool = False


@dataclass
class State:
    env: dict[str, Value]
    blockers: set[str] = field(default_factory=set)
    effects: tuple[str, ...] = ()

    def copy(self):
        return State(dict(self.env), set(self.blockers), self.effects)


def analyze_key_origins(path: Path, graph: NormalizedGraph | None = None) -> list[KeyOriginClaim]:
    """Analyze supported AES key arguments in one Python file.

    Graph CALLS edges may corroborate same-file wrapper expansion. They never
    override source binding or assignment order. The same algorithm is used for
    AST-derived and Fraunhofer graphs; no CPG advantage is assumed.
    """
    return _Analyzer(path, graph).analyze()


class _Analyzer:
    def __init__(self, path: Path, graph: NormalizedGraph | None):
        self.path = path.resolve()
        raw = self.path.read_bytes()
        self.source = raw.decode("utf-8-sig")
        self.digest = hashlib.sha256(raw).hexdigest()
        self.tree = ast.parse(self.source, filename=str(path))
        self.postponed_annotations = any(
            isinstance(node, ast.ImportFrom) and node.module == '__future__'
            and any(alias.name == 'annotations' for alias in node.names)
            for node in self.tree.body
        )
        self.graph = graph
        self.steps: dict[str, EvidenceStep] = {}
        self.targets: dict[tuple[int, int], tuple[ast.Call, str, list[Value]]] = {}
        self.functions = {node.name: node for node in self.tree.body if isinstance(node, ast.FunctionDef)}
        self.class_functions = {f'{node.name}.{member.name}':member for node in self.tree.body if isinstance(node,ast.ClassDef)
                                for member in node.body if isinstance(member,ast.FunctionDef)}
        self.function_definitions = dict(self.functions,**self.class_functions)
        self.module = State({name: Value(symbol=f"builtin:{name}") for name in ("bytes", "str", "len", "range")})
        self.active: list[str] = []
        harmless=set()
        critical={'urandom','token_bytes','AES','AESGCM','new','getenv','environ','get','Hash','update','finalize','default_backend','SHA256'}
        for cls in self.tree.body:
            if not isinstance(cls,ast.ClassDef) or not plain_class(cls,self.postponed_annotations):continue
            if any(isinstance(member,ast.FunctionDef) and member.name in {'__setattr__','__getattribute__','__getattr__'} for member in cls.body):continue
            for member in cls.body:
                if not isinstance(member,ast.FunctionDef) or not member.args.args:continue
                receiver=member.args.args[0].arg
                for node in ast.walk(member):
                    if isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id==receiver and node.attr not in critical:
                        harmless.add(id(node))
        self.attribute_mutation = any(
            isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) not in harmless
            for node in ast.walk(self.tree)
        )
        self.namespace_mutation = any(isinstance(node,(ast.Global,ast.Nonlocal)) or
            isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'exec','eval','globals','locals','vars','setattr','delattr','__import__'} or
            isinstance(node,ast.Attribute) and node.attr in {'__dict__','__globals__','f_globals','f_locals','_getframe','currentframe'}
            for node in ast.walk(self.tree))

    def span(self, node: ast.AST) -> Span:
        return Span(file=self.path.name, line=node.lineno, column=node.col_offset,
                    end_line=node.end_lineno, end_column=node.end_col_offset)

    def step(self, node: ast.AST, kind: str, detail: str, parents=(), graph_edge=None) -> tuple[str, ...]:
        parents = sorted(set(parents))
        payload = f"{self.digest}:{node.lineno}:{node.col_offset}:{kind}:{detail}:{parents}:{graph_edge}"
        identifier = "ev-" + hashlib.sha256(payload.encode()).hexdigest()[:20]
        self.steps[identifier] = EvidenceStep(id=identifier, kind=kind, span=self.span(node), detail=detail, parents=parents,
            graph_edge=graph_edge.model_copy(deep=True) if graph_edge is not None else None)
        return (identifier,)

    def unknown(self, node: ast.AST, reason: str, boundary="expression", parents=()) -> Value:
        return Value(evidence=self.step(node, "unresolved", reason, parents), reasons=frozenset({reason}), boundary=boundary)

    def combine(self, node: ast.AST, values: list[Value], kind="branch_join") -> Value:
        if not values:
            return self.unknown(node, "no_reaching_value")
        symbols = {value.symbol for value in values}
        nonempty={value.symbol for value in values if value.symbol is not None}
        conditional = len(nonempty)==1 and all(value.symbol is not None or not value.origins and value.reasons in {frozenset({'unbound_branch'}),frozenset({'unbound_local'})} for value in values)
        boundaries = {value.boundary for value in values}
        return Value(
            origins=frozenset().union(*(value.origins for value in values)),
            complete=all(value.complete for value in values),
            symbol=next(iter(symbols)) if len(symbols) == 1 else next(iter(nonempty)) if conditional else None,
            evidence=self.step(node, kind, "merge alternatives", [item for value in values for item in value.evidence]),
            reasons=frozenset().union(*(value.reasons for value in values)) | (frozenset({'ambiguous_binding'}) if len(nonempty)>1 else frozenset()),
            boundary=next(iter(boundaries)) if len(boundaries) == 1 else "expression",
            primitive=all(value.primitive for value in values),
        )

    def analyze(self) -> list[KeyOriginClaim]:
        if self.attribute_mutation:self.module.blockers.add('explicit_attribute_mutation')
        if self.namespace_mutation:self.module.blockers.add('explicit_namespace_mutation')
        state, _ = self.block(self.tree.body, self.module.copy(), None, capture=True)
        if state is None:
            # No normal module initialization reaches the function-entry model.
            return [self.claim(*value) for _, value in sorted(self.targets.items())]
        self.module = state
        for name,function in self.function_definitions.items():
            method=name in self.class_functions
            if function.decorator_list and not method:
                continue
            env = self.local_env(function, self.module.env)
            for argument in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]:
                value=self.unknown(argument, "parameter_boundary", "parameter")
                env[argument.arg] = Value(evidence=value.evidence,reasons=value.reasons,boundary='parameter',primitive=True)
            blockers = set(self.module.blockers)
            if self.attribute_mutation:
                blockers.add("explicit_attribute_mutation")
            if self.namespace_mutation:blockers.add('explicit_namespace_mutation')
            if method:blockers.add('unsupported_method_context')
            self.active = [name]
            self.block(function.body, State(env, blockers,self.module.effects), name, capture=True)
        return [self.claim(*value) for _, value in sorted(self.targets.items())]

    def local_env(self, function: ast.FunctionDef, globals_: dict[str, Value]) -> dict[str, Value]:
        env = dict(globals_)
        # Python treats a name assigned later in a function as local throughout
        # that function. Mask globals before evaluating any preceding reads.
        class Locals(ast.NodeVisitor):
            def __init__(self):
                self.names = set()
            def visit_Name(self, node):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    self.names.add(node.id)
            def visit_Import(self, node):
                self.names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            def visit_ImportFrom(self, node):
                self.names.update(alias.asname or alias.name for alias in node.names)
            def visit_FunctionDef(self, node):
                self.names.add(node.name)
            visit_AsyncFunctionDef = visit_FunctionDef
            def visit_ClassDef(self, node):
                self.names.add(node.name)
            def visit_Lambda(self, node):
                pass
        visitor = Locals()
        for statement in function.body:
            visitor.visit(statement)
        for name in visitor.names:
            env[name] = self.unknown(function, "unbound_local")
        return env

    def block(self, body, state: State, caller: str | None, capture: bool):
        returns: list[Value] = []
        for statement in body:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                for alias in statement.names:
                    name = alias.asname or alias.name.split(".")[0]
                    if isinstance(statement, ast.ImportFrom):
                        name = alias.asname or alias.name
                        symbol = f"{statement.module}.{alias.name}"
                    else:
                        symbol = alias.name if alias.asname else alias.name.split(".")[0]
                    if alias.name == "*" or getattr(statement, "level", 0):
                        state.blockers.add("unsupported_import")
                    state.env[name] = Value(symbol=symbol, evidence=self.step(statement, "import_binding", f"{name}={symbol}"))
            elif isinstance(statement, ast.FunctionDef):
                defaults = [*statement.args.defaults, *[value for value in statement.args.kw_defaults if value is not None]]
                parameters=[*statement.args.posonlyargs,*statement.args.args,*statement.args.kwonlyargs]
                parameters.extend(arg for arg in (statement.args.vararg,statement.args.kwarg) if arg is not None)
                annotations = [statement.returns, *[argument.annotation for argument in parameters]]
                if statement.decorator_list or any(not safe_default(value) for value in defaults):
                    state.blockers.add("unsupported_definition_effect")
                if not self.postponed_annotations and any(value is not None and not isinstance(value, (ast.Name, ast.Constant)) for value in annotations):
                    state.blockers.add("unsupported_definition_annotation")
                if caller is None and not statement.decorator_list:
                    state.env[statement.name] = Value(symbol=f"local:{statement.name}", evidence=self.step(statement, "function_binding", statement.name))
                else:
                    state.env[statement.name] = self.unknown(statement, "unsupported_function_binding")
            elif isinstance(statement,ast.ClassDef):
                harmless=plain_class(statement,self.postponed_annotations)
                if not harmless:
                    state.blockers.add('unsupported_statement:ClassDef')
                    body_state,_=self.block(statement.body,state.copy(),f'class:{statement.name}',capture)
                    if body_state is not None:state.blockers.update(body_state.blockers)
                else:
                    state.effects+=self.step(statement,'class_definition_effect','Plain class declaration; method bodies are not module-initialization effects.')
                state.env[statement.name]=Value(symbol='class:'+statement.name,evidence=self.step(statement,'class_binding',statement.name))
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                if isinstance(statement, ast.AnnAssign) and caller is None and not self.postponed_annotations and not isinstance(statement.annotation, (ast.Name, ast.Constant)):
                    state.blockers.add("unsupported_module_annotation")
                value = self.expr(statement.value, state, caller, capture) if statement.value else self.unknown(statement, "annotation_without_value")
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        state.env[target.id] = Value(value.origins, value.complete, value.symbol,
                            self.step(statement, "assignment", target.id, value.evidence), value.reasons, "local_assignment",value.primitive)
                    else:
                        state.blockers.add("unsupported_assignment_target")
                        for node in ast.walk(target):
                            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                                state.env[node.id] = self.unknown(statement, "unsupported_assignment_target")
            elif isinstance(statement, ast.If):
                self.expr(statement.test, state, caller, capture)
                branches = [statement.body, statement.orelse]
                if isinstance(statement.test, ast.Constant) and isinstance(statement.test.value, bool):
                    branches = [branches[0] if statement.test.value else branches[1]]
                continuations = []
                for branch in branches:
                    continuation, branch_returns = self.block(branch, state.copy(), caller, capture)
                    returns.extend(branch_returns)
                    if continuation is not None:
                        continuations.append(continuation)
                if not continuations:
                    return None, returns
                names = set().union(*(set(item.env) for item in continuations))
                state = State({name: self.combine(statement, [item.env.get(name) or self.unknown(statement, "unbound_branch") for item in continuations]) for name in names},
                              set().union(*(item.blockers for item in continuations)),
                              tuple(sorted({identifier for item in continuations for identifier in item.effects})))
            elif isinstance(statement,ast.Try) and not statement.finalbody and not statement.orelse:
                # Prefix states overapproximate where an exception can occur;
                # handler bindings cannot be assumed to start before the try.
                state.blockers.add('unsupported_exception_flow')
                prefixes=[state.copy()];normal=state.copy();normal_returns=[]
                for part in statement.body:
                    if normal is None:break
                    normal,produced=self.block([part],normal,caller,capture)
                    normal_returns.extend(produced)
                    if normal is not None:prefixes.append(normal.copy())
                names=set().union(*(set(item.env) for item in prefixes))
                exceptional=State({name:self.combine(statement,[item.env.get(name) or self.unknown(statement,'unbound_branch') for item in prefixes]) for name in names},
                    set().union(*(item.blockers for item in prefixes)),tuple(sorted({identifier for item in prefixes for identifier in item.effects})))
                continuations=[normal] if normal is not None else []
                returns.extend(normal_returns)
                for handler in statement.handlers:
                    branch=exceptional.copy()
                    if handler.name:branch.env[handler.name]=self.unknown(handler,'exception_parameter')
                    continuation,produced=self.block(handler.body,branch,caller,capture)
                    returns.extend(produced)
                    if continuation is not None:
                        if handler.name:continuation.env[handler.name]=self.unknown(handler,'unbound_branch')
                        continuations.append(continuation)
                if not continuations:return None,returns
                names=set().union(*(set(item.env) for item in continuations))
                state=State({name:self.combine(statement,[item.env.get(name) or self.unknown(statement,'unbound_branch') for item in continuations]) for name in names},
                    set().union(*(item.blockers for item in continuations)),tuple(sorted({identifier for item in continuations for identifier in item.effects})))
            elif isinstance(statement, ast.Return):
                value = self.expr(statement.value, state, caller, capture) if statement.value else self.unknown(statement, "empty_return")
                if state.blockers:
                    value = Value(evidence=value.evidence, reasons=value.reasons | frozenset(state.blockers), boundary=value.boundary)
                returns.append(value)
                return None, returns
            elif isinstance(statement, ast.Raise):
                # Exception construction can have effects, but this branch has
                # no normal continuation. A surrounding try/finally remains an
                # unsupported effect boundary, rather than a solved exception CFG.
                if statement.exc is not None:
                    self.expr(statement.exc, state, caller, capture)
                if statement.cause is not None:
                    self.expr(statement.cause, state, caller, capture)
                return None, returns
            elif isinstance(statement, ast.Expr):
                self.expr(statement.value, state, caller, capture)
            elif isinstance(statement, ast.Pass):
                pass
            else:
                state.blockers.add(f"unsupported_statement:{type(statement).__name__}")
                # Preserve visible target sites as abstentions inside unsupported
                # control flow instead of silently treating them as safe absences.
                for node in ast.walk(statement):
                    if isinstance(node, ast.Call):
                        self.expr(node, state, caller, capture)
                for node in ast.walk(statement):
                    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        boundary = "local_assignment" if isinstance(node.ctx, ast.Store) else "expression"
                        state.env[node.id] = self.unknown(statement, "unsupported_write", boundary)
        return state, returns

    def expr(self, node: ast.AST, state: State, caller: str | None, capture: bool) -> Value:
        if isinstance(node, ast.Constant):
            return Value(frozenset({"literal"}), True, evidence=self.step(node, "literal", type(node.value).__name__), boundary="literal",primitive=True)
        if isinstance(node, ast.Name):
            value = state.env.get(node.id) or self.unknown(node, "unresolved_name")
            return Value(value.origins, value.complete, value.symbol,
                         self.step(node, "name_read", node.id, value.evidence), value.reasons, value.boundary,value.primitive)
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value, state, caller, capture)
            if base.symbol:
                return Value(symbol=f"{base.symbol}.{node.attr}", evidence=self.step(node, "attribute_binding", node.attr, base.evidence))
            if node.attr in {"encode", "decode"} and base.complete and base.origins <= {"literal", "external_configuration"}:
                return Value(base.origins, True, symbol=f"representation:{node.attr}", evidence=base.evidence)
            state.blockers.add("unsupported_attribute_effect")
            return self.unknown(node, "unresolved_attribute", "object_field", base.evidence)
        if isinstance(node, ast.BinOp):
            left = self.expr(node.left, state, caller, capture)
            right = self.expr(node.right, state, caller, capture)
            if isinstance(node.op,(ast.Add,ast.Mult)) and left.origins == right.origins == frozenset({"literal"}) and left.complete and right.complete:
                return Value(frozenset({"literal"}), True, evidence=self.step(node, "literal_composition", type(node.op).__name__, left.evidence + right.evidence),primitive=True)
            if left.primitive and right.primitive:
                evidence=self.step(node,'primitive_guard_contract',type(node.op).__name__,left.evidence+right.evidence)
                state.effects+=evidence
                return Value(evidence=evidence,reasons=frozenset({'unresolved_primitive_expression'}),primitive=True)
            state.blockers.add("unsupported_composition")
            return self.unknown(node, "unsupported_composition", parents=left.evidence + right.evidence)
        if isinstance(node,(ast.Compare,ast.UnaryOp,ast.BoolOp)):
            operands=([node.left,*node.comparators] if isinstance(node,ast.Compare) else [node.operand] if isinstance(node,ast.UnaryOp) else node.values)
            values=[self.expr(value,state,caller,capture) for value in operands]
            if all(value.primitive for value in values):
                evidence=self.step(node,'primitive_guard_contract',type(node).__name__,[parent for value in values for parent in value.evidence])
                state.effects+=evidence
                return Value(evidence=evidence,reasons=frozenset({'unresolved_primitive_expression'}),primitive=True)
            state.blockers.add('unsupported_primitive_operand')
            return self.unknown(node,'unsupported_primitive_operand')
        if isinstance(node, ast.IfExp):
            self.expr(node.test, state, caller, capture)
            if isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
                return self.expr(node.body if node.test.value else node.orelse, state, caller, capture)
            states = [state.copy(), state.copy()]
            values = [self.expr(node.body, states[0], caller, capture), self.expr(node.orelse, states[1], caller, capture)]
            state.blockers.update(set().union(*(item.blockers for item in states)))
            state.effects=tuple(sorted(set().union(*(set(item.effects) for item in states))))
            return self.combine(node, values)
        if isinstance(node, ast.Subscript):
            base = self.expr(node.value, state, caller, capture)
            self.expr(node.slice, state, caller, capture)
            if base.symbol == "os.environ":
                return Value(frozenset({"external_configuration"}), True, evidence=self.step(node, "configuration_read", "os.environ", base.evidence))
            state.blockers.add("unsupported_subscript_effect")
            return self.unknown(node, "unsupported_subscript", parents=base.evidence)
        if isinstance(node, ast.Call):
            callee = self.expr(node.func, state, caller, capture)
            positional = [self.expr(arg, state, caller, capture) for arg in node.args]
            keywords = {keyword.arg: self.expr(keyword.value, state, caller, capture) for keyword in node.keywords}
            if callee.symbol in TARGETS:
                key = positional[0] if positional else keywords.get("key")
                key = key or self.unknown(node, "missing_key_argument")
                if any(isinstance(arg, ast.Starred) for arg in node.args) or None in keywords:
                    key = self.unknown(node, "dynamic_argument_binding")
                if positional and "key" in keywords:
                    key = self.unknown(node, "duplicate_key_argument")
                if state.blockers:
                    key = Value(evidence=key.evidence, reasons=key.reasons | frozenset(state.blockers), boundary=key.boundary)
                key = Value(key.origins, key.complete, evidence=self.step(node, "key_argument", callee.symbol, callee.evidence + key.evidence + state.effects), reasons=key.reasons, boundary=key.boundary)
                if capture:
                    site = (node.lineno, node.col_offset)
                    self.targets.setdefault(site, (node, callee.symbol, []))[2].append(key)
                return self.unknown(node, "crypto_result_not_key_origin", "return_value")
            if callee.symbol in RANDOM_APIS:
                if state.blockers:
                    return Value(evidence=callee.evidence, reasons=frozenset(state.blockers), boundary="return_value")
                return Value(frozenset({"csprng_api"}), True, evidence=self.step(node, "api_contract", callee.symbol, callee.evidence), boundary="return_value",primitive=True)
            if callee.symbol in PRIMITIVE_CALLS and all(value.primitive for value in [*positional,*keywords.values()]):
                evidence=self.step(node,'primitive_guard_contract',callee.symbol,callee.evidence+tuple(parent for value in [*positional,*keywords.values()] for parent in value.evidence))
                state.effects+=evidence
                return Value(evidence=evidence,reasons=frozenset({'unresolved_builtin_result'}),boundary='return_value',primitive=True)
            if callee.symbol in {"os.getenv", "os.environ.get"}:
                configuration = Value(frozenset({"external_configuration"}), True, evidence=self.step(node, "configuration_read", callee.symbol, callee.evidence), boundary="return_value")
                default = positional[1] if len(positional) > 1 else keywords.get("default")
                return self.combine(node, [configuration, default], "configuration_default") if default else configuration
            if callee.symbol and callee.symbol.startswith("local:"):
                name = callee.symbol.removeprefix("local:")
                return self.helper(node, name, positional, keywords, state, caller, callee)
            # Encoding does not establish a new origin. Support it only on a
            # value whose origin was already recovered, not by method spelling.
            if callee.symbol in {"representation:encode", "representation:decode"}:
                return Value(callee.origins, callee.complete, evidence=self.step(node, "representation_change", callee.symbol, callee.evidence), reasons=callee.reasons, boundary="return_value")
            state.blockers.add("unmodeled_call_effect")
            return self.unknown(node, "unresolved_call", "return_value", callee.evidence)
        reason = f"unsupported_expression:{type(node).__name__}"
        state.blockers.add(reason)
        return self.unknown(node, reason)

    def call_edge(self, caller: str | None, target: ast.FunctionDef):
        if self.graph is None or caller not in self.function_definitions:
            return None
        caller_definition = self.function_definitions[caller]
        def same_file(node):
            value = Path(node.file)
            return value == self.path or (not value.is_absolute() and value.as_posix() == self.path.name)
        sources = {node.id for node in self.graph.nodes if node.kind == "function" and same_file(node)
                   and node.line == caller_definition.lineno and (node.name or "").split(".")[-1] == caller_definition.name}
        targets = {node.id for node in self.graph.nodes if node.kind == "function" and same_file(node)
                   and node.line == target.lineno and (node.name or "").split(".")[-1] == target.name}
        return next((edge for edge in self.graph.edges if edge.kind == "CALLS" and edge.source in sources and edge.target in targets), None)

    def helper(self, call, name, positional, keywords, state, caller, callee):
        function = self.bound_function(name,callee)
        edge = self.call_edge(caller, function) if function else None
        summary_bindings={key:(value.symbol if not value.symbol or not value.symbol.startswith('local:') or self.bound_function(value.symbol[6:],value) is not None else None) for key,value in self.module.env.items()}
        summary=binding_effect_summary(function,summary_bindings,self.functions) if function is not None else None
        if summary is not None:
            bindings=tuple(parent for value in self.module.env.values() if value.symbol and any(contract==value.symbol or contract.startswith(value.symbol+'.') for contract in summary) for parent in value.evidence)
            state.effects+=self.step(function,'binding_effect_summary','No modeled caller-binding mutations; contracts='+','.join(summary),callee.evidence+bindings)
        if function is None or function.decorator_list or edge is None:
            if summary is None:state.blockers.add("unexpanded_call_effect")
            return self.unknown(call, "wrapper_binding_or_call_edge_unavailable", "return_value", callee.evidence)
        if name in self.active or len(self.active) >= 4:
            state.blockers.add("call_expansion_limit")
            return self.unknown(call, "call_expansion_limit", "return_value")
        parameters = [*function.args.posonlyargs, *function.args.args]
        if function.args.vararg or function.args.kwarg or function.args.kwonlyargs or function.args.defaults or len(positional) > len(parameters) or None in keywords:
            state.blockers.add("unsupported_wrapper_signature")
            return self.unknown(call, "unsupported_wrapper_signature", "return_value")
        names = [parameter.arg for parameter in parameters]
        positional_only = {parameter.arg for parameter in function.args.posonlyargs}
        if set(keywords) - set(names) or set(keywords) & positional_only or any(parameter.arg in keywords for parameter in parameters[:len(positional)]):
            state.blockers.add("invalid_wrapper_binding")
            return self.unknown(call, "invalid_wrapper_binding", "return_value")
        env = self.local_env(function, self.module.env)
        edge_evidence = self.step(call, "call_graph_edge", f"{caller}->{name}", callee.evidence, graph_edge=edge)
        for index, parameter in enumerate(parameters):
            value = positional[index] if index < len(positional) else keywords.get(parameter.arg)
            if value is None:
                state.blockers.add("missing_wrapper_argument")
                return self.unknown(call, "missing_wrapper_argument", "return_value")
            env[parameter.arg] = Value(value.origins, value.complete, value.symbol,
                self.step(call, "actual_formal_binding", parameter.arg, value.evidence + edge_evidence), value.reasons, "parameter",value.primitive)
        self.active.append(name)
        continuation, values = self.block(function.body, State(env, set(state.blockers),state.effects), name, capture=False)
        self.active.pop()
        if continuation is not None:
            values.append(self.unknown(function, "implicit_none_return"))
        if not values:
            state.blockers.add('no_normal_wrapper_return')
            return self.unknown(call,'no_normal_wrapper_return','return_value',edge_evidence)
        value = self.combine(call, values, "wrapper_return")
        if summary is None:
            state.blockers.update(reason for reason in value.reasons if reason.startswith(("unmodeled", "unexpanded", "unsupported", "explicit_", "call_expansion")))
        return Value(value.origins, value.complete, evidence=self.step(call, "wrapper_binding", name, value.evidence + edge_evidence), reasons=value.reasons, boundary="return_value")

    def bound_function(self,name,value):
        function=self.functions.get(name)
        if function is None:return None
        pending=list(value.evidence);seen=set();bindings=[]
        while pending:
            identifier=pending.pop()
            if identifier in seen:continue
            seen.add(identifier);step=self.steps[identifier]
            if step.kind=='function_binding' and step.detail==name:bindings.append(step.span)
            pending.extend(step.parents)
        return function if bindings and all(span==self.span(function) for span in bindings) else None

    def claim(self, node: ast.Call, api: str, values: list[Value]) -> KeyOriginClaim:
        value = self.combine(node, values, "origin_claim")
        identifiers = set()
        pending = list(value.evidence)
        while pending:
            identifier = pending.pop()
            if identifier not in identifiers:
                identifiers.add(identifier)
                pending.extend(self.steps[identifier].parents)
        origins = sorted(value.origins)
        status = "resolved" if origins and value.complete else "partial" if origins else "abstained"
        return KeyOriginClaim(
            operation_id="key-" + hashlib.sha256(f"{self.path.name}:{self.digest}:{node.lineno}:{node.col_offset}".encode()).hexdigest()[:20],
            target_api=api, target=self.span(node), source_sha256=self.digest,
            context_backend=self.graph.backend if self.graph else "source-only",
            graph_features_used=["CALLS"] if any(self.steps[key].graph_edge for key in identifiers) else [],
            immediate_boundary=values[0].boundary, status=status, origins=origins,
            origin_set_complete=bool(origins) and value.complete,
            modality="must" if status == "resolved" and len(origins) == 1 else "may" if origins else "unknown",
            unresolved_reasons=sorted(value.reasons or ({"unresolved_ultimate_origin"} if not origins else set())), assumptions=ASSUMPTIONS,
            evidence=[self.steps[key] for key in sorted(identifiers)],
        )


def audit_claim_structure(claim: KeyOriginClaim, path: Path, graph: NormalizedGraph | None = None) -> list[str]:
    """Check source identity, spans, DAG closure and local assignment ordering.

    This deliberately does not certify semantic origin correctness. Independent
    annotations are needed for that separate evaluation endpoint.
    """
    errors = []
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != claim.source_sha256:
        errors.append("source_hash_mismatch")
    tree = ast.parse(raw.decode("utf-8-sig"))
    def coordinates(node):
        return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
    positions = {coordinates(node) for node in ast.walk(tree) if hasattr(node, "lineno")}
    calls = {coordinates(node) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    def span_coordinates(span):
        return (span.line, span.column, span.end_line, span.end_column)
    if span_coordinates(claim.target) not in calls:
        errors.append("target_is_not_source_call")
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    def owner(span):
        enclosing = [function for function in functions if
            (function.lineno, function.col_offset) <= (span.line, span.column)
            and (function.end_lineno, function.end_col_offset) >= (span.end_line, span.end_column)]
        return min(enclosing, key=lambda function: function.end_lineno - function.lineno) if enclosing else None
    target_owner = owner(claim.target)
    steps = {step.id: step for step in claim.evidence}
    visited, visiting = set(), set()
    def visit(identifier):
        if identifier in visiting:
            errors.append("cyclic_evidence")
            return
        if identifier in visited:
            return
        if identifier not in steps:
            errors.append("missing_evidence_parent")
            return
        visiting.add(identifier)
        for parent in steps[identifier].parents:
            visit(parent)
        visiting.remove(identifier)
        visited.add(identifier)
    for step in claim.evidence:
        visit(step.id)
        if step.span.file != path.name or span_coordinates(step.span) not in positions:
            errors.append("invalid_source_span")
        if step.kind == "assignment" and owner(step.span) is target_owner and target_owner is not None:
            if (step.span.end_line, step.span.end_column) > (claim.target.line, claim.target.column):
                errors.append("local_assignment_after_target")
        if step.kind == "call_graph_edge" and step.graph_edge is None:
            errors.append("missing_graph_witness")
        if step.graph_edge:
            if graph is None:
                errors.append("graph_witness_unchecked")
            else:
                edge = step.graph_edge
                edges = {(item.source, item.target, item.kind) for item in graph.edges}
                nodes = {item.id for item in graph.nodes}
                if edge.kind != "CALLS" or (edge.source, edge.target, edge.kind) not in edges or edge.source not in nodes or edge.target not in nodes:
                    errors.append("invalid_graph_witness")
                if claim.context_backend != graph.backend:
                    errors.append("graph_backend_mismatch")
    roots = [step for step in claim.evidence if step.kind == "origin_claim" and step.span == claim.target]
    if len(roots) != 1:
        errors.append("missing_or_ambiguous_claim_root")
    else:
        closure, todo = set(), [roots[0].id]
        while todo:
            identifier = todo.pop()
            if identifier not in closure and identifier in steps:
                closure.add(identifier)
                todo.extend(steps[identifier].parents)
        if closure != set(steps):
            errors.append("disconnected_evidence")
    return sorted(set(errors))
