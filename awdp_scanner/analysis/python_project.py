from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping


BACKEND_NAME = "python-ast-v2"


@dataclass(frozen=True, order=True)
class TaintAtom:
    kind: str
    name: str
    file_path: str
    line: int
    origin: str = ""


@dataclass(frozen=True, order=True)
class Sink:
    family: str
    name: str
    file_path: str
    line: int


@dataclass(frozen=True)
class SinkFlow:
    dependencies: frozenset[TaintAtom]
    sink: Sink
    call_chain: tuple[str, ...]
    trace: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True)
class FunctionSummary:
    parameters: tuple[str, ...]
    return_dependencies: frozenset[TaintAtom]
    sink_flows: frozenset[SinkFlow]


@dataclass(frozen=True)
class FunctionUnit:
    key: str
    module: str
    file_path: str
    node: ast.AST
    parameters: tuple[str, ...]
    source_parameters: frozenset[str] = frozenset()
    class_name: str = ""


def _module_name(file_path: str, common_root: str) -> str:
    relative = os.path.relpath(file_path, common_root).replace("\\", "/")
    if relative.endswith(".py"):
        relative = relative[:-3]
    if relative.endswith("/__init__"):
        relative = relative[: -len("/__init__")]
    return relative.replace("/", ".").strip(".") or Path(file_path).stem


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _node_text_name(node: ast.AST) -> str:
    if isinstance(node, ast.Subscript):
        return _node_text_name(node.value)
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return _call_name(node)


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if node.args.vararg:
        arguments.append(node.args.vararg)
    if node.args.kwarg:
        arguments.append(node.args.kwarg)
    return tuple(argument.arg for argument in arguments)


def _route_parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    route_parameters: set[str] = set()
    route_decorators = {"route", "get", "post", "put", "patch", "delete"}
    converters = {"int", "float", "path", "uuid", "string", "re"}
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        decorator_name = _call_name(decorator.func).lower().rsplit(".", 1)[-1]
        if decorator_name not in route_decorators or not decorator.args:
            continue
        route_value = decorator.args[0]
        if not isinstance(route_value, ast.Constant) or not isinstance(route_value.value, str):
            continue
        for raw_parameter in re.findall(r"<([^<>]+)>", route_value.value):
            pieces = [piece.strip() for piece in raw_parameter.split(":", 1)]
            candidate = pieces[1] if len(pieces) == 2 and pieces[0].lower() in converters else pieces[0]
            if candidate.isidentifier():
                route_parameters.add(candidate)
    return frozenset(route_parameters)


def _collect_units(
    trees: Mapping[str, ast.Module],
    modules: Mapping[str, str],
) -> dict[str, FunctionUnit]:
    units: dict[str, FunctionUnit] = {}

    def register_function(
        module: str,
        file_path: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        qualified_name: str,
        *,
        class_name: str = "",
    ) -> None:
        key = f"{module}.{qualified_name}"
        units[key] = FunctionUnit(
            key,
            module,
            file_path,
            node,
            _function_parameters(node),
            source_parameters=_route_parameter_names(node),
            class_name=class_name,
        )
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                register_function(
                    module,
                    file_path,
                    statement,
                    f"{qualified_name}.{statement.name}",
                    class_name=class_name,
                )

    for file_path, tree in trees.items():
        module = modules[file_path]
        module_key = f"{module}.<module>"
        units[module_key] = FunctionUnit(module_key, module, file_path, tree, ())
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                register_function(
                    module,
                    file_path,
                    statement,
                    statement.name,
                )
            elif isinstance(statement, ast.ClassDef):
                for member in statement.body:
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        register_function(
                            module,
                            file_path,
                            member,
                            f"{statement.name}.{member.name}",
                            class_name=statement.name,
                        )
    return units


def _resolve_relative_import(current_module: str, imported_module: str | None, level: int) -> str:
    if level <= 0:
        return imported_module or ""
    package = current_module.split(".")[:-1]
    keep = max(0, len(package) - level + 1)
    prefix = package[:keep]
    if imported_module:
        prefix.extend(imported_module.split("."))
    return ".".join(prefix)


def _collect_import_aliases(trees: Mapping[str, ast.Module], modules: Mapping[str, str]) -> dict[str, dict[str, str]]:
    aliases: dict[str, dict[str, str]] = {}
    for file_path, tree in trees.items():
        module = modules[file_path]
        module_aliases: dict[str, str] = {}
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for imported in statement.names:
                    module_aliases[imported.asname or imported.name.split(".")[0]] = imported.name
            elif isinstance(statement, ast.ImportFrom):
                source_module = _resolve_relative_import(module, statement.module, statement.level)
                for imported in statement.names:
                    if imported.name == "*":
                        continue
                    target = f"{source_module}.{imported.name}" if source_module else imported.name
                    module_aliases[imported.asname or imported.name] = target
        aliases[module] = module_aliases
    return aliases


class _Resolver:
    def __init__(self, units: Mapping[str, FunctionUnit], aliases: Mapping[str, Mapping[str, str]]):
        self.units = units
        self.aliases = aliases

    def resolve(self, unit: FunctionUnit, raw_name: str) -> str | None:
        if not raw_name:
            return None
        candidates: list[str] = []
        if raw_name.startswith("self.") and unit.class_name:
            candidates.append(f"{unit.module}.{unit.class_name}.{raw_name.split('.', 1)[1]}")
        candidates.append(f"{unit.module}.{raw_name}")
        module_aliases = self.aliases.get(unit.module, {})
        first, separator, remainder = raw_name.partition(".")
        if first in module_aliases:
            mapped = module_aliases[first]
            candidates.append(f"{mapped}.{remainder}" if separator else mapped)
        candidates.append(raw_name)
        for candidate in candidates:
            if candidate in self.units:
                return candidate
        suffix = f".{raw_name}"
        matches = [key for key in self.units if key.endswith(suffix)]
        return matches[0] if len(matches) == 1 else None


def _source_label(node: ast.AST) -> str:
    name = _node_text_name(node).lower()
    source_names = {
        "input": "stdin",
        "sys.stdin.readline": "stdin",
        "sys.stdin.read": "stdin",
        "os.getenv": "environment",
        "os.environ.get": "environment",
    }
    if name in source_names:
        return source_names[name]
    if name.startswith("sys.argv") or name.startswith("os.environ"):
        return "process-input"
    request_markers = (
        "request.args",
        "request.form",
        "request.values",
        "request.headers",
        "request.cookies",
        "request.json",
        "request.get_json",
        "request.data",
        "request.body",
    )
    if any(marker in name for marker in request_markers):
        return name or "http-request"
    if name.startswith("django.") and "request" in name:
        return name
    return ""


def _keyword_boolean(call: ast.Call, name: str) -> bool | None:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            return bool(keyword.value.value)
    return None


def _sink_family(call: ast.Call) -> tuple[str, str]:
    name = _call_name(call.func)
    lowered = name.lower()
    terminal = lowered.rsplit(".", 1)[-1]
    if terminal in {"eval", "exec", "compile"}:
        return "code_execution", name
    if lowered in {"os.system", "os.popen"} or terminal in {"shell_exec", "system"}:
        return "command_injection", name
    if lowered.startswith("subprocess."):
        shell_mode = _keyword_boolean(call, "shell")
        if shell_mode is True:
            return "command_injection", name
        return "", ""
    if lowered in {"pickle.loads", "pickle.load", "marshal.loads", "dill.loads"}:
        return "deserialization", name
    if lowered in {"yaml.load", "yaml.unsafe_load"}:
        return "yaml_deserialization", name
    if terminal in {"execute", "executemany", "executescript", "raw"}:
        return "sqli", name
    if terminal in {"find", "find_one", "findone", "aggregate"}:
        return "sqli", name
    if lowered in {
        "requests.get",
        "requests.post",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.request",
        "urllib.request.urlopen",
    }:
        return "ssrf", name
    if lowered in {"render_template_string", "jinja2.template", "template"}:
        return "ssti", name
    if terminal in {"open", "read_text", "read_bytes", "send_file"}:
        return "path_traversal", name
    return "", ""


def _sink_argument_nodes(call: ast.Call, family: str) -> list[ast.AST]:
    if family == "sqli":
        return list(call.args[:1])
    selected = list(call.args[:1])
    for keyword in call.keywords:
        if keyword.arg in {"command", "cmd", "url", "path", "filename", "template"}:
            selected.append(keyword.value)
    return selected or [keyword.value for keyword in call.keywords]


class _FunctionPass:
    def __init__(
        self,
        unit: FunctionUnit,
        resolver: _Resolver,
        summaries: Mapping[str, FunctionSummary],
    ):
        self.unit = unit
        self.resolver = resolver
        self.summaries = summaries
        self.flows: set[SinkFlow] = set()
        self.return_dependencies: set[TaintAtom] = set()
        self.calls: set[tuple[str, str, int]] = set()

    def analyze(self) -> FunctionSummary:
        environment = {
            name: {
                TaintAtom(
                    "source" if name in self.unit.source_parameters else "parameter",
                    f"route:{name}" if name in self.unit.source_parameters else name,
                    self.unit.file_path,
                    getattr(self.unit.node, "lineno", 1),
                    self.unit.key,
                )
            }
            for name in self.unit.parameters
        }
        if isinstance(self.unit.node, ast.Module):
            body = [
                statement
                for statement in self.unit.node.body
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
        else:
            body = self.unit.node.body
        self._statements(body, environment)
        return FunctionSummary(
            parameters=self.unit.parameters,
            return_dependencies=frozenset(self.return_dependencies),
            sink_flows=frozenset(self.flows),
        )

    def _assign(self, target: ast.AST, dependencies: set[TaintAtom], environment: dict[str, set[TaintAtom]]) -> None:
        if isinstance(target, ast.Name):
            environment[target.id] = set(dependencies)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign(element, dependencies, environment)
        elif isinstance(target, ast.Attribute):
            environment[_call_name(target)] = set(dependencies)

    def _record_assignment_sink(
        self,
        target: ast.AST,
        value_dependencies: set[TaintAtom],
        environment: dict[str, set[TaintAtom]],
    ) -> None:
        if not isinstance(target, ast.Subscript):
            return
        if _call_name(target.value).lower() in {"kwargs"}:
            return
        key_dependencies = self._expression(target.slice, environment)
        dependencies = set(value_dependencies) | key_dependencies
        if not any(dependency.kind == "source" for dependency in dependencies):
            return
        literal_key = target.slice.value if isinstance(target.slice, ast.Constant) else None
        privilege_fields = {"admin", "is_admin", "role", "roles", "position", "privileged", "permission", "permissions"}
        privileged_key = isinstance(literal_key, str) and literal_key.lower() in privilege_fields
        untrusted_dynamic_key = not isinstance(target.slice, ast.Constant) and bool(key_dependencies)
        untrusted_value = any(dependency.kind == "source" for dependency in value_dependencies)
        if not privileged_key and not (untrusted_dynamic_key and untrusted_value):
            return
        sink_name = "privilege-field-assignment" if privileged_key else "dynamic-field-assignment"
        sink = Sink("auth", sink_name, self.unit.file_path, getattr(target, "lineno", 0))
        self.flows.add(
            SinkFlow(
                frozenset(dependencies),
                sink,
                (self.unit.key,),
                ((self.unit.file_path, getattr(target, "lineno", 0), sink_name),),
            )
        )

    def _record_auth_comparison(
        self,
        test: ast.AST,
        dependencies: set[TaintAtom],
    ) -> None:
        if not isinstance(test, ast.Compare) or not dependencies:
            return
        unit_name = self.unit.key.lower()
        if not any(marker in unit_name for marker in ("auth", "login", "session", "token", "permission")):
            return
        sink_name = "auth-boundary-comparison"
        sink = Sink("auth", sink_name, self.unit.file_path, getattr(test, "lineno", 0))
        self.flows.add(
            SinkFlow(
                frozenset(dependencies),
                sink,
                (self.unit.key,),
                ((self.unit.file_path, getattr(test, "lineno", 0), sink_name),),
            )
        )

    @staticmethod
    def _merge_environments(*environments: Mapping[str, set[TaintAtom]]) -> dict[str, set[TaintAtom]]:
        merged: dict[str, set[TaintAtom]] = {}
        for environment in environments:
            for name, dependencies in environment.items():
                merged.setdefault(name, set()).update(dependencies)
        return merged

    def _statements(self, statements: Iterable[ast.stmt], environment: dict[str, set[TaintAtom]]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, ast.Assign):
                dependencies = self._expression(statement.value, environment)
                for target in statement.targets:
                    self._record_assignment_sink(target, dependencies, environment)
                    self._assign(target, dependencies, environment)
            elif isinstance(statement, ast.AnnAssign):
                dependencies = self._expression(statement.value, environment) if statement.value else set()
                self._record_assignment_sink(statement.target, dependencies, environment)
                self._assign(statement.target, dependencies, environment)
            elif isinstance(statement, ast.AugAssign):
                dependencies = self._expression(statement.target, environment) | self._expression(statement.value, environment)
                self._assign(statement.target, dependencies, environment)
            elif isinstance(statement, ast.Expr):
                self._expression(statement.value, environment)
            elif isinstance(statement, ast.Return):
                self.return_dependencies.update(self._expression(statement.value, environment) if statement.value else set())
            elif isinstance(statement, ast.If):
                test_dependencies = self._expression(statement.test, environment)
                self._record_auth_comparison(statement.test, test_dependencies)
                before = {name: set(value) for name, value in environment.items()}
                body_env = {name: set(value) for name, value in before.items()}
                else_env = {name: set(value) for name, value in before.items()}
                self._statements(statement.body, body_env)
                self._statements(statement.orelse, else_env)
                environment.clear()
                environment.update(self._merge_environments(body_env, else_env))
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                loop_env = {name: set(value) for name, value in environment.items()}
                self._assign(statement.target, self._expression(statement.iter, environment), loop_env)
                self._statements(statement.body, loop_env)
                self._statements(statement.orelse, loop_env)
                environment.clear()
                environment.update(self._merge_environments(environment, loop_env))
            elif isinstance(statement, ast.While):
                test_dependencies = self._expression(statement.test, environment)
                self._record_auth_comparison(statement.test, test_dependencies)
                loop_env = {name: set(value) for name, value in environment.items()}
                self._statements(statement.body, loop_env)
                self._statements(statement.orelse, loop_env)
                environment.clear()
                environment.update(self._merge_environments(environment, loop_env))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    dependencies = self._expression(item.context_expr, environment)
                    if item.optional_vars:
                        self._assign(item.optional_vars, dependencies, environment)
                self._statements(statement.body, environment)
            elif isinstance(statement, ast.Try):
                variants = []
                for branch in [statement.body, *(handler.body for handler in statement.handlers), statement.orelse]:
                    branch_env = {name: set(value) for name, value in environment.items()}
                    self._statements(branch, branch_env)
                    variants.append(branch_env)
                environment.clear()
                environment.update(self._merge_environments(*variants))
                self._statements(statement.finalbody, environment)
            else:
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        self._expression(child, environment)

    def _substitute(
        self,
        dependencies: Iterable[TaintAtom],
        callee_key: str,
        argument_map: Mapping[str, set[TaintAtom]],
    ) -> set[TaintAtom]:
        substituted: set[TaintAtom] = set()
        for dependency in dependencies:
            if dependency.kind == "parameter" and dependency.origin == callee_key:
                substituted.update(argument_map.get(dependency.name, set()))
            else:
                substituted.add(dependency)
        return substituted

    def _expression(self, node: ast.AST | None, environment: dict[str, set[TaintAtom]]) -> set[TaintAtom]:
        if node is None:
            return set()
        source = _source_label(node)
        if source:
            return {TaintAtom("source", source, self.unit.file_path, getattr(node, "lineno", 0), self.unit.key)}
        if isinstance(node, ast.Name):
            return set(environment.get(node.id, set()))
        if isinstance(node, ast.Attribute):
            named = _call_name(node)
            return set(environment.get(named, set())) | self._expression(node.value, environment)
        if isinstance(node, ast.Subscript):
            return self._expression(node.value, environment) | self._expression(node.slice, environment)
        if isinstance(node, ast.NamedExpr):
            dependencies = self._expression(node.value, environment)
            self._assign(node.target, dependencies, environment)
            return dependencies
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            receiver_dependencies = (
                self._expression(node.func.value, environment) if isinstance(node.func, ast.Attribute) else set()
            )
            argument_dependencies = [self._expression(argument, environment) for argument in node.args]
            keyword_dependencies = {
                keyword.arg: self._expression(keyword.value, environment)
                for keyword in node.keywords
                if keyword.arg
            }
            family, sink_name = _sink_family(node)
            if family:
                dependencies: set[TaintAtom] = set()
                for argument in _sink_argument_nodes(node, family):
                    dependencies.update(self._expression(argument, environment))
                if dependencies:
                    sink = Sink(family, sink_name, self.unit.file_path, getattr(node, "lineno", 0))
                    self.flows.add(
                        SinkFlow(
                            frozenset(dependencies),
                            sink,
                            (self.unit.key,),
                            ((self.unit.file_path, getattr(node, "lineno", 0), sink_name),),
                        )
                    )

            resolved = self.resolver.resolve(self.unit, call_name)
            if not resolved:
                combined = set(receiver_dependencies).union(*argument_dependencies, *keyword_dependencies.values())
                return combined
            self.calls.add((self.unit.key, resolved, getattr(node, "lineno", 0)))
            callee = self.summaries.get(resolved)
            if callee is None:
                return set(receiver_dependencies).union(*argument_dependencies, *keyword_dependencies.values())
            argument_map: dict[str, set[TaintAtom]] = {}
            for index, parameter in enumerate(callee.parameters):
                if index < len(argument_dependencies):
                    argument_map[parameter] = argument_dependencies[index]
                if parameter in keyword_dependencies:
                    argument_map[parameter] = keyword_dependencies[parameter]
            for flow in callee.sink_flows:
                dependencies = self._substitute(flow.dependencies, resolved, argument_map)
                if not dependencies:
                    continue
                chain = flow.call_chain if self.unit.key in flow.call_chain else (self.unit.key, *flow.call_chain)
                trace_prefix = (self.unit.file_path, getattr(node, "lineno", 0), call_name)
                trace = flow.trace if trace_prefix in flow.trace else (trace_prefix, *flow.trace)
                self.flows.add(SinkFlow(frozenset(dependencies), flow.sink, chain, trace))
            return self._substitute(callee.return_dependencies, resolved, argument_map)

        dependencies: set[TaintAtom] = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                dependencies.update(self._expression(child, environment))
        return dependencies


def _flow_to_payload(flow: SinkFlow) -> dict[str, object]:
    sources = sorted(dependency for dependency in flow.dependencies if dependency.kind == "source")
    unresolved = sorted(dependency for dependency in flow.dependencies if dependency.kind == "parameter")
    deployment_config_only = bool(sources) and all(
        source.name in {"environment", "process-input"} for source in sources
    )
    slice_locations = {
        (source.file_path, source.line) for source in sources if source.line
    } | {
        (flow.sink.file_path, flow.sink.line)
    } | {
        (file_path, line) for file_path, line, _name in flow.trace if line
    }
    return {
        "family": flow.sink.family,
        "sink": flow.sink.name,
        "sink_file": flow.sink.file_path,
        "sink_line": flow.sink.line,
        "sources": [
            {"name": source.name, "file": source.file_path, "line": source.line}
            for source in sources
        ],
        "unresolved_parameters": [dependency.name for dependency in unresolved],
        "confirmed_source_to_sink": bool(sources),
        "awdp_actionable_source": bool(sources) and not deployment_config_only,
        "source_scope": "deployment_config" if deployment_config_only else "runtime_input",
        "call_chain": list(flow.call_chain),
        "trace": [
            {"file": file_path, "line": line, "symbol": symbol}
            for file_path, line, symbol in flow.trace
        ],
        "slice": [
            {"file": file_path, "line": line}
            for file_path, line in sorted(slice_locations, key=lambda item: (item[0], item[1]))
        ],
        "confidence": 0.95 if sources else 0.65,
    }


def analyze_python_project(file_records: Iterable[tuple[str, str]]) -> dict[str, object]:
    python_files = [(os.path.abspath(path), content) for path, content in file_records if path.lower().endswith(".py")]
    if not python_files:
        return {
            "backend": BACKEND_NAME,
            "flows": [],
            "configuration_flows": [],
            "per_file": {},
            "call_graph": [],
            "parse_errors": {},
        }
    common_root = os.path.commonpath([path for path, _content in python_files])
    if os.path.isfile(common_root):
        common_root = os.path.dirname(common_root)
    trees: dict[str, ast.Module] = {}
    parse_errors: dict[str, str] = {}
    for file_path, content in python_files:
        try:
            trees[file_path] = ast.parse(content, filename=file_path)
        except (SyntaxError, ValueError) as exc:
            parse_errors[file_path] = str(exc)
    modules = {file_path: _module_name(file_path, common_root) for file_path in trees}
    units = _collect_units(trees, modules)
    aliases = _collect_import_aliases(trees, modules)
    resolver = _Resolver(units, aliases)
    summaries: dict[str, FunctionSummary] = {
        key: FunctionSummary(unit.parameters, frozenset(), frozenset()) for key, unit in units.items()
    }
    all_calls: set[tuple[str, str, int, str]] = set()
    max_iterations = max(2, len(units) + 2)
    for _iteration in range(max_iterations):
        changed = False
        next_summaries: dict[str, FunctionSummary] = {}
        iteration_calls: set[tuple[str, str, int, str]] = set()
        for key, unit in units.items():
            analyzer = _FunctionPass(unit, resolver, summaries)
            summary = analyzer.analyze()
            next_summaries[key] = summary
            iteration_calls.update((caller, callee, line, unit.file_path) for caller, callee, line in analyzer.calls)
            if summary != summaries.get(key):
                changed = True
        summaries = next_summaries
        all_calls = iteration_calls
        if not changed:
            break

    unique_flows: dict[tuple[object, ...], SinkFlow] = {}
    for summary in summaries.values():
        for flow in summary.sink_flows:
            key = (
                flow.sink.family,
                flow.sink.file_path,
                flow.sink.line,
                tuple(sorted(flow.dependencies)),
                flow.call_chain,
            )
            unique_flows[key] = flow
    sink_priority = {
        "dynamic-field-assignment": 0,
        "privilege-field-assignment": 1,
        "auth-boundary-comparison": 5,
    }
    flow_payloads = sorted(
        (_flow_to_payload(flow) for flow in unique_flows.values()),
        key=lambda flow: (
            sink_priority.get(str(flow["sink"]), 2),
            -len(flow["call_chain"]),
            str(flow["family"]),
            str(flow["sink_file"]),
            int(flow["sink_line"]),
            tuple((str(source["file"]), int(source["line"]), str(source["name"])) for source in flow["sources"]),
        ),
    )
    actionable_flows = [flow for flow in flow_payloads if flow["awdp_actionable_source"]]
    configuration_flows = [
        flow for flow in flow_payloads if flow["confirmed_source_to_sink"] and not flow["awdp_actionable_source"]
    ]
    per_file: dict[str, dict[str, object]] = {}
    for file_path, _content in python_files:
        related = [
            flow
            for flow in actionable_flows
            if flow["sink_file"] == file_path
            or any(source["file"] == file_path for source in flow["sources"])
            or any(step["file"] == file_path for step in flow["trace"])
        ]
        slice_lines = sorted(
            {
                item["line"]
                for flow in related
                for item in flow["slice"]
                if item["file"] == file_path and item["line"]
            }
        )
        per_file[file_path] = {"flows": related, "slice_lines": slice_lines}
    return {
        "backend": BACKEND_NAME,
        "flows": actionable_flows,
        "configuration_flows": configuration_flows,
        "per_file": per_file,
        "call_graph": [
            {"caller": caller, "callee": callee, "line": line, "file": file_path}
            for caller, callee, line, file_path in sorted(all_calls)
        ],
        "parse_errors": parse_errors,
    }
