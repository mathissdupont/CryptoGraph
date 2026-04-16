from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import streamlit as st


RESULT_PATH = Path("/app/output/result.json")
OUTPUT_DIR = Path("/app/output")
CPG_PATH = Path("/app/output/cpg.json")
CYCLONEDX_PATH = Path("/app/output/cyclonedx-cbom.json")
UNKNOWN = "unknown"


def find_cbom_path(path: Path = RESULT_PATH) -> Path | None:
    if path.exists():
        return path

    candidates = [
        candidate
        for candidate in OUTPUT_DIR.glob("run-*/result.json")
        if candidate.is_file()
    ]
    candidates.extend(
        candidate
        for candidate in OUTPUT_DIR.glob("run-*/latest-result*.json")
        if candidate.is_file()
    )
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: candidate.stat().st_mtime)


def load_cbom(path: Path = RESULT_PATH) -> tuple[dict[str, Any] | None, str | None]:
    """Load the CBOM JSON file and return either data or an error message."""
    cbom_path = find_cbom_path(path)
    if cbom_path is None:
        return None, f"CBOM file not found: {path}"

    try:
        with cbom_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        return None, f"CBOM file is not valid JSON: {exc}"
    except OSError as exc:
        return None, f"Unable to read CBOM file: {exc}"

    if isinstance(data, list):
        return {"cryptographic_assets": data}, None
    if not isinstance(data, dict):
        return None, "CBOM file must contain a JSON object or a list of assets."
    return data, None


def cbom_download_bytes(cbom: dict[str, Any]) -> bytes:
    return json.dumps(cbom, indent=2, ensure_ascii=False).encode("utf-8")


def load_cpg(path: Path = CPG_PATH) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def load_json_file(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def get_assets(cbom: dict[str, Any]) -> list[dict[str, Any]]:
    assets = cbom.get("cryptographic_assets", [])
    return [asset for asset in assets if isinstance(asset, dict)]


def value_at(data: dict[str, Any], *keys: str, default: Any = UNKNOWN) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    if current is None or current == "":
        return default
    return current


def as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def compute_summary(assets: list[dict[str, Any]]) -> dict[str, Any]:
    risk_counts = Counter(
        str(value_at(asset, "risk", "level", default=UNKNOWN)).lower() for asset in assets
    )
    algorithms = sorted(
        {
            str(value_at(asset, "crypto_metadata", "algorithm"))
            for asset in assets
            if value_at(asset, "crypto_metadata", "algorithm") != UNKNOWN
        }
    )
    return {
        "total": len(assets),
        "high": risk_counts.get("high", 0),
        "medium": risk_counts.get("medium", 0),
        "low": risk_counts.get("low", 0),
        "algorithms": algorithms,
    }


def asset_label(asset: dict[str, Any], index: int) -> str:
    algorithm = value_at(asset, "crypto_metadata", "algorithm")
    function = value_at(asset, "context", "function")
    if function == UNKNOWN:
        function = value_at(asset, "evidence", "summary", "api_call")
    return f"{index + 1}. {algorithm} - {function}"


def risk_badge(level: Any) -> str:
    normalized = str(level or UNKNOWN).lower()
    colors = {
        "high": ("#7f1d1d", "#fee2e2"),
        "medium": ("#854d0e", "#fef3c7"),
        "low": ("#166534", "#dcfce7"),
    }
    text_color, bg_color = colors.get(normalized, ("#374151", "#f3f4f6"))
    return (
        f"<span style='color:{text_color}; background:{bg_color}; padding:0.2rem 0.55rem; "
        "border-radius:6px; font-weight:700;'>"
        f"{normalized.upper()}</span>"
    )


def render_kv(items: list[tuple[str, Any]]) -> None:
    for label, value in items:
        if isinstance(value, list):
            value = " -> ".join(str(item) for item in value) if value else UNKNOWN
        elif isinstance(value, dict):
            value = json.dumps(value, ensure_ascii=False)
        st.markdown(f"**{label}:** `{value if value not in (None, '') else UNKNOWN}`")


def render_list(items: list[Any], empty_text: str = "No entries.") -> None:
    if not items:
        st.markdown(empty_text)
        return
    for item in items:
        if isinstance(item, dict):
            title = item.get("id") or item.get("message") or item.get("value") or "rule"
            detail = item.get("message") or item.get("explanation") or item
            st.markdown(f"- **{title}**: {detail}")
        else:
            st.markdown(f"- {item}")


def inference_value(inference: dict[str, Any], key: str) -> Any:
    block = inference.get(key, {})
    if isinstance(block, dict):
        return block.get("value", UNKNOWN)
    return block or UNKNOWN


def inference_confidence(inference: dict[str, Any]) -> Any:
    candidates = []
    for block in inference.values():
        if isinstance(block, dict) and isinstance(block.get("confidence"), (int, float)):
            candidates.append(float(block["confidence"]))
    if not candidates:
        return UNKNOWN
    return round(sum(candidates) / len(candidates), 3)


def dot_escape(value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return escaped.replace("\n", r"\n")


def node_id(prefix: str, value: Any) -> str:
    clean = "".join(ch if ch.isalnum() else "_" for ch in str(value))
    return f"{prefix}_{clean[:80]}"


def graphviz_for_function(function_name: str, assets: list[dict[str, Any]]) -> str:
    lines = [
        "digraph FunctionCryptoGraph {",
        "  graph [rankdir=LR];",
        '  node [shape=box, style="rounded,filled", color="#64748b", fillcolor="#f8fafc"];',
        '  edge [color="#94a3b8"];',
    ]
    added_nodes: set[str] = set()
    added_edges: set[tuple[str, str, str]] = set()

    def add_node(identifier: str, label: str, fill: str = "#f8fafc") -> None:
        if identifier in added_nodes:
            return
        added_nodes.add(identifier)
        lines.append(
            f'  "{dot_escape(identifier)}" [label="{dot_escape(label)}", fillcolor="{fill}"];'
        )

    def add_edge(source: str, target: str, label: str = "") -> None:
        key = (source, target, label)
        if key in added_edges:
            return
        added_edges.add(key)
        label_text = f' [label="{dot_escape(label)}"]' if label else ""
        lines.append(f'  "{dot_escape(source)}" -> "{dot_escape(target)}"{label_text};')

    selected_assets = []
    for asset in assets:
        context = asset.get("context", {}) if isinstance(asset.get("context"), dict) else {}
        call_chain = as_list(context.get("call_chain"))
        if context.get("function") == function_name or function_name in call_chain:
            selected_assets.append(asset)

    root_id = node_id("function", function_name)
    add_node(root_id, function_name, "#e0f2fe")

    for asset in selected_assets:
        context = asset.get("context", {}) if isinstance(asset.get("context"), dict) else {}
        evidence = asset.get("evidence", {}) if isinstance(asset.get("evidence"), dict) else {}
        summary = evidence.get("summary", {}) if isinstance(evidence.get("summary"), dict) else {}
        crypto = asset.get("crypto_metadata", {}) if isinstance(asset.get("crypto_metadata"), dict) else {}
        usage = asset.get("usage", {}) if isinstance(asset.get("usage"), dict) else {}
        risk = asset.get("risk", {}) if isinstance(asset.get("risk"), dict) else {}

        call_chain = as_list(context.get("call_chain")) or [context.get("function", function_name)]
        previous_id = None
        for function in call_chain:
            function_id = node_id("function", function)
            add_node(function_id, str(function), "#e0f2fe")
            if previous_id:
                add_edge(previous_id, function_id, "CALLS")
            previous_id = function_id

        api_call = summary.get("api_call", UNKNOWN)
        algorithm = crypto.get("algorithm", UNKNOWN)
        operation = usage.get("operation", UNKNOWN)
        risk_level = str(risk.get("level", UNKNOWN)).lower()
        risk_fill = {"high": "#fee2e2", "medium": "#fef3c7", "low": "#dcfce7"}.get(risk_level, "#f8fafc")
        call_id = node_id("crypto", f"{asset.get('asset_id', api_call)}")
        add_node(call_id, f"{api_call}\n{algorithm} / {operation}\nrisk: {risk_level}", risk_fill)
        add_edge(previous_id or root_id, call_id, "crypto call")

    lines.append("}")
    return "\n".join(lines)


def graphviz_for_data_flow(asset: dict[str, Any]) -> str:
    flow = asset.get("flow", {}) if isinstance(asset.get("flow"), dict) else {}
    inference = asset.get("inference", {}) if isinstance(asset.get("inference"), dict) else {}
    data_flow = inference.get("data_flow", {}) if isinstance(inference.get("data_flow"), dict) else {}
    data_flow_value = data_flow.get("value", {}) if isinstance(data_flow.get("value"), dict) else {}

    lines = [
        "digraph DataFlow {",
        "  graph [rankdir=LR];",
        '  node [shape=box, style="rounded,filled", color="#64748b", fillcolor="#f8fafc"];',
        '  edge [color="#94a3b8"];',
    ]
    added: set[str] = set()

    def add_node(identifier: str, label: str, fill: str) -> None:
        if identifier in added:
            return
        added.add(identifier)
        lines.append(
            f'  "{dot_escape(identifier)}" [label="{dot_escape(label)}", fillcolor="{fill}"];'
        )

    def add_edge(source: str, target: str, label: str) -> None:
        lines.append(f'  "{dot_escape(source)}" -> "{dot_escape(target)}" [label="{dot_escape(label)}"];')

    operation_id = "crypto_operation"
    operation_label = (
        f"{value_at(asset, 'crypto_metadata', 'algorithm')}\n"
        f"{value_at(asset, 'usage', 'operation')}\n"
        f"{value_at(asset, 'evidence', 'summary', 'api_call')}"
    )
    add_node(operation_id, operation_label, "#e0f2fe")

    source_fields = [
        ("key_source", "key"),
        ("data_source", "data"),
        ("iv_source", "iv"),
        ("nonce_source", "nonce"),
        ("salt_source", "salt"),
        ("randomness_source", "randomness"),
    ]
    for field, label in source_fields:
        value = flow.get(field)
        if value in (None, "", UNKNOWN):
            continue
        source_id = node_id("source", f"{field}:{value}")
        add_node(source_id, f"{label}\n{value}", "#dcfce7")
        add_edge(source_id, operation_id, field)

    for index, input_source in enumerate(as_list(data_flow_value.get("input_sources"))):
        if input_source in (None, "", UNKNOWN):
            continue
        source_id = node_id("inferred", f"{index}:{input_source}")
        add_node(source_id, f"inferred\n{input_source}", "#fef3c7")
        add_edge(source_id, operation_id, "inferred")

    sink = flow.get("sink", {})
    sink_label = None
    if isinstance(sink, dict) and sink:
        sink_label = sink.get("type") or sink.get("id")
    if not sink_label:
        sink_label = data_flow_value.get("output_destination")
    if sink_label:
        add_node("sink", f"sink\n{sink_label}", "#fee2e2")
        add_edge(operation_id, "sink", "outputs")

    lines.append("}")
    return "\n".join(lines)


def cpg_nodes_for_function(cpg: dict[str, Any], function_name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = [node for node in cpg.get("nodes", []) if isinstance(node, dict)]
    edges = [edge for edge in cpg.get("edges", []) if isinstance(edge, dict)]
    short_name = function_name.split(".")[-1]
    selected_nodes = [
        node
        for node in nodes
        if node.get("function") == function_name
        or node.get("name") == function_name
        or node.get("name") == short_name
    ]
    selected_ids = {node.get("id") for node in selected_nodes}
    selected_edges = [
        edge
        for edge in edges
        if edge.get("source") in selected_ids and edge.get("target") in selected_ids
    ]
    return selected_nodes, selected_edges


def graphviz_for_cpg_nodes(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], limit: int = 45) -> str:
    visible_nodes = nodes[:limit]
    visible_ids = {node.get("id") for node in visible_nodes}
    visible_edges = [
        edge
        for edge in edges
        if edge.get("source") in visible_ids and edge.get("target") in visible_ids
    ]
    lines = [
        "digraph RawFunctionCPG {",
        "  graph [rankdir=LR];",
        '  node [shape=box, style="rounded,filled", color="#64748b", fillcolor="#eef2ff"];',
        '  edge [color="#94a3b8"];',
    ]
    for node in visible_nodes:
        label = node.get("name") or node.get("kind") or node.get("id")
        detail = f"{node.get('kind', UNKNOWN)}"
        if node.get("line"):
            detail = f"{detail}:{node.get('line')}"
        node_label = f"{label}\n{detail}"
        lines.append(
            f'  "{dot_escape(node.get("id"))}" [label="{dot_escape(node_label)}"];'
        )
    for edge in visible_edges:
        lines.append(
            f'  "{dot_escape(edge.get("source"))}" -> "{dot_escape(edge.get("target"))}" '
            f'[label="{dot_escape(edge.get("kind", ""))}"];'
        )
    lines.append("}")
    return "\n".join(lines)


def function_names_from_assets(assets: list[dict[str, Any]]) -> list[str]:
    names: set[str] = set()
    for asset in assets:
        context = asset.get("context", {}) if isinstance(asset.get("context"), dict) else {}
        function = context.get("function")
        if function and function != UNKNOWN:
            names.add(str(function))
        for call in as_list(context.get("call_chain")):
            if call and call != UNKNOWN:
                names.add(str(call))
    return sorted(names)


def render_function_graph_screen(assets: list[dict[str, Any]]) -> None:
    st.header("Function Graph")
    st.markdown("Pick a function to see the extracted crypto calls and call-chain relationships around it.")
    cpg = load_cpg()
    if cpg:
        st.info("Loaded `/app/output/cpg.json` for raw CPG context.")
    else:
        st.info("No `/app/output/cpg.json` found. Showing the function graph derived from CBOM call-chain evidence.")

    functions = function_names_from_assets(assets)
    if not functions:
        st.warning("No function names found in the CBOM context.")
        return

    selected_function = st.selectbox("Function", functions)
    related_assets = [
        asset
        for asset in assets
        if selected_function in as_list(value_at(asset, "context", "call_chain", default=[]))
        or value_at(asset, "context", "function") == selected_function
    ]

    summary_cols = st.columns(4)
    summary_cols[0].metric("Crypto calls", len(related_assets))
    summary_cols[1].metric(
        "Algorithms",
        len(
            {
                value_at(asset, "crypto_metadata", "algorithm")
                for asset in related_assets
                if value_at(asset, "crypto_metadata", "algorithm") != UNKNOWN
            }
        ),
    )
    summary_cols[2].metric(
        "High risk",
        sum(1 for asset in related_assets if str(value_at(asset, "risk", "level")).lower() == "high"),
    )
    summary_cols[3].metric(
        "Cross-function",
        sum(1 for asset in related_assets if value_at(asset, "graph_context", "cross_function_flow", default=False)),
    )

    if not related_assets:
        st.info("No crypto assets were attached to this function.")
        return

    st.markdown("### Crypto Call Graph")
    st.graphviz_chart(graphviz_for_function(selected_function, related_assets), use_container_width=True)

    if cpg:
        cpg_nodes, cpg_edges = cpg_nodes_for_function(cpg, selected_function)
        with st.expander("Raw CPG nodes for this function"):
            cpg_cols = st.columns(2)
            cpg_cols[0].metric("Function CPG nodes", len(cpg_nodes))
            cpg_cols[1].metric("Function CPG edges", len(cpg_edges))
            if cpg_nodes:
                st.graphviz_chart(graphviz_for_cpg_nodes(cpg_nodes, cpg_edges), use_container_width=True)
                if len(cpg_nodes) > 45:
                    st.caption(f"Showing first 45 of {len(cpg_nodes)} nodes.")
            else:
                st.markdown("No raw CPG nodes matched this function name.")

    st.markdown("### Extracted Operations")
    for asset in related_assets:
        crypto = asset.get("crypto_metadata", {}) if isinstance(asset.get("crypto_metadata"), dict) else {}
        usage = asset.get("usage", {}) if isinstance(asset.get("usage"), dict) else {}
        evidence = asset.get("evidence", {}) if isinstance(asset.get("evidence"), dict) else {}
        summary = evidence.get("summary", {}) if isinstance(evidence.get("summary"), dict) else {}
        st.markdown(
            f"- **{summary.get('api_call', UNKNOWN)}**: "
            f"`{crypto.get('algorithm', UNKNOWN)}` / `{usage.get('operation', UNKNOWN)}` "
            f"risk `{value_at(asset, 'risk', 'level')}`"
        )

    with st.expander("Graph details"):
        for asset in related_assets:
            st.markdown(f"**{asset_label(asset, related_assets.index(asset))}**")
            render_kv(
                [
                    ("Call chain", as_list(value_at(asset, "context", "call_chain", default=[]))),
                    ("Edge kinds", as_list(value_at(asset, "graph_context", "edge_kinds", default=[]))),
                    ("Dataflow steps", value_at(asset, "graph_context", "dataflow_steps")),
                    ("Node ref", value_at(asset, "evidence", "debug", "node_ref")),
                ]
            )


def render_data_flow_screen(assets: list[dict[str, Any]]) -> None:
    st.header("Data Flow")
    st.markdown("Trace where cryptographic inputs come from and where each operation sends its output.")

    labels = [asset_label(asset, index) for index, asset in enumerate(assets)]
    selected_label = st.selectbox("Asset", labels)
    asset = assets[labels.index(selected_label)]
    flow = asset.get("flow", {}) if isinstance(asset.get("flow"), dict) else {}
    inference = asset.get("inference", {}) if isinstance(asset.get("inference"), dict) else {}
    data_flow = inference.get("data_flow", {}) if isinstance(inference.get("data_flow"), dict) else {}
    data_flow_value = data_flow.get("value", {}) if isinstance(data_flow.get("value"), dict) else {}
    variable_flows = as_list(flow.get("variable_flows"))

    metric_cols = st.columns(4)
    metric_cols[0].metric("Algorithm", value_at(asset, "crypto_metadata", "algorithm"))
    metric_cols[1].metric("Operation", value_at(asset, "usage", "operation"))
    metric_cols[2].metric("Variable flows", len(variable_flows))
    metric_cols[3].metric("Inference confidence", data_flow.get("confidence", UNKNOWN))

    st.markdown("### Flow Graph")
    st.graphviz_chart(graphviz_for_data_flow(asset), use_container_width=True)

    st.markdown("### Sources")
    render_kv(
        [
            ("Key source", flow.get("key_source", UNKNOWN)),
            ("Data source", flow.get("data_source", UNKNOWN)),
            ("IV source", flow.get("iv_source", UNKNOWN)),
            ("Nonce source", flow.get("nonce_source", UNKNOWN)),
            ("Salt source", flow.get("salt_source", UNKNOWN)),
            ("Randomness source", flow.get("randomness_source", UNKNOWN)),
        ]
    )

    st.markdown("### Sink")
    sink = flow.get("sink")
    if isinstance(sink, dict) and sink:
        render_kv([("Type", sink.get("type", UNKNOWN)), ("ID", sink.get("id", UNKNOWN))])
    else:
        render_kv([("Output destination", data_flow_value.get("output_destination", UNKNOWN))])

    st.markdown("### Inferred Data Flow")
    render_kv(
        [
            ("Input sources", as_list(data_flow_value.get("input_sources"))),
            ("Output destination", data_flow_value.get("output_destination", UNKNOWN)),
            ("Method", data_flow.get("method", UNKNOWN)),
            ("Confidence", data_flow.get("confidence", UNKNOWN)),
        ]
    )
    st.markdown("**Evidence:**")
    render_list(as_list(data_flow.get("evidence")), "No inference evidence available.")

    st.markdown("### Variable Flows")
    if variable_flows:
        for item in variable_flows:
            if not isinstance(item, dict):
                st.markdown(f"- {item}")
                continue
            source = item.get("source", {})
            source_text = json.dumps(source, ensure_ascii=False) if isinstance(source, dict) else str(source)
            st.markdown(
                f"- Argument `{item.get('argument', UNKNOWN)}` via `{item.get('via', UNKNOWN)}` "
                f"from `{source_text}` reaches sink: `{item.get('reaches_sink', UNKNOWN)}`"
            )
    else:
        st.markdown("No variable-level flow evidence for this asset.")

    with st.expander("Raw flow details"):
        st.json({"flow": flow, "inference_data_flow": data_flow})


def render_exports_screen(cbom: dict[str, Any]) -> None:
    st.header("Exports")
    st.markdown("Download the native CryptoGraph CBOM or the CycloneDX hybrid CBOM.")

    st.markdown("### Native CryptoGraph CBOM")
    st.download_button(
        "Download native CBOM JSON",
        data=cbom_download_bytes(cbom),
        file_name="cbom-result.json",
        mime="application/json",
        key="download-native-cbom",
    )

    st.markdown("### CycloneDX Hybrid CBOM")
    cyclonedx = load_json_file(CYCLONEDX_PATH)
    if cyclonedx:
        st.success("CycloneDX CBOM found at `/app/output/cyclonedx-cbom.json`.")
        cols = st.columns(4)
        cols[0].metric("Format", cyclonedx.get("bomFormat", UNKNOWN))
        cols[1].metric("Spec", cyclonedx.get("specVersion", UNKNOWN))
        cols[2].metric("Components", len(as_list(cyclonedx.get("components"))))
        cols[3].metric("Dependencies", len(as_list(cyclonedx.get("dependencies"))))
        st.download_button(
            "Download CycloneDX CBOM JSON",
            data=cbom_download_bytes(cyclonedx),
            file_name="cyclonedx-cbom.json",
            mime="application/json",
            key="download-cyclonedx-cbom",
        )
        with st.expander("CycloneDX metadata preview"):
            st.json(cyclonedx.get("metadata", {}))
    else:
        st.warning("CycloneDX CBOM has not been generated yet.")
        st.code(
            "docker compose run --rm cryptograph cyclonedx "
            "--input /app/output/result.json "
            "--output /app/output/cyclonedx-cbom.json",
            language="powershell",
        )


def render_fraunhofer_screen(cbom: dict[str, Any], assets: list[dict[str, Any]]) -> None:
    analysis = cbom.get("analysis", {}) if isinstance(cbom.get("analysis"), dict) else {}
    graph = analysis.get("graph", {}) if isinstance(analysis.get("graph"), dict) else {}
    methodology = analysis.get("methodology", {}) if isinstance(analysis.get("methodology"), dict) else {}
    limitations = as_list(analysis.get("limitations"))

    st.header("Fraunhofer / CPG")
    st.markdown("How CryptoGraph used the code property graph while extracting cryptographic assets.")

    graph_cols = st.columns(4)
    graph_cols[0].metric("Graph available", "yes" if graph.get("available") else "no")
    graph_cols[1].metric("Backend", graph.get("backend", UNKNOWN))
    graph_cols[2].metric("Nodes", graph.get("node_count", 0))
    graph_cols[3].metric("Edges", graph.get("edge_count", 0))

    render_kv(
        [
            ("Graph root", graph.get("root", UNKNOWN)),
            ("Input", value_at(analysis, "scope", "input")),
            ("Language", value_at(analysis, "scope", "language")),
        ]
    )

    node_kinds = graph.get("node_kinds", {})
    edge_kinds = graph.get("edge_kinds", {})
    dist_cols = st.columns(2)
    with dist_cols[0]:
        st.markdown("### CPG Nodes")
        if isinstance(node_kinds, dict) and node_kinds:
            st.json(node_kinds)
        else:
            st.markdown("No node distribution available.")
    with dist_cols[1]:
        st.markdown("### CPG Edges")
        if isinstance(edge_kinds, dict) and edge_kinds:
            st.json(edge_kinds)
        else:
            st.markdown("No edge distribution available.")

    st.markdown("### How It Was Used")
    render_kv(
        [
            ("Asset classification", methodology.get("asset_classification", UNKNOWN)),
            ("Algorithm normalization", methodology.get("algorithm_normalization", UNKNOWN)),
            ("Risk scoring", methodology.get("risk_scoring", UNKNOWN)),
            ("Rule filtering", methodology.get("rule_filtering", UNKNOWN)),
            ("Inference", methodology.get("inference", UNKNOWN)),
        ]
    )

    if limitations:
        with st.expander("Known limitations"):
            render_list(limitations)

    if not assets:
        st.warning("No assets available for graph context inspection.")
        return

    st.markdown("### Asset Graph Context")
    labels = [asset_label(asset, index) for index, asset in enumerate(assets)]
    selected_label = st.selectbox("Inspect graph context for asset", labels)
    asset = assets[labels.index(selected_label)]

    graph_context = asset.get("graph_context", {}) if isinstance(asset.get("graph_context"), dict) else {}
    context = asset.get("context", {}) if isinstance(asset.get("context"), dict) else {}
    evidence = asset.get("evidence", {}) if isinstance(asset.get("evidence"), dict) else {}
    debug = evidence.get("debug", {}) if isinstance(evidence.get("debug"), dict) else {}
    edges_summary = (
        debug.get("graph_edges_summary", {})
        if isinstance(debug.get("graph_edges_summary"), dict)
        else {}
    )

    context_cols = st.columns(4)
    context_cols[0].metric("Call depth", graph_context.get("call_depth", 0))
    context_cols[1].metric("Cross-function", "yes" if graph_context.get("cross_function_flow") else "no")
    context_cols[2].metric("Dataflow steps", graph_context.get("dataflow_steps", 0))
    context_cols[3].metric("Graph edges", edges_summary.get("incoming_count", 0) + edges_summary.get("outgoing_count", 0))

    render_kv(
        [
            ("File", context.get("file", UNKNOWN)),
            ("Function", context.get("function", UNKNOWN)),
            ("Call chain", as_list(context.get("call_chain"))),
            ("Edge kinds", as_list(graph_context.get("edge_kinds"))),
        ]
    )

    with st.expander("Fraunhofer evidence debug"):
        st.json(
            {
                "node_ref": debug.get("node_ref"),
                "location_ref": debug.get("location_ref"),
                "raw_node_id": debug.get("raw_node_id"),
                "graph_edges_summary": edges_summary,
                "argument_signals": debug.get("argument_signals", []),
            }
        )


def render_asset(asset: dict[str, Any]) -> None:
    crypto = asset.get("crypto_metadata", {}) if isinstance(asset.get("crypto_metadata"), dict) else {}
    usage = asset.get("usage", {}) if isinstance(asset.get("usage"), dict) else {}
    context = asset.get("context", {}) if isinstance(asset.get("context"), dict) else {}
    flow = asset.get("flow", {}) if isinstance(asset.get("flow"), dict) else {}
    risk = asset.get("risk", {}) if isinstance(asset.get("risk"), dict) else {}
    inference = asset.get("inference", {}) if isinstance(asset.get("inference"), dict) else {}
    evidence = asset.get("evidence", {}) if isinstance(asset.get("evidence"), dict) else {}

    st.header(value_at(asset, "crypto_metadata", "algorithm"))
    st.caption(value_at(asset, "asset_id", default="asset"))

    st.markdown("### Crypto Info")
    render_kv(
        [
            ("Algorithm", crypto.get("algorithm", UNKNOWN)),
            ("Primitive", crypto.get("primitive", UNKNOWN)),
            ("Mode", crypto.get("mode", UNKNOWN)),
            ("Operation", usage.get("operation", UNKNOWN)),
        ]
    )

    st.markdown("### Context")
    render_kv(
        [
            ("File", context.get("file", UNKNOWN)),
            ("Function", context.get("function", UNKNOWN)),
            ("Call chain", as_list(context.get("call_chain"))),
            ("Usage context", inference_value(inference, "usage_context")),
        ]
    )

    st.markdown("### Flow")
    render_kv(
        [
            ("Key source", flow.get("key_source", UNKNOWN)),
            ("Data source", flow.get("data_source", UNKNOWN)),
            ("IV source", flow.get("iv_source", UNKNOWN)),
            ("Nonce source", flow.get("nonce_source", UNKNOWN)),
            ("Salt source", flow.get("salt_source", UNKNOWN)),
        ]
    )

    st.markdown("### Risk")
    st.markdown(f"**Level:** {risk_badge(risk.get('level'))}", unsafe_allow_html=True)
    render_kv([("Confidence", risk.get("confidence", UNKNOWN))])
    st.markdown("**Tags:**")
    render_list(as_list(risk.get("tags")), "No risk tags.")

    st.markdown("### Rules")
    render_list(as_list(asset.get("rules")), "No rules matched.")

    st.markdown("### Inference")
    render_kv(
        [
            ("Intent", inference_value(inference, "intent")),
            ("Derived from", inference_value(inference, "derivation_path")),
            ("Confidence", inference_confidence(inference)),
        ]
    )

    st.markdown("### Evidence")
    summary = evidence.get("summary", {}) if isinstance(evidence.get("summary"), dict) else {}
    debug = evidence.get("debug", {}) if isinstance(evidence.get("debug"), dict) else {}
    if summary:
        st.json(summary)
    else:
        st.markdown("No evidence summary available.")
    with st.expander("Debug evidence"):
        if debug:
            st.json(debug)
        else:
            st.markdown("No debug evidence available.")


def main() -> None:
    st.set_page_config(page_title="CBOM Viewer", layout="wide")
    st.title("CBOM Viewer")
    st.markdown("What cryptographic operations are happening in this code and how are they used?")

    cbom, error = load_cbom()
    if error:
        st.error(error)
        st.info("Run the analyzer first, or mount the host output directory to /app/output.")
        return

    active_path = find_cbom_path()
    if active_path and active_path != RESULT_PATH:
        st.info(f"Loaded latest run artifact: `{active_path}`")

    assets = get_assets(cbom or {})
    summary = compute_summary(assets)

    metric_cols = st.columns(4)
    metric_cols[0].metric("Assets", summary["total"])
    metric_cols[1].metric("High risk", summary["high"])
    metric_cols[2].metric("Medium risk", summary["medium"])
    metric_cols[3].metric("Low risk", summary["low"])

    st.markdown("**Algorithms:**")
    st.markdown(", ".join(f"`{algorithm}`" for algorithm in summary["algorithms"]) or "No algorithms found.")
    if not assets:
        st.warning("No cryptographic assets found in the CBOM file.")
        return

    screen = st.sidebar.radio("Screen", ["CBOM Assets", "Fraunhofer / CPG", "Function Graph", "Data Flow", "Exports"])
    if screen == "Fraunhofer / CPG":
        render_fraunhofer_screen(cbom or {}, assets)
        return
    if screen == "Function Graph":
        render_function_graph_screen(assets)
        return
    if screen == "Data Flow":
        render_data_flow_screen(assets)
        return
    if screen == "Exports":
        render_exports_screen(cbom or {})
        return

    labels = [asset_label(asset, index) for index, asset in enumerate(assets)]
    selected_label = st.sidebar.selectbox("Cryptographic assets", labels)
    selected_asset = assets[labels.index(selected_label)]
    render_asset(selected_asset)


if __name__ == "__main__":
    main()
