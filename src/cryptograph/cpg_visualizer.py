from __future__ import annotations

import html
import json
import math
from collections import Counter
from pathlib import Path

from cryptograph.models import GraphNode, NormalizedGraph


def write_graph_json(graph: NormalizedGraph, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(graph.model_dump(mode="json"), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def write_dot(graph: NormalizedGraph, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "digraph CryptoGraphCPG {",
        '  graph [rankdir=LR, bgcolor="white", fontname="Arial"];',
        '  node [shape=box, style="rounded,filled", fillcolor="#eef5ff", color="#5d6f86", fontname="Arial"];',
        '  edge [color="#8898aa", fontname="Arial"];',
    ]
    for node in graph.nodes:
        label = _node_label(node)
        lines.append(f'  "{_dot_escape(node.id)}" [label="{_dot_escape(label)}"];')
    for edge in graph.edges:
        lines.append(
            f'  "{_dot_escape(edge.source)}" -> "{_dot_escape(edge.target)}" '
            f'[label="{_dot_escape(edge.kind)}"];'
        )
    lines.append("}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_html(graph: NormalizedGraph, output_path: Path, max_nodes: int = 300) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    nodes = graph.nodes[:max_nodes]
    node_ids = {node.id for node in nodes}
    edges = [edge for edge in graph.edges if edge.source in node_ids and edge.target in node_ids]
    positions = _layout(nodes)
    kind_counts = Counter(node.kind for node in graph.nodes)
    edge_counts = Counter(edge.kind for edge in graph.edges)

    svg_edges = []
    for edge in edges:
        source = positions.get(edge.source)
        target = positions.get(edge.target)
        if not source or not target:
            continue
        svg_edges.append(
            f'<line x1="{source[0]}" y1="{source[1]}" x2="{target[0]}" y2="{target[1]}" '
            f'class="edge"><title>{html.escape(edge.kind)}</title></line>'
        )

    svg_nodes = []
    for node in nodes:
        x, y = positions[node.id]
        title = html.escape(_node_label(node))
        short = html.escape(_short_label(node))
        svg_nodes.append(
            f'<g class="node">'
            f'<circle cx="{x}" cy="{y}" r="22"><title>{title}</title></circle>'
            f'<text x="{x}" y="{y + 4}" text-anchor="middle">{short}</text>'
            f"</g>"
        )

    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(node.kind)}</td>"
        f"<td>{html.escape(node.name or '')}</td>"
        f"<td>{html.escape(_node_detail(node))}</td>"
        f"<td>{html.escape(node.file)}</td>"
        f"<td>{'' if node.line is None else node.line}</td>"
        f"<td>{html.escape(node.function or '')}</td>"
        f"<td><code>{html.escape(node.id)}</code></td>"
        "</tr>"
        for node in nodes
    )
    counts = ", ".join(f"{html.escape(kind)}: {count}" for kind, count in sorted(kind_counts.items()))
    edge_kinds = ", ".join(f"{html.escape(kind)}: {count}" for kind, count in sorted(edge_counts.items()))
    truncated = ""
    if len(graph.nodes) > max_nodes:
        truncated = f"<p class=\"notice\">Showing first {max_nodes} of {len(graph.nodes)} nodes.</p>"

    output_path.write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CryptoGraph CPG Viewer</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; color: #17202a; background: #f7f9fb; }}
    header {{ padding: 24px 32px; background: #ffffff; border-bottom: 1px solid #d8dee7; }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    p {{ margin: 6px 0; }}
    main {{ padding: 24px 32px; }}
    .panel {{ background: #ffffff; border: 1px solid #d8dee7; border-radius: 8px; overflow: hidden; }}
    svg {{ width: 100%; height: 640px; display: block; background: #ffffff; }}
    .edge {{ stroke: #8fa0b3; stroke-width: 1.4; }}
    .node circle {{ fill: #e8f1ff; stroke: #4e6f94; stroke-width: 1.5; }}
    .node text {{ font-size: 10px; fill: #17202a; pointer-events: none; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #ffffff; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #e3e8ef; text-align: left; font-size: 14px; }}
    th {{ background: #eef2f6; }}
    code {{ font-size: 12px; word-break: break-all; }}
    .notice {{ padding: 12px 14px; background: #fff8df; border: 1px solid #ead891; border-radius: 8px; }}
  </style>
</head>
<body>
  <header>
    <h1>CryptoGraph CPG Viewer</h1>
    <p><strong>Backend:</strong> {html.escape(graph.backend)}</p>
    <p><strong>Root:</strong> {html.escape(graph.root)}</p>
    <p><strong>Nodes:</strong> {len(graph.nodes)} | <strong>Edges:</strong> {len(graph.edges)}</p>
    <p><strong>Node kinds:</strong> {counts}</p>
    <p><strong>Edge kinds:</strong> {edge_kinds or "none"}</p>
  </header>
  <main>
    {truncated}
    <section class="panel">
      <svg viewBox="0 0 1200 720" role="img" aria-label="Normalized CPG graph">
        {"".join(svg_edges)}
        {"".join(svg_nodes)}
      </svg>
    </section>
    <table>
      <thead>
        <tr><th>Kind</th><th>Name</th><th>Detail</th><th>File</th><th>Line</th><th>Function</th><th>Node ID</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )


def _layout(nodes: list[GraphNode]) -> dict[str, tuple[int, int]]:
    if not nodes:
        return {}
    center_x = 600
    center_y = 350
    radius = min(300, max(110, len(nodes) * 8))
    positions = {}
    for index, node in enumerate(nodes):
        angle = (2 * math.pi * index) / len(nodes)
        positions[node.id] = (
            int(center_x + radius * math.cos(angle)),
            int(center_y + radius * math.sin(angle)),
        )
    return positions


def _node_label(node: GraphNode) -> str:
    location = f"{node.file}:{node.line}" if node.line is not None else node.file
    name = _node_detail(node) or node.name or node.kind
    function = f" in {node.function}" if node.function else ""
    return f"{node.kind}: {name}\\n{location}{function}"


def _short_label(node: GraphNode) -> str:
    detail = _node_detail(node)
    label = detail or node.name or node.kind
    return label if len(label) <= 12 else f"{label[:10]}.."


def _node_detail(node: GraphNode) -> str:
    callee = node.properties.get("callee")
    code = node.properties.get("code")
    if isinstance(callee, str) and callee:
        return callee
    if isinstance(code, str) and code:
        return code
    return ""


def _dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
