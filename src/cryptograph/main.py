from __future__ import annotations

import argparse
from pathlib import Path

from cryptograph.cbom_builder import build_cbom
from cryptograph.context_extractor import enrich_context
from cryptograph.cpg_loader import CpgLoadError, load_graph
from cryptograph.cpg_visualizer import write_dot, write_graph_json, write_html
from cryptograph.crypto_matcher import find_crypto_calls
from cryptograph.manifest import write_manifest
from cryptograph.report_builder import build_html_report
from cryptograph.utils import new_run_dir, path_in_run_dir, project_path, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cryptograph")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan Python source and emit CryptoGraph CBOM.")
    scan.add_argument("--input", required=True, type=Path, help="Source file or directory to scan.")
    scan.add_argument("--output", required=True, type=Path, help="Path for CryptoGraph CBOM JSON output.")
    scan.add_argument(
        "--backend",
        choices=["fraunhofer", "fraunhofer-strict", "ast-lite"],
        default="fraunhofer",
        help=(
            "Graph backend to use. fraunhofer may fall back to ast-lite; "
            "fraunhofer-strict fails instead of falling back."
        ),
    )
    scan.add_argument("--mappings", type=Path, default=project_path("config", "api_mappings.json"))
    scan.add_argument("--rules", type=Path, default=project_path("config", "rules.json"))
    scan.add_argument("--source-sinks", type=Path, default=project_path("config", "source_sinks.json"))
    scan.add_argument("--report", type=Path, help="Optional HTML report path.")
    scan.add_argument("--run-dir", type=Path, help="Directory for all artifacts in this scan run.")

    graph = subparsers.add_parser("graph", help="Export and visualize the normalized CPG graph.")
    graph.add_argument("--input", required=True, type=Path, help="Source file or directory to graph.")
    graph.add_argument(
        "--backend",
        choices=["fraunhofer", "fraunhofer-strict", "ast-lite"],
        default="fraunhofer-strict",
        help="Graph backend to use for visualization.",
    )
    graph.add_argument("--output", type=Path, help="Normalized graph JSON output path.")
    graph.add_argument("--dot", type=Path, help="Graphviz DOT output path.")
    graph.add_argument("--html", type=Path, help="Standalone HTML viewer output path.")
    graph.add_argument("--run-dir", type=Path, help="Directory for all artifacts in this graph run.")

    report = subparsers.add_parser("report", help="Build an HTML report from CryptoGraph CBOM JSON.")
    report.add_argument("--input", required=True, type=Path, help="CryptoGraph CBOM JSON input.")
    report.add_argument("--output", required=True, type=Path, help="HTML report output.")

    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "graph":
            return _graph(args)
    except CpgLoadError as exc:
        print(f"CryptoGraph CPG error: {exc}")
        return 2
    if args.command == "report":
        build_html_report(args.input, args.output)
        print(f"Wrote CryptoGraph HTML report to {args.output}")
        return 0
    return 1


def _scan(args: argparse.Namespace) -> int:
    run_dir = _resolve_run_dir(args.run_dir)
    args.output = path_in_run_dir(args.output, run_dir)
    args.report = path_in_run_dir(args.report, run_dir)
    graph = load_graph(args.input, args.backend)
    findings = find_crypto_calls(graph, args.mappings, args.rules)
    findings = enrich_context(findings, graph, args.source_sinks)
    cbom = build_cbom(findings, source=str(args.input), backend=graph.backend, graph=graph, run_id=run_dir.name)
    write_json(args.output, cbom)
    if args.report:
        build_html_report(args.output, args.report)
    manifest_path = write_manifest(
        run_dir=run_dir,
        command="scan",
        source=args.input,
        backend=graph.backend,
        graph=graph,
        findings=findings,
        artifacts={"cbom": args.output, "report": args.report},
        config_paths=[args.mappings, args.rules, args.source_sinks],
    )
    print(f"Wrote {len(findings)} cryptographic findings to {args.output}")
    if args.report:
        print(f"Wrote CryptoGraph HTML report to {args.report}")
    print(f"Wrote run manifest to {manifest_path}")
    print(f"Run artifacts directory: {run_dir}")
    return 0


def _graph(args: argparse.Namespace) -> int:
    run_dir = _resolve_run_dir(args.run_dir)
    if not args.output and not args.dot and not args.html:
        args.output = run_dir / "cpg.json"
        args.dot = run_dir / "cpg.dot"
        args.html = run_dir / "cpg.html"
    else:
        args.output = path_in_run_dir(args.output, run_dir)
        args.dot = path_in_run_dir(args.dot, run_dir)
        args.html = path_in_run_dir(args.html, run_dir)
    graph = load_graph(args.input, args.backend)
    wrote_anything = False
    if args.output:
        write_graph_json(graph, args.output)
        print(f"Wrote normalized graph JSON to {args.output}")
        wrote_anything = True
    if args.dot:
        write_dot(graph, args.dot)
        print(f"Wrote Graphviz DOT graph to {args.dot}")
        wrote_anything = True
    if args.html:
        write_html(graph, args.html)
        print(f"Wrote CPG HTML viewer to {args.html}")
        wrote_anything = True
    manifest_path = write_manifest(
        run_dir=run_dir,
        command="graph",
        source=args.input,
        backend=graph.backend,
        graph=graph,
        artifacts={"graph_json": args.output, "graph_dot": args.dot, "graph_html": args.html},
    )
    if not wrote_anything:
        print(f"Loaded graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges from {graph.backend}")
    else:
        print(f"Wrote run manifest to {manifest_path}")
        print(f"Run artifacts directory: {run_dir}")
    return 0


def _resolve_run_dir(run_dir: Path | None) -> Path:
    if run_dir:
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir
    return new_run_dir()


if __name__ == "__main__":
    raise SystemExit(main())
