from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from cryptograph.utils import load_json


def build_html_report(input_json: Path, output_html: Path) -> None:
    cbom = load_json(input_json)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(_render(cbom), encoding="utf-8")


def _render(cbom: dict[str, Any]) -> str:
    components = cbom.get("cryptographic_assets", cbom.get("components", []))
    metadata = cbom.get("metadata", {})
    summary = cbom.get("summary", {})
    by_risk = summary.get("by_risk", {})
    by_primitive = summary.get("by_primitive", {})
    payload = html.escape(json.dumps(cbom, indent=2))

    rows = "\n".join(_component_row(component) for component in components)
    risk_cards = "\n".join(_metric_card(risk, count, f"risk-{risk}") for risk, count in by_risk.items())
    primitive_cards = "\n".join(_metric_card(name, count, "primitive") for name, count in by_primitive.items())

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CryptoGraph Report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #17202a;
      --muted: #5d6875;
      --line: #d7dde4;
      --panel: #ffffff;
      --soft: #f4f7f9;
      --high: #c7362f;
      --medium: #9a6a00;
      --info: #2d6a8e;
      --accent: #176b5d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font: 15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif;
      color: var(--ink);
      background: var(--soft);
    }}
    header {{
      padding: 32px clamp(18px, 4vw, 56px);
      background: #ffffff;
      border-bottom: 1px solid var(--line);
    }}
    h1, h2, h3 {{ margin: 0; line-height: 1.15; }}
    h1 {{ font-size: clamp(28px, 5vw, 48px); }}
    h2 {{ font-size: 22px; margin-bottom: 14px; }}
    main {{ padding: 28px clamp(18px, 4vw, 56px) 56px; }}
    .meta {{
      margin-top: 14px;
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 10px 18px;
    }}
    .band {{
      margin-bottom: 26px;
      padding: 20px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-left: 5px solid var(--accent);
      border-radius: 8px;
      padding: 14px;
      background: #fff;
    }}
    .metric.risk-high {{ border-left-color: var(--high); }}
    .metric.risk-medium {{ border-left-color: var(--medium); }}
    .metric.risk-info {{ border-left-color: var(--info); }}
    .metric strong {{ display: block; font-size: 26px; }}
    .metric span {{ color: var(--muted); overflow-wrap: anywhere; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      text-align: left;
      padding: 11px 12px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{ background: #eef3f6; font-size: 13px; color: #34424f; }}
    tr:last-child td {{ border-bottom: 0; }}
    code {{
      background: #eef3f6;
      border-radius: 6px;
      padding: 2px 5px;
      overflow-wrap: anywhere;
    }}
    .pill {{
      display: inline-block;
      border-radius: 8px;
      padding: 3px 8px;
      font-weight: 700;
      font-size: 12px;
      color: #fff;
      background: var(--info);
    }}
    .pill.high {{ background: var(--high); }}
    .pill.medium {{ background: var(--medium); }}
    details {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px 14px;
    }}
    pre {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      margin: 12px 0 0;
      color: #26323d;
    }}
  </style>
</head>
<body>
  <header>
    <h1>CryptoGraph Report</h1>
    <div class="meta">
      <span>Source: <code>{html.escape(str(metadata.get("source", "")))}</code></span>
      <span>Backend: <code>{html.escape(str(metadata.get("backend", "")))}</code></span>
      <span>Generated: <code>{html.escape(str(metadata.get("generated_at", "")))}</code></span>
    </div>
  </header>
  <main>
    <section class="band">
      <h2>Risk Summary</h2>
      <div class="metrics">
        {_metric_card("total", summary.get("total_assets", summary.get("total_components", len(components))), "primitive")}
        {risk_cards}
      </div>
    </section>
    <section class="band">
      <h2>Primitive Summary</h2>
      <div class="metrics">{primitive_cards}</div>
    </section>
    <section class="band">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Risk</th>
            <th>API</th>
            <th>Primitive</th>
            <th>Location</th>
            <th>Context</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    <details>
      <summary>Raw CBOM-like JSON</summary>
      <pre>{payload}</pre>
    </details>
  </main>
</body>
</html>
"""


def _metric_card(label: str, count: Any, css_class: str) -> str:
    return f"""<div class="metric {html.escape(css_class)}">
  <strong>{html.escape(str(count))}</strong>
  <span>{html.escape(str(label))}</span>
</div>"""


def _component_row(component: dict[str, Any]) -> str:
    if "crypto_metadata" in component:
        return _custom_asset_row(component)

    evidence = component.get("evidence", {})
    context = component.get("context", {})
    signals = context.get("signals", {})
    risk = str(component.get("risk", "info"))
    rules = component.get("rules", [])
    rule_text = "; ".join(rule.get("id", "") for rule in rules) or "none"
    args = ", ".join(evidence.get("arguments", [])) or "none"
    location = f"{evidence.get('file')}:{evidence.get('line')}"
    if evidence.get("function"):
        location += f" in {evidence.get('function')}"

    return f"""<tr>
  <td><span class="pill {html.escape(risk)}">{html.escape(risk)}</span></td>
  <td><code>{html.escape(str(component.get("api_name", "")))}</code><br>{html.escape(str(component.get("algorithm", "")))}</td>
  <td>{html.escape(str(component.get("primitive", "")))}<br><small>{html.escape(str(component.get("provider", "")))}</small></td>
  <td><code>{html.escape(location)}</code></td>
  <td>args: <code>{html.escape(args)}</code><br>mode: <code>{html.escape(str(signals.get("mode")))}</code><br>rules: <code>{html.escape(rule_text)}</code></td>
</tr>"""


def _custom_asset_row(asset: dict[str, Any]) -> str:
    crypto = asset.get("crypto_metadata", {})
    code = asset.get("context", asset.get("code_context", {}))
    risk_block = asset.get("risk", asset.get("inference", {}))
    evidence = asset.get("evidence", {})
    risk = str(risk_block.get("level", risk_block.get("risk_level", "info")))
    rules = evidence.get("rules", [])
    rule_text = "; ".join(rule.get("id", "") for rule in rules) or "none"
    args = ", ".join(evidence.get("arguments", [])) or "none"
    location = f"{code.get('file')}:{code.get('line')}"
    if code.get("function"):
        location += f" in {code.get('function')}"

    return f"""<tr>
  <td><span class="pill {html.escape(risk)}">{html.escape(risk)}</span></td>
  <td><code>{html.escape(str(evidence.get("api_call", "")))}</code><br>{html.escape(str(crypto.get("algorithm", "")))}</td>
  <td>{html.escape(str(crypto.get("primitive", "")))}<br><small>{html.escape(str(crypto.get("provider", "")))}</small></td>
  <td><code>{html.escape(location)}</code></td>
  <td>args: <code>{html.escape(args)}</code><br>mode: <code>{html.escape(str(crypto.get("mode")))}</code><br>confidence: <code>{html.escape(str(risk_block.get("confidence", "")))}</code><br>rules: <code>{html.escape(rule_text)}</code></td>
</tr>"""
