from __future__ import annotations

import html
import json
from typing import Any


def render_html(job: dict[str, Any], intelligence: dict[str, Any]) -> str:
    result = job["result"]
    verification = result.get("verification") or {}
    explanation = intelligence.get("explanation", {})
    escaped = html.escape
    rows = []
    for side in ("vulnerable", "patched"):
        artifact = result["artifacts"][side]
        analysis = artifact["analysis"]
        rows.append(
            "<tr><th>{}</th><td><code>{}</code></td><td>{}</td><td>{} functions</td></tr>".format(
                escaped(side.title()), escaped(artifact["sha256"]),
                escaped(analysis.get("analyzer") or "metadata-only"),
                len(analysis.get("functions", [])),
            )
        )
    solver_rows = ""
    if verification:
        solver_rows = "".join(
            f"<tr><th>{escaped(side.title())}</th><td>{escaped(verification.get(side, {}).get('status', 'INCONCLUSIVE'))}</td>"
            f"<td>{escaped(verification.get(side, {}).get('solver_result', 'not-run'))}</td>"
            f"<td>{escaped(verification.get(side, {}).get('reason') or '—')}</td></tr>"
            for side in ("vulnerable", "patched")
        )
    limitations = "".join(f"<li>{escaped(item)}</li>" for item in result.get("limitations", []) + result.get("abstentions", []))
    evidence_rows = "".join(
        f"<tr><td><code>{escaped(item.get('evidence_id'))}</code></td><td>{escaped(item.get('kind'))}</td>"
        f"<td><code>{escaped((item.get('binary_sha256') or '')[:20])}</code></td></tr>"
        for item in result.get("evidence", [])[:100]
    )
    citation_rows = "".join(
        f"<li>Sources: <code>{escaped(', '.join(citation.get('source_ids', [])) or '—')}</code>; "
        f"evidence: <code>{escaped(', '.join(citation.get('evidence_ids', [])) or '—')}</code></li>"
        for citation in explanation.get("citations", [])
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>VulnGenome Lite report — {escaped(job['id'])}</title>
<style>
body{{margin:0;background:#07111f;color:#e8f1fb;font:15px/1.6 Segoe UI,Arial,sans-serif}}main{{max-width:1080px;margin:44px auto;padding:0 24px}}.eyebrow{{color:#47d6e7;letter-spacing:.16em;text-transform:uppercase;font-size:12px}}h1{{font-size:34px;margin:8px 0}}h2{{margin-top:34px;font-size:19px}}.panel{{background:#0d1a2b;border:1px solid #24364c;border-radius:14px;padding:20px;margin:16px 0}}.status{{color:#55d7a3}}table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;border-bottom:1px solid #24364c;text-align:left;vertical-align:top}}th{{color:#91a7be}}code{{word-break:break-all;color:#8bddff}}.warning{{color:#ffc267}}small{{color:#91a7be}}
</style></head><body><main>
<div class="eyebrow">VulnGenome Lite · Static binary analysis</div>
<h1>Controlled pair analysis</h1>
<p class="status">Engine status: {escaped(result.get('analysis_status', 'INCONCLUSIVE'))}</p>
<p><small>Job {escaped(job['id'])} · Created {escaped(job['created_at'])} · Profile {escaped(result['profile']['id'])}</small></p>
<section class="panel"><h2>Artifacts and provenance</h2><table><thead><tr><th>Role</th><th>SHA-256</th><th>Analyzer</th><th>Recovered functions</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>
<section class="panel"><h2>Evidence-grounded explanation</h2><p><b>{escaped(explanation.get('summary','No explanation available.'))}</b></p><p>{escaped(explanation.get('mechanism',''))}</p><p>{escaped(explanation.get('patch_interpretation',''))}</p><p>{escaped(explanation.get('verification_scope',''))}</p><small>{escaped(intelligence.get('label',''))}</small></section>
<section class="panel"><h2>Verification</h2><table><thead><tr><th>Artifact</th><th>Status</th><th>Solver</th><th>Reason</th></tr></thead><tbody>{solver_rows or '<tr><td colspan="4">No solver result. Extent inference abstained or the candidate was unsupported.</td></tr>'}</tbody></table></section>
<section class="panel"><h2>Evidence references</h2><table><thead><tr><th>Evidence ID</th><th>Kind</th><th>Binary SHA-256 prefix</th></tr></thead><tbody>{evidence_rows or '<tr><td colspan="3">No evidence records were returned.</td></tr>'}</tbody></table><h3>Explanation citations</h3><ul>{citation_rows or '<li>No citations returned.</li>'}</ul></section>
<section class="panel"><h2>Limitations and abstentions</h2><ul>{limitations}</ul></section>
<p class="warning">Static analysis only. Results apply to the listed hashes and documented engine assumptions. No uploaded binary was executed.</p>
</main></body></html>"""


def json_report(job: dict[str, Any], intelligence: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in job.items() if key not in {"result", "result_json"}}
    payload["result"] = job["result"]
    payload["intelligence"] = intelligence
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
