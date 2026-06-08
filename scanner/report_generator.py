import json
from datetime import datetime
from html import escape


SEVERITY_WEIGHTS = {
    "info": 1,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50
}


def calculate_risk_score(findings):
    score = 0

    for item in findings:
        severity = item.get("severity", "info").lower()
        confidence = item.get("confidence", "medium").lower()

        base = SEVERITY_WEIGHTS.get(severity, 1)

        if confidence == "high":
            multiplier = 1.0
        elif confidence == "medium":
            multiplier = 0.75
        else:
            multiplier = 0.5

        score += int(base * multiplier)

    score = min(score, 100)

    if score >= 70:
        verdict = "High Risk"
    elif score >= 35:
        verdict = "Medium Risk"
    elif score >= 10:
        verdict = "Low Risk"
    else:
        verdict = "Informational"

    return {
        "score": score,
        "verdict": verdict
    }


def severity_counts(findings):
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for item in findings:
        severity = item.get("severity", "info").lower()
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def confidence_counts(findings):
    counts = {
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for item in findings:
        confidence = item.get("confidence", "medium").lower()
        counts[confidence] = counts.get(confidence, 0) + 1

    return counts


def generate_json_report(target_url, config, pages, findings, output_base, attack_surface=None):
    risk = calculate_risk_score(findings)

    if attack_surface is None:
        attack_surface = {
            "javascript_files": [],
            "endpoints": [],
            "dangerous_sinks": [],
            "secret_indicators": [],
            "source_maps": []
        }

    report = {
        "tool": "thebugbounty",
        "version": "1.0.0",
        "target": target_url,
        "scan_time": datetime.now().isoformat(),
        "config": config,
        "summary": {
            "pages_scanned": len(pages),
            "forms_found": sum(len(page.get("forms", [])) for page in pages),
            "findings_count": len(findings),
            "severity_counts": severity_counts(findings),
            "confidence_counts": confidence_counts(findings),
            "risk": risk
        },
        "attack_surface": attack_surface,
        "pages": [
            {
                "url": page.get("final_url"),
                "status_code": page.get("status_code"),
                "forms": len(page.get("forms", [])),
                "links": len(page.get("links", [])),
                "error": page.get("error")
            }
            for page in pages
        ],
        "findings": findings
    }

    output_base.mkdir(parents=True, exist_ok=True)

    filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path = output_base / filename

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report, output_path


def build_attack_surface_rows(attack_surface):
    rows = ""

    for item in attack_surface.get("javascript_files", [])[:100]:
        rows += f"""
        <tr>
            <td>JavaScript File</td>
            <td>{escape(str(item))}</td>
        </tr>
        """

    for item in attack_surface.get("endpoints", [])[:150]:
        rows += f"""
        <tr>
            <td>Endpoint</td>
            <td>{escape(str(item.get("endpoint", "")))}<br><small>Source: {escape(str(item.get("source", "")))}</small></td>
        </tr>
        """

    for item in attack_surface.get("source_maps", [])[:100]:
        rows += f"""
        <tr>
            <td>Source Map</td>
            <td>{escape(str(item))}</td>
        </tr>
        """

    for item in attack_surface.get("secret_indicators", [])[:100]:
        rows += f"""
        <tr>
            <td>Secret Indicator</td>
            <td>{escape(str(item.get("type", "")))}<br><small>Source: {escape(str(item.get("source", "")))}</small></td>
        </tr>
        """

    for item in attack_surface.get("dangerous_sinks", [])[:100]:
        rows += f"""
        <tr>
            <td>Dangerous JS Sink</td>
            <td>{escape(str(item.get("sink", "")))}<br><small>Source: {escape(str(item.get("source", "")))}</small></td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="2">No JavaScript attack surface data collected.</td>
        </tr>
        """

    return rows


def generate_html_report(report, output_base):
    html_dir = output_base / "html"
    html_dir.mkdir(parents=True, exist_ok=True)

    safe_target = str(report["target"]).replace("/", "_").replace(":", "")
    output_path = html_dir / f"{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    risk = report["summary"]["risk"]
    severity = report["summary"]["severity_counts"]
    confidence = report["summary"]["confidence_counts"]
    attack_surface = report.get("attack_surface", {})

    findings_rows = ""

    for item in report["findings"]:
        findings_rows += f"""
        <tr>
            <td>{escape(str(item.get("severity", "")))}</td>
            <td>{escape(str(item.get("confidence", "")))}</td>
            <td>{escape(str(item.get("category", "")))}</td>
            <td>{escape(str(item.get("title", "")))}</td>
            <td>{escape(str(item.get("url", "")))}</td>
            <td>{escape(str(item.get("parameter", "") or ""))}</td>
            <td>{escape(str(item.get("evidence", "")))}</td>
            <td>{escape(str(item.get("recommendation", "")))}</td>
        </tr>
        """

    if not findings_rows:
        findings_rows = """
        <tr>
            <td colspan="8">No findings detected.</td>
        </tr>
        """

    pages_rows = ""

    for page in report["pages"]:
        pages_rows += f"""
        <tr>
            <td>{escape(str(page.get("url", "")))}</td>
            <td>{escape(str(page.get("status_code", "")))}</td>
            <td>{escape(str(page.get("forms", "")))}</td>
            <td>{escape(str(page.get("links", "")))}</td>
        </tr>
        """

    attack_surface_rows = build_attack_surface_rows(attack_surface)

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>thebugbounty Report</title>
    <style>
        body {{
            background: #0f172a;
            color: #e5e7eb;
            font-family: Arial, sans-serif;
            padding: 30px;
        }}
        .container {{
            max-width: 1300px;
            margin: auto;
        }}
        .card {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #38bdf8;
        }}
        h2 {{
            color: #cbd5e1;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            border: 1px solid #334155;
            padding: 10px;
            text-align: left;
            vertical-align: top;
            word-break: break-word;
        }}
        th {{
            background: #1e293b;
            color: #38bdf8;
        }}
        .score {{
            font-size: 32px;
            font-weight: bold;
            color: #facc15;
        }}
        code {{
            color: #93c5fd;
        }}
        small {{
            color: #94a3b8;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>thebugbounty Report</h1>

    <div class="card">
        <h2>Target</h2>
        <p><code>{escape(str(report["target"]))}</code></p>
        <p>Scan Time: {escape(str(report["scan_time"]))}</p>
    </div>

    <div class="card">
        <h2>Risk Summary</h2>
        <p class="score">{risk["score"]}/100 - {escape(risk["verdict"])}</p>
        <p>Pages Scanned: {report["summary"]["pages_scanned"]}</p>
        <p>Forms Found: {report["summary"]["forms_found"]}</p>
        <p>Findings Count: {report["summary"]["findings_count"]}</p>
        <p>Severity: Critical {severity["critical"]} | High {severity["high"]} | Medium {severity["medium"]} | Low {severity["low"]} | Info {severity["info"]}</p>
        <p>Confidence: High {confidence["high"]} | Medium {confidence["medium"]} | Low {confidence["low"]}</p>
    </div>

    <div class="card">
        <h2>Attack Surface Map</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Value</th>
            </tr>
            {attack_surface_rows}
        </table>
    </div>

    <div class="card">
        <h2>Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Category</th>
                <th>Title</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Evidence</th>
                <th>Recommendation</th>
            </tr>
            {findings_rows}
        </table>
    </div>

    <div class="card">
        <h2>Pages Scanned</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Status</th>
                <th>Forms</th>
                <th>Links</th>
            </tr>
            {pages_rows}
        </table>
    </div>
</div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html)

    return output_path
