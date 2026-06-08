from datetime import datetime


def sanitize(text):
    if text is None:
        return ""
    return str(text).replace("\n", " ").strip()


def generate_bug_bounty_markdown(report, output_base):
    bb_dir = output_base / "bug_bounty"
    bb_dir.mkdir(parents=True, exist_ok=True)

    output_path = bb_dir / f"bug_bounty_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

    lines = []

    lines.append(f"# Bug Bounty Style Report - {report['target']}")
    lines.append("")
    lines.append(f"**Tool:** {report['tool']} v{report['version']}")
    lines.append(f"**Scan Time:** {report['scan_time']}")
    lines.append(f"**Risk Score:** {report['summary']['risk']['score']}/100")
    lines.append(f"**Verdict:** {report['summary']['risk']['verdict']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"The scan reviewed {report['summary']['pages_scanned']} page(s), "
        f"identified {report['summary']['forms_found']} form(s), and produced "
        f"{report['summary']['findings_count']} finding(s)."
    )
    lines.append("")

    counts = report["summary"]["severity_counts"]
    lines.append("### Severity Breakdown")
    lines.append("")
    lines.append(f"- Critical: {counts.get('critical', 0)}")
    lines.append(f"- High: {counts.get('high', 0)}")
    lines.append(f"- Medium: {counts.get('medium', 0)}")
    lines.append(f"- Low: {counts.get('low', 0)}")
    lines.append(f"- Informational: {counts.get('info', 0)}")
    lines.append("")

    attack_surface = report.get("attack_surface", {})

    lines.append("---")
    lines.append("")
    lines.append("## Attack Surface Map")
    lines.append("")

    lines.append(f"### JavaScript Files ({len(attack_surface.get('javascript_files', []))})")
    for item in attack_surface.get("javascript_files", [])[:50]:
        lines.append(f"- `{item}`")
    lines.append("")

    lines.append(f"### Discovered Endpoints ({len(attack_surface.get('endpoints', []))})")
    for item in attack_surface.get("endpoints", [])[:100]:
        lines.append(f"- `{item.get('endpoint')}` from `{item.get('source')}`")
    lines.append("")

    lines.append(f"### Source Maps ({len(attack_surface.get('source_maps', []))})")
    for item in attack_surface.get("source_maps", [])[:50]:
        lines.append(f"- `{item}`")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not report["findings"]:
        lines.append("No findings were detected.")
    else:
        for index, item in enumerate(report["findings"], start=1):
            lines.append(f"### {index}. {sanitize(item.get('title'))}")
            lines.append("")
            lines.append(f"**Severity:** {sanitize(item.get('severity'))}")
            lines.append(f"**Confidence:** {sanitize(item.get('confidence'))}")
            lines.append(f"**Category:** {sanitize(item.get('category'))}")
            lines.append(f"**Affected URL:** `{sanitize(item.get('url'))}`")

            if item.get("parameter"):
                lines.append(f"**Parameter/Field:** `{sanitize(item.get('parameter'))}`")

            if item.get("payload"):
                lines.append(f"**Payload Used:** `{sanitize(item.get('payload'))}`")

            lines.append("")
            lines.append("#### Evidence")
            lines.append("")
            lines.append(f"```txt\n{sanitize(item.get('evidence'))}\n```")
            lines.append("")

            lines.append("#### Impact")
            lines.append("")
            lines.append(sanitize(item.get("impact")))
            lines.append("")

            steps = item.get("steps_to_reproduce", [])

            if steps:
                lines.append("#### Steps to Reproduce")
                lines.append("")
                for step_no, step in enumerate(steps, start=1):
                    lines.append(f"{step_no}. {sanitize(step)}")
                lines.append("")

            lines.append("#### Recommendation")
            lines.append("")
            lines.append(sanitize(item.get("recommendation")))
            lines.append("")

            lines.append("#### False Positive Notes")
            lines.append("")
            lines.append(sanitize(item.get("false_positive_notes")))
            lines.append("")
            lines.append("---")
            lines.append("")

    lines.append("## Ethical Use Note")
    lines.append("")
    lines.append("This report is intended only for authorized security testing and defensive remediation.")
    lines.append("")

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    return output_path
