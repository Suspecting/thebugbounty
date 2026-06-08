import argparse
import ipaddress
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.banner import print_banner
from scanner.bug_bounty_report import generate_bug_bounty_markdown
from scanner.crawler import WebCrawler
from scanner.form_scanner import scan_forms
from scanner.header_scanner import scan_security_headers
from scanner.js_analyzer import scan_javascript
from scanner.report_generator import generate_json_report, generate_html_report
from scanner.scope_policy import ScopePolicy
from scanner.sqli_scanner import scan_sqli
from scanner.utils import get_hostname
from scanner.xss_scanner import scan_xss


console = Console()


def is_local_target(url):
    hostname = urlparse(url).hostname

    if not hostname:
        return False

    if hostname in ["localhost", "127.0.0.1", "0.0.0.0"]:
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        console.print("[bold red]Error:[/bold red] URL must start with http:// or https://")
        sys.exit(1)

    if not parsed.netloc:
        console.print("[bold red]Error:[/bold red] Invalid URL")
        sys.exit(1)

    return parsed


def print_config(args, scope_policy, active_enabled):
    table = Table(title="Scan Configuration")
    table.add_column("Setting", style="bold cyan")
    table.add_column("Value")

    table.add_row("Tool", "thebugbounty")
    table.add_row("Target", args.url)
    table.add_row("Authorized", str(args.authorized))
    table.add_row("Scope File", str(args.scope))
    table.add_row("Active XSS/SQLi Tests", str(active_enabled))
    table.add_row("JavaScript Analysis", str(not args.no_js))
    table.add_row("Max Pages", str(args.max_pages))
    table.add_row("Delay", f"{args.delay} seconds")
    table.add_row("Timeout", f"{args.timeout} seconds")
    table.add_row("Allowed Domains", ", ".join(scope_policy.allowed_domains()))
    table.add_row("Blocked Paths", ", ".join(scope_policy.blocked_paths()) or "None")

    console.print(table)


def print_findings(findings):
    table = Table(title="Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Confidence")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("URL")

    if not findings:
        table.add_row("None", "None", "None", "No findings detected", "N/A")
    else:
        for item in findings:
            table.add_row(
                str(item.get("severity", "")),
                str(item.get("confidence", "")),
                str(item.get("category", "")),
                str(item.get("title", "")),
                str(item.get("url", ""))
            )

    console.print(table)


def print_summary(report, json_path, html_path, markdown_path):
    summary = report["summary"]
    risk = summary["risk"]
    severity = summary["severity_counts"]
    confidence = summary["confidence_counts"]

    table = Table(title="Scan Summary")
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value")

    table.add_row("Pages Scanned", str(summary["pages_scanned"]))
    table.add_row("Forms Found", str(summary["forms_found"]))
    table.add_row("Findings", str(summary["findings_count"]))
    table.add_row("Risk Score", f"{risk['score']}/100")
    table.add_row("Verdict", risk["verdict"])
    table.add_row("High Findings", str(severity["high"]))
    table.add_row("Medium Findings", str(severity["medium"]))
    table.add_row("Low Findings", str(severity["low"]))
    table.add_row("Info Findings", str(severity["info"]))
    table.add_row("High Confidence", str(confidence["high"]))
    table.add_row("Medium Confidence", str(confidence["medium"]))
    table.add_row("Low Confidence", str(confidence["low"]))
    table.add_row("JSON Report", str(json_path))
    table.add_row("HTML Report", str(html_path))
    table.add_row("Bug Bounty Markdown", str(markdown_path))

    console.print(table)


def main():
    print_banner(console)

    parser = argparse.ArgumentParser(
        description="thebugbounty - Evidence-Based Bug Bounty Triage Scanner"
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL. Use only authorized targets."
    )

    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you are authorized to scan this external target."
    )

    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable active XSS/SQLi indicator tests. Use only when explicitly permitted."
    )

    parser.add_argument(
        "--no-js",
        action="store_true",
        help="Disable JavaScript bundle analysis."
    )

    parser.add_argument(
        "--scope",
        default="scope.json",
        help="Path to scope policy file. Default: scope.json."
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="Maximum pages to crawl. Default comes from scope.json. Maximum: 50."
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=None,
        help="Delay between requests. Default comes from scope.json. Minimum: 0.5."
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds. Default: 10."
    )

    args = parser.parse_args()
    validate_url(args.url)

    scope_policy = ScopePolicy(args.scope)

    if args.max_pages is None:
        args.max_pages = scope_policy.max_pages()

    if args.delay is None:
        args.delay = scope_policy.delay()

    if args.max_pages < 1 or args.max_pages > 50:
        console.print("[bold red]Error:[/bold red] --max-pages must be between 1 and 50")
        sys.exit(1)

    if args.delay < 0.5:
        console.print("[bold red]Error:[/bold red] --delay must be at least 0.5 seconds")
        sys.exit(1)

    local_target = is_local_target(args.url)

    if not local_target and not args.authorized:
        console.print(Panel(
            "[bold red]External target detected.[/bold red]\n\n"
            "Use --authorized only when you own the target, manage it, or have written permission to test it.\n\n"
            "For bug bounty programs, confirm that scanning is allowed in the program policy.",
            title="Authorization Required",
            style="red"
        ))
        sys.exit(1)

    if not scope_policy.is_domain_allowed(args.url):
        console.print(Panel(
            "[bold red]Target is not allowed by scope.json.[/bold red]\n\n"
            f"Target: {args.url}\n"
            f"Allowed domains: {', '.join(scope_policy.allowed_domains())}\n\n"
            "Add only authorized domains to scope.json before scanning.",
            title="Out of Scope",
            style="red"
        ))
        sys.exit(1)

    if scope_policy.is_path_blocked(args.url):
        console.print(Panel(
            "[bold red]Target path is blocked by scope.json.[/bold red]\n\n"
            "This prevents scanning sensitive/destructive paths like logout, delete, payment, checkout, or billing.",
            title="Blocked Path",
            style="red"
        ))
        sys.exit(1)

    active_enabled = args.active and scope_policy.allow_active_tests()

    if args.active and not scope_policy.allow_active_tests():
        console.print("[yellow]Active tests requested but disabled by scope.json. Continuing in passive mode.[/yellow]")

    console.print(Panel(
        "[bold cyan]thebugbounty[/bold cyan]\n"
        "Evidence-Based Bug Bounty Triage Scanner",
        style="cyan"
    ))

    print_config(args, scope_policy, active_enabled)

    crawler = WebCrawler(
        start_url=args.url,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        scope_policy=scope_policy
    )

    console.print("[yellow]Crawling target...[/yellow]")
    pages = crawler.crawl()

    findings = []

    attack_surface = {
        "javascript_files": [],
        "endpoints": [],
        "dangerous_sinks": [],
        "secret_indicators": [],
        "source_maps": []
    }

    base_hostname = get_hostname(args.url)

    console.print("[yellow]Checking security headers...[/yellow]")
    for page in pages:
        findings.extend(scan_security_headers(page))

    console.print("[yellow]Analyzing forms...[/yellow]")
    findings.extend(scan_forms(pages, base_hostname))

    if not args.no_js:
        console.print("[yellow]Analyzing JavaScript bundles...[/yellow]")
        js_findings, js_attack_surface = scan_javascript(
            pages=pages,
            session=crawler.session,
            base_hostname=base_hostname,
            timeout=args.timeout,
            delay=args.delay
        )

        findings.extend(js_findings)
        attack_surface = js_attack_surface
    else:
        console.print("[cyan]JavaScript analysis disabled with --no-js.[/cyan]")

    if active_enabled:
        console.print("[yellow]Running active reflected XSS indicator tests...[/yellow]")
        findings.extend(scan_xss(
            pages=pages,
            session=crawler.session,
            base_hostname=base_hostname,
            timeout=args.timeout,
            delay=args.delay
        ))

        console.print("[yellow]Running active SQL error indicator tests...[/yellow]")
        findings.extend(scan_sqli(
            pages=pages,
            session=crawler.session,
            base_hostname=base_hostname,
            timeout=args.timeout,
            delay=args.delay
        ))
    else:
        console.print("[cyan]Passive mode: active XSS/SQLi payload checks skipped. Use --active only when explicitly permitted.[/cyan]")

    config = {
        "authorized": args.authorized,
        "active_tests": active_enabled,
        "javascript_analysis": not args.no_js,
        "scope_file": args.scope,
        "max_pages": args.max_pages,
        "delay": args.delay,
        "timeout": args.timeout,
        "scope": "same-host-and-scope-json"
    }

    output_base = ROOT_DIR / "reports"

    report, json_path = generate_json_report(
        target_url=args.url,
        config=config,
        pages=pages,
        findings=findings,
        output_base=output_base,
        attack_surface=attack_surface
    )

    html_path = generate_html_report(report, output_base)
    markdown_path = generate_bug_bounty_markdown(report, output_base)

    print_findings(findings)
    print_summary(report, json_path, html_path, markdown_path)

    console.print("[bold green]Scan completed.[/bold green]")


if __name__ == "__main__":
    main()
