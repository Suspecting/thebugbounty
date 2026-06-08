import re
import time

import requests
from bs4 import BeautifulSoup

from scanner.utils import finding, normalize_url, is_same_host


JS_ENDPOINT_PATTERN = re.compile(
    r"""(?:"|')((?:/|https?://)[A-Za-z0-9_\-./?=&%#:]+)(?:"|')"""
)

SECRET_PATTERNS = {
    "Possible API key": re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    "Possible secret": re.compile(r"(?i)(secret|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"),
    "Possible bearer token": re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
    "Possible Firebase config": re.compile(r"(?i)firebase[a-z0-9_\-]*\.googleapis\.com"),
    "Possible AWS key id": re.compile(r"AKIA[0-9A-Z]{16}")
}

DANGEROUS_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "dangerouslySetInnerHTML",
    "location.hash",
    "location.search"
]


def collect_js_assets(pages, base_hostname):
    assets = set()

    for page in pages:
        html = page.get("text", "")
        page_url = page.get("final_url")

        if not html or not page_url:
            continue

        soup = BeautifulSoup(html, "html.parser")

        for script in soup.find_all("script", src=True):
            src = script.get("src")
            js_url = normalize_url(page_url, src)

            if js_url and is_same_host(js_url, base_hostname):
                assets.add(js_url)

    return sorted(assets)


def fetch_js(session, js_url, timeout):
    try:
        response = session.get(js_url, timeout=timeout, allow_redirects=True)

        if response.status_code == 200:
            return response.text

        return ""

    except requests.RequestException:
        return ""


def extract_endpoints(js_text):
    endpoints = set()

    for match in JS_ENDPOINT_PATTERN.findall(js_text):
        if len(match) < 2:
            continue

        lowered = match.lower()

        if any(bad in lowered for bad in ["png", "jpg", "jpeg", "gif", "svg", "css", "woff", "woff2"]):
            continue

        endpoints.add(match)

    return sorted(endpoints)


def find_secret_indicators(js_text):
    results = []

    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(js_text):
            start = max(match.start() - 60, 0)
            end = min(match.end() + 60, len(js_text))
            snippet = js_text[start:end]

            results.append({
                "type": name,
                "snippet": snippet
            })

    return results


def find_dangerous_sinks(js_text):
    results = []

    for sink in DANGEROUS_SINKS:
        index = js_text.find(sink)

        if index != -1:
            start = max(index - 80, 0)
            end = min(index + 120, len(js_text))

            results.append({
                "sink": sink,
                "snippet": js_text[start:end]
            })

    return results


def check_source_map(session, js_url, timeout):
    candidates = [
        js_url + ".map"
    ]

    exposed = []

    for candidate in candidates:
        try:
            response = session.get(candidate, timeout=timeout, allow_redirects=True)

            if response.status_code == 200 and ("sources" in response.text or "version" in response.text):
                exposed.append(candidate)

        except requests.RequestException:
            pass

    return exposed


def scan_javascript(pages, session, base_hostname, timeout=10.0, delay=1.0):
    findings = []
    attack_surface = {
        "javascript_files": [],
        "endpoints": [],
        "dangerous_sinks": [],
        "secret_indicators": [],
        "source_maps": []
    }

    js_assets = collect_js_assets(pages, base_hostname)
    attack_surface["javascript_files"] = js_assets

    for js_url in js_assets:
        js_text = fetch_js(session, js_url, timeout)

        if not js_text:
            continue

        endpoints = extract_endpoints(js_text)

        for endpoint in endpoints[:100]:
            attack_surface["endpoints"].append({
                "source": js_url,
                "endpoint": endpoint
            })

        if endpoints:
            findings.append(finding(
                severity="info",
                confidence="medium",
                category="JavaScript Recon",
                url=js_url,
                title="API endpoints discovered in JavaScript bundle",
                evidence=f"Found {len(endpoints)} potential endpoint(s) in JavaScript.",
                impact="Discovered endpoints may expand the application's attack surface for authorized testing.",
                recommendation="Review exposed endpoints and ensure sensitive routes require proper authorization.",
                false_positive_notes="Some extracted paths may be static assets or non-sensitive frontend routes."
            ))

        secrets = find_secret_indicators(js_text)

        for secret in secrets[:20]:
            attack_surface["secret_indicators"].append({
                "source": js_url,
                "type": secret["type"]
            })

            findings.append(finding(
                severity="medium",
                confidence="low",
                category="JavaScript Secrets",
                url=js_url,
                title=secret["type"],
                evidence=secret["snippet"],
                impact="Potential secrets in frontend JavaScript may expose sensitive integrations if valid.",
                recommendation="Verify whether the value is sensitive. Move secrets to server-side storage if required.",
                false_positive_notes="Some frontend keys are public by design and require manual impact validation."
            ))

        sinks = find_dangerous_sinks(js_text)

        for sink in sinks[:20]:
            attack_surface["dangerous_sinks"].append({
                "source": js_url,
                "sink": sink["sink"]
            })

            findings.append(finding(
                severity="low",
                confidence="medium",
                category="DOM XSS Recon",
                url=js_url,
                title="Potential dangerous JavaScript sink found",
                evidence=f"Sink: {sink['sink']} | Snippet: {sink['snippet']}",
                impact="Dangerous DOM sinks may become exploitable if attacker-controlled input reaches them.",
                recommendation="Review data flow into dangerous sinks and use safe DOM APIs.",
                false_positive_notes="Presence of a sink does not confirm DOM XSS. Manual source-to-sink validation is required."
            ))

        source_maps = check_source_map(session, js_url, timeout)

        for source_map in source_maps:
            attack_surface["source_maps"].append(source_map)

            findings.append(finding(
                severity="medium",
                confidence="high",
                category="Information Disclosure",
                url=source_map,
                title="Exposed JavaScript source map",
                evidence=f"Source map accessible: {source_map}",
                impact="Source maps may expose original source code, routes, comments, and internal implementation details.",
                recommendation="Disable public source maps in production unless intentionally exposed.",
                false_positive_notes="Some programs classify source maps as informational unless sensitive data is exposed."
            ))

        time.sleep(delay)

    return findings, attack_surface
