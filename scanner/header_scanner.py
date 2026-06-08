from urllib.parse import urlparse

from scanner.utils import finding


def scan_security_headers(page):
    findings = []

    url = page["final_url"]
    headers = {key.lower(): value for key, value in page.get("headers", {}).items()}
    parsed = urlparse(url)

    if parsed.scheme == "http":
        findings.append(finding(
            "medium",
            "Transport Security",
            url,
            "Website is using HTTP",
            "The target page is served over HTTP instead of HTTPS.",
            "Use HTTPS with a valid TLS certificate."
        ))

    required_headers = {
        "content-security-policy": {
            "severity": "medium",
            "title": "Missing Content-Security-Policy header",
            "recommendation": "Add a strict Content-Security-Policy header to reduce XSS impact."
        },
        "x-frame-options": {
            "severity": "low",
            "title": "Missing X-Frame-Options header",
            "recommendation": "Add X-Frame-Options or frame-ancestors in CSP to reduce clickjacking risk."
        },
        "x-content-type-options": {
            "severity": "low",
            "title": "Missing X-Content-Type-Options header",
            "recommendation": "Add X-Content-Type-Options: nosniff."
        },
        "referrer-policy": {
            "severity": "low",
            "title": "Missing Referrer-Policy header",
            "recommendation": "Add a Referrer-Policy header such as strict-origin-when-cross-origin."
        },
        "permissions-policy": {
            "severity": "low",
            "title": "Missing Permissions-Policy header",
            "recommendation": "Add a Permissions-Policy header to restrict browser features."
        }
    }

    for header, details in required_headers.items():
        if header not in headers:
            findings.append(finding(
                details["severity"],
                "Security Headers",
                url,
                details["title"],
                f"Header not found: {header}",
                details["recommendation"]
            ))

    if parsed.scheme == "https" and "strict-transport-security" not in headers:
        findings.append(finding(
            "medium",
            "Transport Security",
            url,
            "Missing Strict-Transport-Security header",
            "HTTPS page does not include HSTS.",
            "Add Strict-Transport-Security to enforce HTTPS."
        ))

    if "server" in headers:
        findings.append(finding(
            "info",
            "Information Disclosure",
            url,
            "Server header exposed",
            f"Server header: {headers.get('server')}",
            "Consider reducing detailed server version disclosure."
        ))

    return findings

