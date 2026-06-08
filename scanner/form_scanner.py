from urllib.parse import urlparse

from scanner.utils import finding, get_hostname


def scan_forms(pages, base_hostname):
    findings = []

    for page in pages:
        page_url = page["final_url"]

        for form in page.get("forms", []):
            action = form.get("action")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            if not action:
                findings.append(finding(
                    "low",
                    "Forms",
                    page_url,
                    "Form missing action attribute",
                    "A form was found without a clear action URL.",
                    "Define a valid form action and validate server-side handling."
                ))
                continue

            action_host = get_hostname(action)

            if action_host and action_host != base_hostname:
                findings.append(finding(
                    "medium",
                    "Forms",
                    page_url,
                    "Form submits to external domain",
                    f"Form action points to external host: {action}",
                    "Verify that form submissions only go to trusted domains."
                ))

            has_password = any(field.get("type") == "password" for field in inputs)

            if has_password and urlparse(action).scheme == "http":
                findings.append(finding(
                    "high",
                    "Forms",
                    page_url,
                    "Password form submits over HTTP",
                    f"Password form action: {action}",
                    "Use HTTPS for all authentication forms."
                ))

            if has_password and method == "GET":
                findings.append(finding(
                    "high",
                    "Forms",
                    page_url,
                    "Password form uses GET method",
                    "Password input found in a GET form.",
                    "Use POST for login forms and never place credentials in URLs."
                ))

            if method == "POST":
                has_csrf_field = any(
                    "csrf" in field.get("name", "").lower() or
                    "token" in field.get("name", "").lower()
                    for field in inputs
                )

                if not has_csrf_field:
                    findings.append(finding(
                        "low",
                        "Forms",
                        page_url,
                        "POST form may be missing CSRF token",
                        f"POST form action: {action}",
                        "Use anti-CSRF tokens for state-changing forms."
                    ))

    return findings
