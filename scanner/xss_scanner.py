import time
import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from scanner.utils import finding, is_same_host, get_hostname


TEXT_INPUT_TYPES = {
    "text", "search", "email", "url", "tel", "password", ""
}


def build_url_with_payload(url, parameter_name, payload):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)

    new_params = []

    for name, value in params:
        if name == parameter_name:
            new_params.append((name, payload))
        else:
            new_params.append((name, value))

    return urlunparse(parsed._replace(query=urlencode(new_params)))


def scan_xss_get_params(pages, session, timeout, delay):
    findings = []

    for page in pages:
        url = page["final_url"]
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        if not params:
            continue

        for name, _value in params:
            marker = f"WVSXSS{uuid.uuid4().hex[:8]}"
            payload = f"{marker}<svg/onload=alert(1)>"
            test_url = build_url_with_payload(url, name, payload)

            try:
                response = session.get(test_url, timeout=timeout, allow_redirects=True)

                if payload in response.text:
                    findings.append(finding(
                        "high",
                        "Reflected XSS",
                        test_url,
                        "Potential reflected XSS in URL parameter",
                        f"Payload reflected in response for parameter: {name}",
                        "Encode output contextually and validate user-controlled input."
                    ))

            except requests.RequestException:
                pass

            time.sleep(delay)

    return findings


def scan_xss_forms(pages, session, base_hostname, timeout, delay):
    findings = []

    for page in pages:
        for form in page.get("forms", []):
            action = form.get("action")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            if not action or not is_same_host(action, base_hostname):
                continue

            injectable_fields = [
                field for field in inputs
                if field.get("name") and field.get("type", "text") in TEXT_INPUT_TYPES
            ]

            if not injectable_fields:
                continue

            for target_field in injectable_fields:
                marker = f"WVSXSS{uuid.uuid4().hex[:8]}"
                payload = f"{marker}<svg/onload=alert(1)>"

                data = {}

                for field in inputs:
                    name = field.get("name")
                    if not name:
                        continue

                    if name == target_field["name"]:
                        data[name] = payload
                    else:
                        data[name] = field.get("value") or "test"

                try:
                    if method == "POST":
                        response = session.post(action, data=data, timeout=timeout, allow_redirects=True)
                    else:
                        response = session.get(action, params=data, timeout=timeout, allow_redirects=True)

                    if payload in response.text:
                        findings.append(finding(
                            "high",
                            "Reflected XSS",
                            action,
                            "Potential reflected XSS in form input",
                            f"Payload reflected through form field: {target_field['name']}",
                            "Encode output contextually and validate user-controlled input."
                        ))

                except requests.RequestException:
                    pass

                time.sleep(delay)

    return findings


def scan_xss(pages, session, base_hostname, timeout=10.0, delay=1.0):
    findings = []
    findings.extend(scan_xss_get_params(pages, session, timeout, delay))
    findings.extend(scan_xss_forms(pages, session, base_hostname, timeout, delay))
    return findings
