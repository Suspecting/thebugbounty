import re
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from scanner.utils import finding, is_same_host


SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"postgresql.*error",
    r"sqlite.*error",
    r"ora-\d+",
    r"microsoft ole db",
    r"odbc sql server driver",
    r"syntax error near"
]

COMPILED_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in SQL_ERROR_PATTERNS
]


def contains_sql_error(text):
    return any(pattern.search(text) for pattern in COMPILED_PATTERNS)


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


def scan_sqli_get_params(pages, session, timeout, delay):
    findings = []
    payloads = ["'", "\""]

    for page in pages:
        url = page["final_url"]
        params = parse_qsl(urlparse(url).query, keep_blank_values=True)

        if not params:
            continue

        for name, _value in params:
            for payload in payloads:
                test_url = build_url_with_payload(url, name, payload)

                try:
                    response = session.get(test_url, timeout=timeout, allow_redirects=True)

                    if contains_sql_error(response.text):
                        findings.append(finding(
                            "high",
                            "SQL Injection",
                            test_url,
                            "Potential SQL injection error indicator",
                            f"Database error pattern detected after testing parameter: {name}",
                            "Use parameterized queries/prepared statements and avoid exposing database errors."
                        ))

                except requests.RequestException:
                    pass

                time.sleep(delay)

    return findings


def scan_sqli_forms(pages, session, base_hostname, timeout, delay):
    findings = []
    payloads = ["'", "\""]

    for page in pages:
        for form in page.get("forms", []):
            action = form.get("action")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            if not action or not is_same_host(action, base_hostname):
                continue

            injectable_fields = [
                field for field in inputs
                if field.get("name") and field.get("type", "text") not in ["submit", "button", "reset", "hidden"]
            ]

            for target_field in injectable_fields:
                for payload in payloads:
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

                        if contains_sql_error(response.text):
                            findings.append(finding(
                                "high",
                                "SQL Injection",
                                action,
                                "Potential SQL injection error indicator in form",
                                f"Database error pattern detected after testing field: {target_field['name']}",
                                "Use parameterized queries/prepared statements and avoid exposing database errors."
                            ))

                    except requests.RequestException:
                        pass

                    time.sleep(delay)

    return findings


def scan_sqli(pages, session, base_hostname, timeout=10.0, delay=1.0):
    findings = []
    findings.extend(scan_sqli_get_params(pages, session, timeout, delay))
    findings.extend(scan_sqli_forms(pages, session, base_hostname, timeout, delay))
    return findings
