from urllib.parse import urljoin, urlparse, urldefrag


def normalize_url(base_url, link):
    if not link:
        return None

    link = link.strip()

    if link.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None

    absolute_url = urljoin(base_url, link)
    absolute_url, _fragment = urldefrag(absolute_url)

    parsed = urlparse(absolute_url)

    if parsed.scheme not in ["http", "https"]:
        return None

    if not parsed.netloc:
        return None

    return absolute_url.rstrip("/")


def get_hostname(url):
    return urlparse(url).hostname or ""


def is_same_host(url, base_hostname):
    return get_hostname(url) == base_hostname


def get_path(url):
    return urlparse(url).path or "/"


def finding(
    severity,
    category,
    url,
    title,
    evidence,
    recommendation,
    confidence="medium",
    parameter=None,
    payload=None,
    impact=None,
    steps_to_reproduce=None,
    false_positive_notes=None
):
    return {
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "url": url,
        "title": title,
        "parameter": parameter,
        "payload": payload,
        "evidence": evidence,
        "impact": impact or "Manual validation is recommended to determine real-world impact.",
        "steps_to_reproduce": steps_to_reproduce or [],
        "recommendation": recommendation,
        "false_positive_notes": false_positive_notes or "This finding should be manually verified before reporting."
    }
