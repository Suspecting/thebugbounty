import time
from collections import deque

import requests
from bs4 import BeautifulSoup

from scanner.utils import normalize_url, is_same_host, get_hostname


class WebCrawler:
    def __init__(self, start_url, max_pages=10, delay=1.0, timeout=10.0, scope_policy=None):
        self.start_url = start_url.rstrip("/")
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.scope_policy = scope_policy
        self.base_hostname = get_hostname(self.start_url)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "thebugbounty/1.0 Authorized Security Scanner"
        })

    def is_allowed_url(self, url):
        if not url:
            return False

        if not is_same_host(url, self.base_hostname):
            return False

        if self.scope_policy and not self.scope_policy.is_url_allowed(url):
            return False

        return True

    def fetch_page(self, url):
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )

            content_type = response.headers.get("Content-Type", "")

            return {
                "url": url,
                "final_url": response.url.rstrip("/"),
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_type": content_type,
                "text": response.text if "text/html" in content_type else "",
                "error": None
            }

        except requests.RequestException as error:
            return {
                "url": url,
                "final_url": url,
                "status_code": None,
                "headers": {},
                "content_type": "",
                "text": "",
                "error": str(error)
            }

    def extract_links(self, page_url, html):
        soup = BeautifulSoup(html, "html.parser")
        links = set()

        for tag in soup.find_all("a", href=True):
            normalized = normalize_url(page_url, tag.get("href"))

            if normalized and self.is_allowed_url(normalized):
                links.add(normalized)

        return sorted(links)

    def extract_forms(self, page_url, html):
        soup = BeautifulSoup(html, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            method = form.get("method", "GET").upper()
            action_raw = form.get("action") or page_url
            action = normalize_url(page_url, action_raw)

            inputs = []

            for field in form.find_all(["input", "textarea", "select"]):
                field_name = field.get("name", "")
                field_type = field.get("type", "text").lower()
                field_value = field.get("value", "")

                inputs.append({
                    "tag": field.name,
                    "name": field_name,
                    "type": field_type,
                    "value": field_value
                })

            forms.append({
                "page_url": page_url,
                "method": method,
                "action": action,
                "inputs": inputs
            })

        return forms

    def crawl(self):
        visited = set()
        queue = deque([self.start_url])
        pages = []

        while queue and len(visited) < self.max_pages:
            current_url = queue.popleft()

            if current_url in visited:
                continue

            if not self.is_allowed_url(current_url):
                continue

            visited.add(current_url)

            page = self.fetch_page(current_url)

            if page["text"]:
                page["links"] = self.extract_links(current_url, page["text"])
                page["forms"] = self.extract_forms(current_url, page["text"])

                for link in page["links"]:
                    if link not in visited and len(visited) + len(queue) < self.max_pages:
                        queue.append(link)
            else:
                page["links"] = []
                page["forms"] = []

            pages.append(page)
            time.sleep(self.delay)

        return pages
