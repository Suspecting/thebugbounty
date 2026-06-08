import json
from pathlib import Path

from scanner.utils import get_hostname, get_path


class ScopePolicy:
    def __init__(self, scope_file="scope.json"):
        self.scope_file = Path(scope_file)
        self.data = self.load_scope()

    def load_scope(self):
        if not self.scope_file.exists():
            return {
                "allowed_domains": ["127.0.0.1", "localhost"],
                "blocked_paths": [],
                "max_pages": 10,
                "delay": 1.0,
                "passive_first": True,
                "allow_active_tests": False
            }

        with open(self.scope_file, "r", encoding="utf-8") as file:
            return json.load(file)

    def allowed_domains(self):
        return self.data.get("allowed_domains", [])

    def blocked_paths(self):
        return self.data.get("blocked_paths", [])

    def is_domain_allowed(self, url):
        hostname = get_hostname(url)

        for allowed in self.allowed_domains():
            if hostname == allowed or hostname.endswith("." + allowed):
                return True

        return False

    def is_path_blocked(self, url):
        path = get_path(url).lower()

        for blocked in self.blocked_paths():
            if path.startswith(blocked.lower()):
                return True

        return False

    def is_url_allowed(self, url):
        return self.is_domain_allowed(url) and not self.is_path_blocked(url)

    def max_pages(self):
        return int(self.data.get("max_pages", 10))

    def delay(self):
        return float(self.data.get("delay", 1.0))

    def allow_active_tests(self):
        return bool(self.data.get("allow_active_tests", False))

    def passive_first(self):
        return bool(self.data.get("passive_first", True))
