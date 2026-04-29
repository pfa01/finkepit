"""
ssl_adapter.py
──────────────
Eigener HTTPAdapter mit konfigurierbarem SSL-Kontext und Retry-Logik.
"""

import ssl

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.util.ssl_ import create_urllib3_context


class SSLAdapter(HTTPAdapter):
    """
    HTTPAdapter mit konfigurierbarer TLS-Mindestversion und Retry-Strategie.

    Args:
        ssl_minimum_version: Minimale TLS-Version ("TLSv1_2" | "TLSv1_3")
        max_retries:         urllib3 Retry-Objekt oder Anzahl Versuche
    """

    TLS_VERSION_MAP = {
        "TLSv1_2": ssl.TLSVersion.TLSv1_2,
        "TLSv1_3": ssl.TLSVersion.TLSv1_3,
    }

    def __init__(self, ssl_minimum_version: str = "TLSv1_2", **kwargs):
        if ssl_minimum_version not in self.TLS_VERSION_MAP:
            raise ValueError(
                f"Ungültige TLS-Version '{ssl_minimum_version}'. "
                f"Erlaubt: {list(self.TLS_VERSION_MAP)}"
            )
        self.ssl_minimum_version = ssl_minimum_version
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.minimum_version = self.TLS_VERSION_MAP[self.ssl_minimum_version]
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)


def build_retry(max_retries: int = 3) -> Retry:
    """Erstellt eine vorkonfigurierte Retry-Strategie für Jira-Requests."""
    return Retry(
        total=max_retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
