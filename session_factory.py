"""
session_factory.py
──────────────────
Erstellt und konfiguriert eine requests.Session mit Auth, Proxy und SSL.
"""

import logging
from typing import Optional, Union

import urllib3
import requests

from ssl_adapter import SSLAdapter, build_retry

logger = logging.getLogger(__name__)


def create_session(
    username: Optional[str] = None,
    api_token: Optional[str] = None,
    bearer_token: Optional[str] = None,
    proxy_http: Optional[str] = None,
    proxy_https: Optional[str] = None,
    ssl_verify: Union[bool, str] = True,
    ssl_min_version: str = "TLSv1_2",
    max_retries: int = 3,
) -> requests.Session:
    """
    Erzeugt eine fertig konfigurierte requests.Session.

    Args:
        username:       Jira-Benutzername / E-Mail (Basic Auth)
        api_token:      API-Token oder Passwort (Basic Auth)
        bearer_token:   Bearer-Token / PAT (Alternative zu Basic Auth)
        proxy_http:     HTTP-Proxy-URL,  z. B. http://proxy.corp.local:8080
        proxy_https:    HTTPS-Proxy-URL, z. B. http://proxy.corp.local:8080
        ssl_verify:     True  → Standard-CA-Validierung
                        False → SSL deaktivieren (NUR für Tests!)
                        str   → Pfad zu eigenem CA-Bundle (.pem)
        ssl_min_version: Minimale TLS-Version ("TLSv1_2" | "TLSv1_3")
        max_retries:    Anzahl Wiederholversuche bei Netzwerk-/Serverfehlern

    Returns:
        Konfigurierte requests.Session
    """
    session = requests.Session()

    _configure_auth(session, username, api_token, bearer_token)
    _configure_headers(session)
    _configure_proxy(session, proxy_http, proxy_https)
    _configure_ssl(session, ssl_verify)
    _configure_adapter(session, ssl_min_version, max_retries)

    return session


# ── Interne Konfigurationshelfer ──────────────────────────────────────────────

def _configure_auth(
    session: requests.Session,
    username: Optional[str],
    api_token: Optional[str],
    bearer_token: Optional[str],
) -> None:
    if bearer_token:
        session.headers["Authorization"] = f"Bearer {bearer_token}"
        logger.debug("Auth: Bearer Token")
    elif username and api_token:
        session.auth = (username, api_token)
        logger.debug("Auth: Basic Auth (%s)", username)
    else:
        logger.warning("Keine Authentifizierung konfiguriert!")


def _configure_headers(session: requests.Session) -> None:
    session.headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Atlassian-Token": "no-check",
    })


def _configure_proxy(
    session: requests.Session,
    proxy_http: Optional[str],
    proxy_https: Optional[str],
) -> None:
    if proxy_http:
        session.proxies["http"] = proxy_http
        logger.info("HTTP-Proxy:  %s", proxy_http)
    if proxy_https:
        session.proxies["https"] = proxy_https
        logger.info("HTTPS-Proxy: %s", proxy_https)


def _configure_ssl(
    session: requests.Session,
    ssl_verify: Union[bool, str],
) -> None:
    session.verify = ssl_verify
    if ssl_verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning(
            "SSL-Verifizierung deaktiviert! Nicht für Produktionsumgebungen geeignet."
        )
    elif isinstance(ssl_verify, str):
        logger.info("SSL CA-Bundle: %s", ssl_verify)


def _configure_adapter(
    session: requests.Session,
    ssl_min_version: str,
    max_retries: int,
) -> None:
    retry = build_retry(max_retries)
    adapter = SSLAdapter(ssl_minimum_version=ssl_min_version, max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    logger.debug("SSL-Adapter: TLS-Mindestversion=%s, max_retries=%d", ssl_min_version, max_retries)
