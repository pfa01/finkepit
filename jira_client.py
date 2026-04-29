"""
jira_client.py
──────────────
Kapselt die Kommunikation mit der Jira REST API v2.
Unterstützt Einzelabfragen, JQL-Suche und automatische Paginierung.
"""

import json
import logging
from typing import Generator, Optional, Union
from urllib.parse import urljoin

import requests

from session_factory import create_session

logger = logging.getLogger(__name__)


class JiraClient:
    """
    Client für die Jira REST API v2.

    Beispiel:
        client = JiraClient(
            base_url="https://company.atlassian.net",
            username="user@company.com",
            api_token="<TOKEN>",
            proxy_https="http://proxy.corp.local:8080",
            ssl_verify="/etc/ssl/certs/corp-ca.pem",
        )
        issue = client.get_issue("PROJ-42")
    """

    API_PATH = "/rest/api/2"

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        api_token: Optional[str] = None,
        bearer_token: Optional[str] = None,
        proxy_http: Optional[str] = None,
        proxy_https: Optional[str] = None,
        ssl_verify: Union[bool, str] = True,
        ssl_min_version: str = "TLSv1_2",
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = create_session(
            username=username,
            api_token=api_token,
            bearer_token=bearer_token,
            proxy_http=proxy_http,
            proxy_https=proxy_https,
            ssl_verify=ssl_verify,
            ssl_min_version=ssl_min_version,
            max_retries=max_retries,
        )

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def get_server_info(self) -> dict:
        """Gibt Versions- und Instanzinformationen des Jira-Servers zurück."""
        data = self._get("serverInfo")
        logger.info(
            "Verbunden mit: %s (Version %s)",
            data.get("serverTitle"),
            data.get("version"),
        )
        return data

    def get_projects(self) -> list:
        """Gibt alle für den Benutzer zugänglichen Projekte zurück."""
        projects = self._get("project")
        logger.info("%d Projekte geladen.", len(projects))
        return projects

    def get_issue(
        self,
        issue_key: str,
        fields: Optional[list[str]] = None,
    ) -> dict:
        """
        Lädt ein einzelnes Issue anhand seines Keys.

        Args:
            issue_key: Jira Issue-Key, z. B. "PROJ-42"
            fields:    Optionale Feldliste; None → alle navigierbaren Felder

        Returns:
            Issue-Dictionary (vollständige API-Antwort)
        """
        params = {}
        if fields:
            params["fields"] = ",".join(fields)

        data = self._get(f"issue/{issue_key}", params=params)
        logger.info(
            "Issue geladen: %s – %s",
            issue_key,
            data["fields"].get("summary", "(kein Titel)"),
        )
        return data

    def search_issues(
        self,
        jql: str,
        fields: Optional[list[str]] = None,
        max_results: int = 50,
        start_at: int = 0,
    ) -> dict:
        """
        Durchsucht Issues per JQL (eine Seite).

        Args:
            jql:         JQL-Abfragestring
            fields:      Felder die zurückgegeben werden sollen
            max_results: Maximale Anzahl Ergebnisse pro Seite (max. 100)
            start_at:    Offset für Paginierung

        Returns:
            API-Antwort mit: issues, total, startAt, maxResults
        """
        params = {
            "jql": jql,
            "startAt": start_at,
            "maxResults": min(max_results, 100),
            "fields": ",".join(fields) if fields else "*navigable",
        }
        result = self._get("search", params=params)
        logger.debug(
            "Suche: %d/%d Issues ab Position %d",
            len(result.get("issues", [])),
            result.get("total", 0),
            start_at,
        )
        return result

    def iter_all_issues(
        self,
        jql: str,
        fields: Optional[list[str]] = None,
        page_size: int = 50,
    ) -> Generator[dict, None, None]:
        """
        Generator, der automatisch alle Seiten durchläuft.

        Args:
            jql:       JQL-Abfragestring
            fields:    Felder die zurückgegeben werden sollen
            page_size: Anzahl Issues pro API-Aufruf (max. 100)

        Yields:
            Einzelne Issue-Dictionaries
        """
        start_at = 0
        total: Optional[int] = None

        while total is None or start_at < total:
            result = self.search_issues(
                jql=jql,
                fields=fields,
                max_results=page_size,
                start_at=start_at,
            )

            if total is None:
                total = result["total"]
                logger.info("JQL '%s' → %d Issues gefunden.", jql, total)

            issues = result.get("issues", [])
            if not issues:
                break

            yield from issues
            start_at += len(issues)

        logger.info("Paginierung abgeschlossen. Gesamt geliefert: %d", start_at)

    # ── Interne Hilfsmethoden ─────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return urljoin(self.base_url + self.API_PATH + "/", path.lstrip("/"))

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = self._url(path)
        logger.debug("GET %s | params=%s", url, params)
        response = self.session.get(url, params=params, timeout=self.timeout)
        _raise_for_status(response)
        return response.json()


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _raise_for_status(response: requests.Response) -> None:
    """Wirft HTTPError mit lesbarer Fehlermeldung aus der API-Antwort."""
    if response.ok:
        return
    try:
        body = response.json()
        messages = body.get("errorMessages") or [json.dumps(body)]
    except Exception:
        messages = [response.text or "(kein Body)"]

    raise requests.HTTPError(
        f"HTTP {response.status_code} bei {response.url}\n" + "\n".join(messages),
        response=response,
    )
