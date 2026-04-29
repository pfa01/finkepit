"""
cli.py
──────
Kommandozeileninterface für den Jira REST API v2 Client.

Verwendung:
    python cli.py --help
"""

import argparse
import json
import logging
import sys
from typing import Optional, Union

import requests

from jira_client import JiraClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger("jira_cli")


# ── Argument-Parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Jira REST API v2 – Issue Reader",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    conn = p.add_argument_group("Verbindung")
    conn.add_argument(
        "--url", required=True,
        help="Jira-Instanz-URL, z. B. https://company.atlassian.net",
    )
    conn.add_argument("--username", help="Jira-Benutzername / E-Mail (Basic Auth)")
    conn.add_argument("--api-token", help="API-Token (Basic Auth)")
    conn.add_argument("--bearer-token", help="Personal Access Token (Bearer Auth)")

    prx = p.add_argument_group("Proxy")
    prx.add_argument("--proxy-http",  help="HTTP-Proxy,  z. B. http://proxy:8080")
    prx.add_argument("--proxy-https", help="HTTPS-Proxy, z. B. http://proxy:8080")

    ssl_g = p.add_argument_group("SSL")
    ssl_g.add_argument(
        "--ssl-verify", default="true",
        help="true | false | Pfad zu CA-Bundle (.pem)",
    )
    ssl_g.add_argument(
        "--ssl-min-version", default="TLSv1_2",
        choices=["TLSv1_2", "TLSv1_3"],
        help="Minimale TLS-Version",
    )

    act = p.add_argument_group("Aktionen")
    act.add_argument("--info",     action="store_true", help="Server-Info ausgeben")
    act.add_argument("--projects", action="store_true", help="Alle Projekte listen")
    act.add_argument("--issue",    metavar="KEY",       help="Einzelnes Issue laden (z. B. PROJ-42)")
    act.add_argument("--jql",      metavar="QUERY",     help='JQL-Query, z. B. "project=PROJ AND status=Open"')
    act.add_argument(
        "--fields", metavar="FELDER",
        help='Kommagetrennte Felder, z. B. "summary,status,assignee,priority"',
    )
    act.add_argument("--max-results", type=int, default=50, help="Maximale Trefferzahl pro Seite")
    act.add_argument("--all-pages",   action="store_true", help="Alle Seiten abrufen (automatische Paginierung)")
    act.add_argument(
        "--output", choices=["pretty", "json"], default="pretty",
        help="Ausgabeformat (pretty = eingerücktes JSON)",
    )
    act.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log-Level",
    )

    return p


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def resolve_ssl_verify(value: str) -> Union[bool, str]:
    """Wandelt den CLI-String-Parameter in den korrekten requests-Typ um."""
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value  # Pfad zu CA-Bundle


def parse_fields(raw: Optional[str]) -> Optional[list[str]]:
    if not raw:
        return None
    return [f.strip() for f in raw.split(",") if f.strip()]


def print_result(data, fmt: str) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


# ── Hauptlogik ────────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    """Führt die angeforderten Aktionen aus. Gibt Exit-Code zurück."""
    logging.getLogger().setLevel(args.log_level)

    client = JiraClient(
        base_url=args.url,
        username=args.username,
        api_token=args.api_token,
        bearer_token=args.bearer_token,
        proxy_http=args.proxy_http,
        proxy_https=args.proxy_https,
        ssl_verify=resolve_ssl_verify(args.ssl_verify),
        ssl_min_version=args.ssl_min_version,
    )

    fields = parse_fields(args.fields)

    try:
        if args.info:
            print_result(client.get_server_info(), args.output)

        if args.projects:
            print_result(client.get_projects(), args.output)

        if args.issue:
            print_result(client.get_issue(args.issue, fields=fields), args.output)

        if args.jql:
            if args.all_pages:
                issues = list(client.iter_all_issues(args.jql, fields=fields))
                logger.info("Gesamt geliefert: %d Issues", len(issues))
                print_result(issues, args.output)
            else:
                result = client.search_issues(
                    jql=args.jql,
                    fields=fields,
                    max_results=args.max_results,
                )
                logger.info(
                    "%d von %d Issues geladen.",
                    len(result["issues"]),
                    result["total"],
                )
                print_result(result, args.output)

    except requests.HTTPError as exc:
        logger.error("API-Fehler:\n%s", exc)
        return 1
    except requests.ConnectionError as exc:
        logger.error("Verbindungsfehler: %s", exc)
        return 1
    except requests.Timeout:
        logger.error("Timeout – Jira hat nicht rechtzeitig geantwortet.")
        return 1
    except KeyboardInterrupt:
        logger.info("Abgebrochen.")
        return 0

    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not any([args.info, args.projects, args.issue, args.jql]):
        parser.print_help()
        sys.exit(0)

    sys.exit(run(args))


if __name__ == "__main__":
    main()
