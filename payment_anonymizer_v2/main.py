#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
main.py
=======
CLI-Einstiegspunkt für den Payment Message Anonymizer.

Verwendung
----------
  python main.py                        # Verarbeitet alle Dateien mit Standard-Config
  python main.py -c custom_config.json  # Verwendet eigene Konfiguration
  python main.py -f einzelne_datei.xml  # Verarbeitet eine einzelne Datei
"""

import argparse
import sys
from pathlib import Path

from payment_anonymizer import PaymentAnonymizer


def main():
    """Haupteinstiegspunkt."""
    parser = argparse.ArgumentParser(
        description=(
            'Payment Message Anonymizer - '
            'Anonymisiert ISO 20022 und SWIFT MT Nachrichten'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python main.py                        # Verarbeitet alle Dateien mit Standard-Config
  python main.py -c custom_config.json  # Verwendet eigene Konfiguration
  python main.py -f einzelne_datei.xml  # Verarbeitet eine einzelne Datei
        """
    )

    parser.add_argument(
        '-c', '--config',
        default='config.json',
        help='Pfad zur Konfigurationsdatei (Standard: config.json)'
    )
    parser.add_argument(
        '-f', '--file',
        help='Einzelne Datei verarbeiten (statt ganzes Verzeichnis)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Ausführliche Ausgabe'
    )

    args = parser.parse_args()

    try:
        anonymizer = PaymentAnonymizer(args.config)

        if args.file:
            result = anonymizer.process_file(Path(args.file))
            anonymizer.logger.add_result(result)
            anonymizer.logger.write_log()
            anonymizer.print_summary([result])
        else:
            results = anonymizer.process_directory()
            anonymizer.print_summary(results)

    except FileNotFoundError as e:
        print(f"Fehler: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unerwarteter Fehler: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
