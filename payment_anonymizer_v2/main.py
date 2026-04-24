#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
main.py
=======
CLI-Einstiegspunkt für den Payment Message Anonymizer.

Verwendung
----------
  python main.py                              # Ganzes Input-Verzeichnis
  python main.py -c custom_config.json        # Eigene Konfiguration
  python main.py -f einzelne_datei.xml        # Einzelne Datei
  python main.py -f "input/pacs.*.xml"        # Wildcard
  python main.py -f "input/*.xml,input/*.fin" # Mehrere Muster
  python main.py -f "input/**/*.xml"          # Rekursiv
"""

import argparse
import sys

from payment_anonymizer import PaymentAnonymizer


def main():
    """Haupteinstiegspunkt."""
    parser = argparse.ArgumentParser(
        description=(
            'Payment Message Anonymizer – '
            'Anonymisiert ISO 20022 und SWIFT MT Nachrichten'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python main.py
      Verarbeitet alle Dateien im konfigurierten Input-Verzeichnis.

  python main.py -c custom_config.json
      Verwendet eine eigene Konfigurationsdatei.

  python main.py -f input/pacs.008.xml
      Verarbeitet eine einzelne Datei.

  python main.py -f "input/pacs.*.xml"
      Verarbeitet alle pacs-Dateien im input-Verzeichnis (Wildcard).

  python main.py -f "input/*.xml,input/*.fin"
      Mehrere Muster kommagetrennt.

  python main.py -f "input/**/*.xml"
      Alle XML-Dateien rekursiv in Unterverzeichnissen.

  python main.py -v
      Ausführliche Fehlerausgabe (Stacktrace).
        """
    )

    parser.add_argument(
        '-c', '--config',
        default='config.json',
        help='Pfad zur Konfigurationsdatei (Standard: config.json)'
    )
    parser.add_argument(
        '-f', '--file',
        help=(
            'Datei(en) verarbeiten statt ganzes Verzeichnis.\n'
            'Unterstützt Wildcards und kommagetrennte Muster:\n'
            '  Einzeldatei:  input/pacs.008.xml\n'
            '  Wildcard:     "input/pacs.*.xml"\n'
            '  Mehrere:      "input/*.xml,input/*.fin"\n'
            '  Rekursiv:     "input/**/*.xml"'
        )
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Ausführliche Ausgabe bei Fehlern (Stacktrace)'
    )

    args = parser.parse_args()

    try:
        anonymizer = PaymentAnonymizer(args.config)

        if args.file:
            results = anonymizer.process_files(args.file)
            anonymizer.print_summary(results)
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
