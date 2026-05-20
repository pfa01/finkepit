#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
analyse_input.py
================
Dieses Skript erledigt zwei Aufgaben:

1. VERSCHIEBEN
   Alle Dateien aus input/Massentest (rekursiv, inkl. Unterordner)
   werden in den Ordner input/ verschoben.
   - Der Ordner Massentest wird danach gelöscht.
   - Bei Namenskonflikt: Datei erhält einen Timestamp-Suffix.

2. ANALYSE
   Alle Dateien in input/ werden auf ihren Nachrichtentyp untersucht.
   - XML-Dateien: Namespace und Typ aus dem <Document>-Tag
   - SWIFT-MT-Dateien (.txt, .fin): Typ aus dem {2:}-Block
   Ergebnis: analyse_JJJJMMTT_HHMMSS.csv im aktuellen Verzeichnis.

Aufruf:
    # Nur verschieben
    python analyse_input.py --remove-files

    # Nur analysieren
    python analyse_input.py --analyse-files

    # Beides – zuerst verschieben, dann analysieren
    python analyse_input.py --remove-files --analyse-files

    # Mit abweichenden Pfaden
    python analyse_input.py --remove-files --analyse-files \
        --input-dir pfad/zu/input \
        --output-dir pfad/zu/logs
"""

import argparse
import csv
import logging
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

# lxml bevorzugt, Fallback auf stdlib xml
try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    import xml.etree.ElementTree as ET
    LXML_AVAILABLE = False

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s  %(levelname)-7s  %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ── Konstanten ────────────────────────────────────────────────────────────────
DEFAULT_INPUT_DIR  = Path('input')
MASSENTEST_SUBDIR  = 'Massentest'
XML_EXTENSIONS     = {'.xml'}
MT_EXTENSIONS      = {'.txt', '.fin'}
ALL_EXTENSIONS     = XML_EXTENSIONS | MT_EXTENSIONS

MSG_TYPE_REGEX     = re.compile(r'([a-z]+\.\d{3})', re.IGNORECASE)
MT_BLOCK2_REGEX    = re.compile(r'\{2:[OI](\d{3})', re.IGNORECASE)

# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _timestamp_suffix() -> str:
    """Gibt einen Timestamp-Suffix zurück, z.B. _20240401_143022_123"""
    return datetime.now().strftime('_%Y%m%d_%H%M%S_%f')[:20]


def _resolve_conflict(target: Path) -> Path:
    """
    Gibt einen konfliktfreien Zielpfad zurück.
    Existiert die Datei bereits, wird ein Timestamp-Suffix an den Stamm angehängt.
    """
    if not target.exists():
        return target
    new_name = f"{target.stem}{_timestamp_suffix()}{target.suffix}"
    resolved = target.parent / new_name
    logger.debug("Namenskonflikt: %s → %s", target.name, resolved.name)
    return resolved


# ── Teil 1: Dateien verschieben ───────────────────────────────────────────────

def move_massentest_files(input_dir: Path,
                          subdir: str = MASSENTEST_SUBDIR) -> int:
    """
    Verschiebt alle Dateien aus input_dir/Massentest rekursiv nach input_dir.

    Die Ordnerstruktur unterhalb von Massentest wird aufgeloest – alle
    Dateien landen direkt in input/, unabhaengig von ihrer urspruenglichen
    Unterordner-Tiefe. Bei Namenskonflikt erhaelt die Datei einen Timestamp-Suffix.
    Löscht den Massentest-Ordner anschließend vollständig.
    Gibt die Anzahl verschobener Dateien zurück.
    """
    massentest_dir = input_dir / subdir

    if not massentest_dir.exists():
        logger.info("Ordner '%s' nicht vorhanden – nichts zu verschieben.",
                    massentest_dir)
        return 0

    if not massentest_dir.is_dir():
        logger.warning("'%s' ist kein Verzeichnis.", massentest_dir)
        return 0

    files = [p for p in massentest_dir.rglob('*') if p.is_file()]
    if not files:
        logger.info("Massentest-Ordner ist leer.")
    else:
        logger.info("Verschiebe %d Datei(en) aus '%s' nach '%s' ...",
                    len(files), massentest_dir, input_dir)

    moved = 0
    for src in files:
        target  = _resolve_conflict(input_dir / src.name)
        try:
            shutil.move(str(src), str(target))
            logger.info("  ✓  %s → %s", src.name, target.name)
            moved += 1
        except Exception as exc:
            logger.error("  ✗  %s: %s", src.name, exc)

    # Massentest-Ordner löschen (inkl. eventuell verbliebener leerer Unterordner)
    try:
        shutil.rmtree(massentest_dir)
        logger.info("Massentest-Ordner gelöscht.")
    except Exception as exc:
        logger.warning("Massentest-Ordner konnte nicht gelöscht werden: %s", exc)

    return moved


# ── Teil 2: Analyse ───────────────────────────────────────────────────────────

def _extract_message_type(namespace: str) -> str:
    """Extrahiert den ISO-20022-Nachrichtentyp aus einem Namespace-String."""
    m = MSG_TYPE_REGEX.search(namespace)
    return m.group(1).lower() if m else ''


def analyse_xml(file_path: Path) -> dict:
    """
    Parst eine XML-Datei und sucht nach dem <Document>-Tag.
    Gibt ein Dict mit namespace, message_type, root_element zurück.
    """
    result = {
        'namespace':    '',
        'message_type': '',
        'root_element': '',
        'error':        '',
    }
    try:
        if LXML_AVAILABLE:
            tree = etree.parse(str(file_path))
            root = tree.getroot()

            # Direkt nach <Document>-Tag suchen (max. 200 Elemente)
            for i, elem in enumerate(root.iter()):
                if i >= 200:
                    break
                try:
                    local = etree.QName(elem.tag).localname
                except Exception:
                    continue
                if local == 'Document':
                    ns = elem.nsmap.get(None) or etree.QName(elem.tag).namespace
                    if ns:
                        result['namespace']    = ns
                        result['message_type'] = _extract_message_type(ns)
                        result['root_element'] = local
                        return result

            # Fallback: Swiss SIX oder SEPA Bulk ohne Document-Wrapper
            for i, elem in enumerate(root.iter()):
                if i >= 200:
                    break
                for ns in (elem.nsmap or {}).values():
                    if ns and ('tech:xsd:' in ns or
                               'six-interbank-clearing.com' in ns):
                        try:
                            local = etree.QName(elem.tag).localname
                        except Exception:
                            local = ''
                        result['namespace']    = ns
                        result['message_type'] = _extract_message_type(ns)
                        result['root_element'] = local
                        return result

            # Root-Element als Fallback eintragen
            try:
                result['root_element'] = etree.QName(root.tag).localname
            except Exception:
                result['root_element'] = root.tag

        else:
            # Fallback: stdlib xml.etree
            tree = ET.parse(str(file_path))
            root = tree.getroot()
            for elem in root.iter():
                tag = elem.tag
                if tag.startswith('{'):
                    ns    = tag.split('}')[0][1:]
                    local = tag.split('}')[1]
                else:
                    ns    = ''
                    local = tag
                if local == 'Document' and ns:
                    result['namespace']    = ns
                    result['message_type'] = _extract_message_type(ns)
                    result['root_element'] = local
                    return result

    except Exception as exc:
        result['error'] = str(exc)

    return result


def analyse_swift_mt(file_path: Path) -> dict:
    """
    Liest eine SWIFT-MT-Datei und extrahiert den Nachrichtentyp
    aus dem {2:O/I}-Block.
    """
    result = {
        'namespace':    '',
        'message_type': '',
        'root_element': '',
        'error':        '',
    }
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
        m = MT_BLOCK2_REGEX.search(content)
        if m:
            result['message_type'] = f"MT{m.group(1)}"
        else:
            # Fallback: explizite MT-Angabe im Text
            m2 = re.search(r'MT\s*(\d{3})', content, re.IGNORECASE)
            if m2:
                result['message_type'] = f"MT{m2.group(1)}"
            else:
                result['error'] = 'Kein MT-Typ gefunden'
    except Exception as exc:
        result['error'] = str(exc)

    return result


def analyse_files(input_dir: Path) -> list:
    """
    Analysiert alle Dateien in input_dir (nicht rekursiv – Massentest ist weg).
    Gibt eine Liste von Dicts zurück.
    """
    files = sorted(
        p for p in input_dir.iterdir()
        if p.is_file() and p.suffix.lower() in ALL_EXTENSIONS
    )

    if not files:
        logger.warning("Keine Dateien mit bekannter Endung in '%s'.", input_dir)
        return []

    logger.info("Analysiere %d Datei(en) ...", len(files))
    rows = []

    for file_path in files:
        ext = file_path.suffix.lower()
        size_kb = round(file_path.stat().st_size / 1024, 1)

        if ext in XML_EXTENSIONS:
            info = analyse_xml(file_path)
        elif ext in MT_EXTENSIONS:
            info = analyse_swift_mt(file_path)
        else:
            info = {'namespace':'','message_type':'','root_element':'',
                    'error':'Unbekannte Endung'}

        row = {
            'Dateipfad':        str(file_path),
            'Dateiname':        file_path.name,
            'Namespace':        info['namespace'],
            'Nachrichtentyp':   info['message_type'],
            'Root-Element':     info['root_element'],
            'Groesse_KB':       size_kb,
            'Fehler':           info['error'],
        }
        rows.append(row)

        status = f"  {info['message_type'] or '?':20s}  {info['namespace'][:60]}" \
                 if not info['error'] else f"  FEHLER: {info['error'][:60]}"
        logger.info("  %-40s%s", file_path.name, status)

    return rows


# ── Teil 3: CSV schreiben ─────────────────────────────────────────────────────

def write_csv(rows: list, output_dir: Path) -> Path:
    """Schreibt die Analyseergebnisse in eine CSV-Datei mit Timestamp."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_path  = output_dir / f"analyse_{timestamp}.csv"

    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        fieldnames = [
            'Dateipfad', 'Dateiname', 'Namespace',
            'Nachrichtentyp', 'Root-Element', 'Groesse_KB', 'Fehler'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';')
        writer.writeheader()
        writer.writerows(rows)

    logger.info("CSV geschrieben: %s  (%d Zeilen)", csv_path, len(rows))
    return csv_path


# ── Hauptprogramm ─────────────────────────────────────────────────────────────

def _print_summary(rows: list, csv_path: Path = None):
    """Gibt eine Zusammenfassung der Analyseergebnisse aus."""
    types  = {}
    errors = 0
    for r in rows:
        mt = r['Nachrichtentyp'] or 'unbekannt'
        types[mt] = types.get(mt, 0) + 1
        if r['Fehler']:
            errors += 1

    print()
    print('=' * 60)
    print(f"  Dateien analysiert:  {len(rows)}")
    print(f"  Fehler:              {errors}")
    print(f"  Nachrichtentypen:")
    for mt, cnt in sorted(types.items()):
        print(f"    {mt:<20} {cnt:>4}x")
    if csv_path:
        print(f"  CSV: {csv_path}")
    print('=' * 60)
    print()


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Werkzeug zum Verschieben und Analysieren von Zahlungsnachrichten.\n'
            '\n'
            'Die beiden Funktionen lassen sich unabhängig voneinander aufrufen:\n'
            '  --remove-files     Dateien aus input/Massentest nach input/ verschieben\n'
            '  --analyse-files  Alle Dateien in input/ analysieren und CSV erzeugen\n'
            '\n'
            'Werden beide Flags angegeben, wird zuerst verschoben, dann analysiert.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # ── Hauptaktionen ────────────────────────────────────────────────────
    action_group = parser.add_argument_group('Aktionen (mindestens eine angeben)')
    action_group.add_argument(
        '--remove-files',
        action='store_true',
        help=(
            'Alle Dateien aus input/Massentest rekursiv nach input/ verschieben. '
            'Die Unterordnerstruktur wird aufgelöst – alle Dateien landen '
            'direkt in input/, egal wie tief sie lagen. '
            'Bei Namenskonflikt erhält die Datei einen Timestamp-Suffix. '
            'Massentest-Ordner wird anschließend vollständig gelöscht.'
        )
    )
    action_group.add_argument(
        '--analyse-files',
        action='store_true',
        help=(
            'Alle .xml-, .txt- und .fin-Dateien in input/ analysieren. '
            'Für XML-Dateien wird der Namespace aus dem <Document>-Tag gelesen, '
            'für SWIFT-MT-Dateien der Typ aus dem {2:}-Block. '
            'Ergebnis: analyse_JJJJMMTT_HHMMSS.csv im Output-Verzeichnis.'
        )
    )

    # ── Pfade ────────────────────────────────────────────────────────────
    path_group = parser.add_argument_group('Pfade')
    path_group.add_argument(
        '--input-dir',
        type=Path,
        default=DEFAULT_INPUT_DIR,
        metavar='PFAD',
        help=f'Pfad zum Input-Ordner (Standard: {DEFAULT_INPUT_DIR})'
    )
    path_group.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        metavar='PFAD',
        help='Zielordner für die CSV-Datei (Standard: aktuelles Verzeichnis)'
    )
    path_group.add_argument(
        '--massentest-dir',
        type=str,
        default=MASSENTEST_SUBDIR,
        metavar='NAME',
        help=f'Name des Quell-Unterordners (Standard: {MASSENTEST_SUBDIR})'
    )

    args = parser.parse_args()

    # Mindestens eine Aktion muss angegeben sein
    if not args.remove_files and not args.analyse_files:
        parser.print_help()
        print()
        print('Fehler: Bitte mindestens eine Aktion angeben '
              '(--remove-files und/oder --analyse-files).')
        sys.exit(1)

    input_dir  = args.input_dir
    output_dir = args.output_dir or Path('.')

    if not input_dir.exists():
        logger.error("Input-Ordner nicht gefunden: %s", input_dir)
        sys.exit(1)

    # ── Aktion 1: Verschieben ─────────────────────────────────────────────
    if args.remove_files:
        print()
        print('=' * 60)
        print('  DATEIEN VERSCHIEBEN  (--remove-files)')
        print('=' * 60)

        moved = move_massentest_files(input_dir, args.massentest_dir)
        logger.info("%d Datei(en) erfolgreich verschoben.", moved)

    # ── Aktion 2: Analysieren ─────────────────────────────────────────────
    if args.analyse_files:
        print()
        print('=' * 60)
        print('  DATEIEN ANALYSIEREN  (--analyse-files)')
        print('=' * 60)

        rows = analyse_files(input_dir)

        if not rows:
            logger.info("Keine Dateien mit bekannter Endung in '%s'.", input_dir)
            return

        print()
        print('=' * 60)
        print('  CSV SCHREIBEN')
        print('=' * 60)

        csv_path = write_csv(rows, output_dir)
        _print_summary(rows, csv_path)


if __name__ == '__main__':
    main()
