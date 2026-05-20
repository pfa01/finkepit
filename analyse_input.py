#!/usr/bin/env python3
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


# ── Teil 4: Kontoverbindungs-Analyse ─────────────────────────────────────────

IBAN_RE      = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b')
BIC_RE       = re.compile(r'\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b')
MT86_IBAN_RE = re.compile(r'/IBAN/([A-Z]{2}\d{2}[A-Z0-9]{4,30})')
MT86_BIC_RE  = re.compile(r'/BIC/([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)')
MT86_NAME_RE = re.compile(r'/(?:ABWA|ABWE|NAME|ENAM)/([^/\n]{2,70})')
MT86_KEY_RE  = re.compile(r'/(?P<key>ABWA|ABWE|NAME|ENAM|IBAN|BIC)/(?P<val>[^/\n]{1,70})')

ISO_IBAN_TAGS = {'IBAN', 'PrtryAcct'}
ISO_BIC_TAGS  = {'BICFI', 'BIC', 'MmbId'}

# ISO 20022: Bekannte Rollen-Tags (Eltern-Elemente der Datenfelder)
ISO_ROLE_TAGS = {
    'Dbtr', 'DbtrAcct', 'DbtrAgt',
    'Cdtr', 'CdtrAcct', 'CdtrAgt',
    'InitgPty', 'UltmtDbtr', 'UltmtCdtr',
    'IntrmyAgt1', 'IntrmyAgt2', 'IntrmyAgt3',
    'IntrmyAgt1Acct', 'IntrmyAgt2Acct', 'IntrmyAgt3Acct',
    'InstgAgt', 'InstdAgt',
    'Assgnr', 'Assgnee',
}

# SWIFT MT: Feld → lesbare Rollenbezeichnung
MT_TAG_ROLE = {
    ':25:':  'Konto',      ':25A:': 'Konto',    ':25P:': 'Konto',
    ':50:':  'Auftraggeber', ':50A:': 'Auftraggeber',
    ':50F:': 'Auftraggeber', ':50K:': 'Auftraggeber',
    ':52A:': 'Auftraggeberbank', ':52D:': 'Auftraggeberbank',
    ':53A:': 'KorrBank-Auftr',   ':53B:': 'KorrBank-Auftr',
    ':53D:': 'KorrBank-Auftr',
    ':54A:': 'KorrBank-Empf',    ':54B:': 'KorrBank-Empf',
    ':54D:': 'KorrBank-Empf',
    ':56A:': 'Intermediary',     ':56D:': 'Intermediary',
    ':57A:': 'Empfaengerbank',   ':57B:': 'Empfaengerbank',
    ':57D:': 'Empfaengerbank',
    ':59:':  'Beguenstigter', ':59A:': 'Beguenstigter',
    ':59F:': 'Beguenstigter',
}
MT86_KEY_ROLE = {
    'ABWA': 'Auftraggeber', 'ABWE': 'Beguenstigter',
    'NAME': 'Beteiligter',  'ENAM': 'Beteiligter',
    'IBAN': 'Zahlung',      'BIC':  'Zahlung',
}

# ── Kategorisierung: Rolle → Auftraggeber / Empfaenger / Sonstige ─────────────
# Dieses Mapping steuert die neuen CSV-Spalten "Auftraggeber_BIC" und
# "Empfaenger_BIC". Jede Rolle wird genau einer Kategorie zugeordnet.
# Rollen ohne Eintrag landen in keiner der beiden Spalten.
ROLE_CATEGORY = {
    # Auftraggeber-Seite (ISO 20022)
    'Dbtr':               'Auftraggeber',
    'DbtrAcct':           'Auftraggeber',
    'DbtrAgt':            'Auftraggeber',
    'InitgPty':           'Auftraggeber',
    'UltmtDbtr':          'Auftraggeber',
    'InstgAgt':           'Auftraggeber',
    'Assgnr':             'Auftraggeber',
    # Auftraggeber-Seite (SWIFT MT)
    'Konto':              'Auftraggeber',
    'Auftraggeber':       'Auftraggeber',
    'Auftraggeberbank':   'Auftraggeber',
    'KorrBank-Auftr':     'Auftraggeber',

    # Empfaenger-Seite (ISO 20022)
    'Cdtr':               'Empfaenger',
    'CdtrAcct':           'Empfaenger',
    'CdtrAgt':            'Empfaenger',
    'UltmtCdtr':          'Empfaenger',
    'InstdAgt':           'Empfaenger',
    'Assgnee':            'Empfaenger',
    # Empfaenger-Seite (SWIFT MT)
    'Beguenstigter':      'Empfaenger',
    'Empfaengerbank':     'Empfaenger',
    'KorrBank-Empf':      'Empfaenger',

    # Nicht zugeordnet (werden nicht in Auftraggeber/Empfaenger-Spalten aufgenommen)
    # IntrmyAgt*, Intermediary, Zahlung, Beteiligter → landen nur in BICs/IBANs/Namen
}


def _fmt(role: str, value: str) -> str:
    """Formatiert einen Wert mit Rollen-Präfix: 'Dbtr:DE89...'"""
    return f"{role}:{value}"


def _dedupe_tagged(pairs: list) -> str:
    """
    Gibt '|'-getrennte eindeutige Rolle:Wert-Paare zurück.
    Beispiel: 'Dbtr:DE89... | Cdtr:DE27...'
    Gleicher Wert mit gleicher Rolle wird nur einmal ausgegeben.
    """
    seen = []
    for role, val in pairs:
        val  = val.strip()
        entry = _fmt(role, val)
        if val and entry not in seen:
            seen.append(entry)
    return ' | '.join(seen)


def _find_role_ancestor(elem, get_local) -> str:
    """
    Läuft den Elternbaum nach oben und gibt den ersten bekannten
    Rollen-Tag zurück. Fallback: direkter Eltern-Tag-Name.
    """
    node = elem.getparent() if hasattr(elem, 'getparent') else None
    while node is not None:
        local = get_local(node)
        if local in ISO_ROLE_TAGS:
            return local
        node = node.getparent() if hasattr(node, 'getparent') else None
    # Fallback: direktes Elternelement
    parent = elem.getparent() if hasattr(elem, 'getparent') else None
    return get_local(parent) if parent is not None else '?'


def _extract_accounts_xml(file_path: Path) -> dict:
    """
    Extrahiert IBANs, BICs und Namen mit Rollen-Tags aus einer
    ISO-20022-XML-Datei.

    Jeder Wert erhält den Rollen-Tag seines Elternbaums als Präfix,
    z.B. 'Dbtr', 'Cdtr', 'DbtrAgt'. Das ermöglicht die eindeutige
    Zuordnung als Auftraggeber oder Zahlungsempfänger.
    """
    result = {'ibans': [], 'bics': [], 'names': [], 'error': ''}
    try:
        if LXML_AVAILABLE:
            root = etree.parse(str(file_path)).getroot()

            def get_local(e):
                try:
                    return etree.QName(e.tag).localname
                except Exception:
                    return ''

            for elem in root.iter():
                local = get_local(elem)
                val   = (elem.text or '').strip()
                if not val:
                    continue
                if local in ISO_IBAN_TAGS and IBAN_RE.match(val):
                    role = _find_role_ancestor(elem, get_local)
                    result['ibans'].append((role, val))
                elif local in ISO_BIC_TAGS and BIC_RE.match(val):
                    role = _find_role_ancestor(elem, get_local)
                    result['bics'].append((role, val))
                elif local == 'Nm':
                    role = _find_role_ancestor(elem, get_local)
                    result['names'].append((role, val))
        else:
            root = ET.parse(str(file_path)).getroot()

            def get_local_et(e):
                t = e.tag
                return t.split('}')[1] if '}' in t else t

            # ET hat kein getparent() – Parent-Map aufbauen
            parent_map = {c: p for p in root.iter() for c in p}

            def find_role_et(elem):
                node = parent_map.get(elem)
                while node is not None:
                    local = get_local_et(node)
                    if local in ISO_ROLE_TAGS:
                        return local
                    node = parent_map.get(node)
                p = parent_map.get(elem)
                return get_local_et(p) if p is not None else '?'

            for elem in root.iter():
                local = get_local_et(elem)
                val   = (elem.text or '').strip()
                if not val:
                    continue
                if local in ISO_IBAN_TAGS and IBAN_RE.match(val):
                    result['ibans'].append((find_role_et(elem), val))
                elif local in ISO_BIC_TAGS and BIC_RE.match(val):
                    result['bics'].append((find_role_et(elem), val))
                elif local == 'Nm':
                    result['names'].append((find_role_et(elem), val))
    except Exception as exc:
        result['error'] = str(exc)
    return result


def _extract_accounts_mt(file_path: Path) -> dict:
    """
    Extrahiert IBANs, BICs und Namen mit Rollen aus einer SWIFT-MT-Datei.

    Ausgewertete Felder und ihre Rollen:
      :25:/:25A:  → Konto
      :50x:       → Auftraggeber
      :52x:       → Auftraggeberbank
      :53x:       → KorrBank-Auftr
      :54x:       → KorrBank-Empf
      :56x:       → Intermediary
      :57x:       → Empfaengerbank
      :59x:       → Beguenstigter
      :86:        → /ABWA/ Auftraggeber | /ABWE/ Beguenstigter |
                    /NAME/ Beteiligter  | /IBAN/ Zahlung | /BIC/ Zahlung
    """
    result = {'ibans': [], 'bics': [], 'names': [], 'error': ''}
    try:
        content  = file_path.read_text(encoding='utf-8', errors='replace')
        field_re = re.compile(
            r':(\d{2}[A-Z]?):(.*?)(?=\n:\d{2}[A-Z]?:|\n-\}|$)',
            re.DOTALL
        )
        for m in field_re.finditer(content):
            tag   = f":{m.group(1)}:"
            value = m.group(2).strip()
            role  = MT_TAG_ROLE.get(tag, '')

            if role:
                for iban in IBAN_RE.findall(value):
                    result['ibans'].append((role, iban))
                for line in value.split('\n'):
                    line = line.strip().lstrip('/')
                    if BIC_RE.match(line):
                        result['bics'].append((role, line))
                    elif line and not IBAN_RE.match(line) and len(line) > 3:
                        if not re.match(r'^[\d,./+\-]+$', line):
                            result['names'].append((role, line))

            # :86: Subfelder mit individuellen Rollen
            if tag == ':86:':
                for hit in MT86_KEY_RE.finditer(value):
                    key  = hit.group('key')
                    val  = hit.group('val').strip()
                    r86  = MT86_KEY_ROLE.get(key, 'Info')
                    if key == 'IBAN' and IBAN_RE.match(val):
                        result['ibans'].append((r86, val))
                    elif key == 'BIC' and BIC_RE.match(val):
                        result['bics'].append((r86, val))
                    else:
                        result['names'].append((r86, val))
    except Exception as exc:
        result['error'] = str(exc)
    return result


def analyse_account_connections(source_dir: Path) -> list:
    """
    Analysiert alle XML- und MT-Dateien in source_dir rekursiv.
    Pro Datei eine Zeile mit allen Kontoverbindungen inkl. Rolle.

    Format in der CSV:
      IBANs/BICs/Namen: 'Dbtr:DE89... | Cdtr:DE27...'
      Auftraggeber_BIC: BICs der Auftraggeber-Seite (via ROLE_CATEGORY)
      Empfaenger_BIC:   BICs der Empfaenger-Seite  (via ROLE_CATEGORY)
    """
    files = sorted(
        p for p in source_dir.rglob('*')
        if p.is_file() and p.suffix.lower() in ALL_EXTENSIONS
    )
    if not files:
        logger.warning("Keine Dateien in '%s' gefunden.", source_dir)
        return []

    logger.info("Kontoverbindungen aus %d Datei(en) extrahieren ...", len(files))
    rows = []
    for file_path in files:
        ext     = file_path.suffix.lower()
        size_kb = round(file_path.stat().st_size / 1024, 1)

        if ext in XML_EXTENSIONS:
            msg_info = analyse_xml(file_path)
            accounts = _extract_accounts_xml(file_path)
        else:
            msg_info = analyse_swift_mt(file_path)
            accounts = _extract_accounts_mt(file_path)

        ibans = _dedupe_tagged(accounts['ibans'])
        bics  = _dedupe_tagged(accounts['bics'])
        names = _dedupe_tagged(accounts['names'])
        error = accounts['error'] or msg_info.get('error', '')

        # BICs und IBANs nach Kategorie aufteilen (via ROLE_CATEGORY-Mapping)
        auftr_bics  = []
        empf_bics   = []
        auftr_ibans = []
        empf_ibans  = []

        for role, bic in accounts['bics']:
            cat = ROLE_CATEGORY.get(role)
            bic = bic.strip()
            if cat == 'Auftraggeber' and bic not in auftr_bics:
                auftr_bics.append(bic)
            elif cat == 'Empfaenger' and bic not in empf_bics:
                empf_bics.append(bic)

        for role, iban in accounts['ibans']:
            cat  = ROLE_CATEGORY.get(role)
            iban = iban.strip()
            if cat == 'Auftraggeber' and iban not in auftr_ibans:
                auftr_ibans.append(iban)
            elif cat == 'Empfaenger' and iban not in empf_ibans:
                empf_ibans.append(iban)

        rows.append({
            'Dateipfad':         str(file_path),
            'Dateiname':         file_path.name,
            'Nachrichtentyp':    msg_info.get('message_type', ''),
            'IBANs':             ibans,
            'BICs':              bics,
            'Namen':             names,
            'Auftraggeber_BIC':  ', '.join(auftr_bics),
            'Auftraggeber_IBAN': ', '.join(auftr_ibans),
            'Empfaenger_BIC':    ', '.join(empf_bics),
            'Empfaenger_IBAN':   ', '.join(empf_ibans),
            'Groesse_KB':        size_kb,
            'Fehler':            error,
        })
        logger.info(
            "  %-35s  %-12s  "
            "Auftr-BIC:%s  Auftr-IBAN:%s  Empf-BIC:%s  Empf-IBAN:%s%s",
            file_path.name,
            msg_info.get('message_type', '?'),
            ', '.join(auftr_bics)  or '-',
            ', '.join(auftr_ibans) or '-',
            ', '.join(empf_bics)   or '-',
            ', '.join(empf_ibans)  or '-',
            f"  FEHLER: {error[:30]}" if error else ''
        )
    return rows


def write_account_csv(rows: list, output_dir: Path) -> Path:
    """Schreibt die Kontoverbindungs-Analyse in eine CSV mit Timestamp."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_path  = output_dir / f"kontoverbindungen_{timestamp}.csv"
    fieldnames = [
        'Dateipfad', 'Dateiname', 'Nachrichtentyp',
        'IBANs', 'BICs', 'Namen',
        'Auftraggeber_BIC', 'Auftraggeber_IBAN',
        'Empfaenger_BIC',   'Empfaenger_IBAN',
        'Groesse_KB', 'Fehler'
    ]
    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
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
    action_group.add_argument(
        '--analyse-output',
        action='store_true',
        help=(
            'Alle Dateien im Quellordner (--source-dir) auf Kontoverbindungen '
            'analysieren. Extrahiert IBANs, BICs und Namen aus XML- und '
            'SWIFT-MT-Dateien. Durchsucht den Ordner rekursiv. '
            'Ergebnis: kontoverbindungen_JJJJMMTT_HHMMSS.csv.'
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
        help='Zielordner für die CSV-Dateien (Standard: aktuelles Verzeichnis)'
    )
    path_group.add_argument(
        '--source-dir',
        type=Path,
        default=None,
        metavar='PFAD',
        help=(
            'Quellordner für --analyse-output. '
            'Standard: output/ im selben Verzeichnis wie input/. '
            'Akzeptiert jeden beliebigen Pfad.'
        )
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
    if not args.remove_files and not args.analyse_files and not args.analyse_output:
        parser.print_help()
        print()
        print('Fehler: Bitte mindestens eine Aktion angeben '
              '(--remove-files, --analyse-files und/oder --analyse-output).')
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


    # ── Aktion 3: Kontoverbindungs-Analyse ──────────────────────────────
    if args.analyse_output:
        # Quellordner bestimmen
        if args.source_dir:
            source_dir = args.source_dir
        else:
            source_dir = input_dir.parent / 'output'

        if not source_dir.exists():
            logger.error(
                "Quellordner für --analyse-output nicht gefunden: %s\n"
                "Bitte --source-dir angeben.", source_dir
            )
            sys.exit(1)

        print()
        print('=' * 60)
        print('  KONTOVERBINDUNGEN ANALYSIEREN  (--analyse-output)')
        print(f'  Quelle: {source_dir}')
        print('=' * 60)

        account_rows = analyse_account_connections(source_dir)

        if not account_rows:
            logger.info("Keine Dateien zum Analysieren gefunden.")
        else:
            print()
            print('=' * 60)
            print('  CSV SCHREIBEN')
            print('=' * 60)
            csv_path = write_account_csv(account_rows, output_dir)

            total_ibans = sum(
                len(r['IBANs'].split(', ')) for r in account_rows if r['IBANs']
            )
            total_bics = sum(
                len(r['BICs'].split(', ')) for r in account_rows if r['BICs']
            )
            errors = sum(1 for r in account_rows if r['Fehler'])
            print()
            print('=' * 60)
            print(f"  Dateien analysiert:   {len(account_rows)}")
            print(f"  IBANs gefunden:       {total_ibans}")
            print(f"  BICs gefunden:        {total_bics}")
            print(f"  Fehler:               {errors}")
            print(f"  CSV: {csv_path}")
            print('=' * 60)
            print()


if __name__ == '__main__':
    main()
