# -*- coding: utf-8 -*-
"""
payment_anonymizer.py
=====================
Hauptprozessor: koordiniert Dateierkennung, Anonymisierung,
Validierung und Logging.
"""

import logging
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import List

from lxml import etree

from .config import Config
from .models import AnonymizationResult
from .result_logger import ResultLogger
from .anonymizers import ISO20022Anonymizer, SwiftMTAnonymizer

logger = logging.getLogger(__name__)


class PaymentAnonymizer:
    """Hauptklasse für die Anonymisierung von Zahlungsnachrichten."""

    def __init__(self, config_path: str):
        self.config = Config(config_path)
        self.iso_anonymizer = ISO20022Anonymizer(self.config)
        self.mt_anonymizer  = SwiftMTAnonymizer(self.config)
        self.logger = ResultLogger(
            self.config.log_path,
            self.config.data.get('logging', {}).get('format', 'csv')
        )

        log_level = self.config.data.get('logging', {}).get('level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Alle konfigurierten Verzeichnisse beim Start sicherstellen
        self._ensure_directories()

    # -------------------------------------------------------------------------
    # Initialisierung
    # -------------------------------------------------------------------------

    def _ensure_directories(self):
        """
        Erstellt alle konfigurierten Verzeichnisse falls sie nicht existieren.
        Wird einmalig beim Start aufgerufen.
        """
        dirs = {
            'output_path':        self.config.output_path,
            'log_path':           self.config.log_path,
            'not_supported_path': self.config.not_supported_path,
            'archive_path':       self.config.archive_path,
            'error_path':         self.config.error_path,
        }
        for name, path in dirs.items():
            p = Path(path)
            p.mkdir(parents=True, exist_ok=True)
            logger.debug("Verzeichnis sichergestellt: %s → %s", name, p)

    # -------------------------------------------------------------------------
    # Dateityp-Erkennung
    # -------------------------------------------------------------------------

    def _detect_file_type(self, content: str) -> str:
        """
        Erkennt den Dateityp (ISO20022 oder SWIFT MT).

        ISO 20022-Erkennung prüft drei Varianten:
        1. Standard:    <?xml ... oder <Document
        2. Namespace:   urn:iso:std:iso:20022 im Inhalt (SEPA Bulk etc.)
        3. Präfix-XML:  <BBkICF:... mit xmlns-Attribut
        """
        # Standard ISO 20022
        if '<?xml' in content[:100] or '<Document' in content[:500]:
            return 'ISO20022'

        # Praefix-Namespace – ISO 20022 irgendwo im Dokument
        # Erfasst SEPA Bulk (BBkICF), Standard und Swiss SIX-Nachrichten
        if re.search(r'urn:iso:std:iso:20022', content):
            return 'ISO20022'

        # Swiss SIX-Namespace (camt.019.001.07.ch.02 etc.)
        if re.search(r'six-interbank-clearing[.]com', content):
            return 'ISO20022'

        # XML mit beliebigem Namespace-Präfix auf Root-Element
        if re.search(r'<[A-Za-z][A-Za-z0-9]*:[A-Za-z]', content[:500]) \
                and 'xmlns' in content[:2000]:
            return 'ISO20022'

        # SWIFT MT
        if '{1:' in content and '{4:' in content:
            return 'SWIFT_MT'
        if re.search(r':\d{2}[A-Z]?:', content):
            return 'SWIFT_MT'

        return 'UNKNOWN'

    def _get_output_filename(self, input_path: Path) -> Path:
        """Generiert den Output-Dateinamen."""
        
        now         = datetime.now()
        datestamp   = now.strftime('%Y%m%d')
        timestamp   = now.strftime('%H%M%S')

        
        output_dir = Path(self.config.output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        new_name = (
            f"{self.config.prefix}"
            f"{datestamp}_{timestamp}_"
            f"{input_path.stem}"
            f"{self.config.suffix}"
            f"{input_path.suffix}"
        )
        return output_dir / new_name

    # -------------------------------------------------------------------------
    # Unterstützte Nachrichtentypen
    # -------------------------------------------------------------------------

    def _is_supported_type(self, message_type: str) -> bool:
        """
        Prüft ob der erkannte Nachrichtentyp unterstützt wird.

        Liest die unterstützten Typen aus config.json (supported_message_types).
        Der Vergleich erfolgt über den Präfix, damit Versionsvarianten
        (z.B. camt.052.001.08) korrekt erfasst werden.
        """
        if not message_type or message_type in ('UNKNOWN', 'MT_UNKNOWN'):
            return False
        for supported in self.config.supported_message_types:
            if message_type.startswith(supported):
                return True
        return False

    def _move_to_not_supported(self, input_path: Path) -> Path:
        """
        Kopiert eine nicht unterstützte Datei in den not_supported_path.
        Die Originaldatei im Input-Verzeichnis bleibt erhalten.
        """
        target_path = self._build_archive_target(input_path, Path(self.config.not_supported_path))
        
        shutil.move(str(input_path), str(target_path))
        logger.info(
            "Nicht unterstützter Nachrichtentyp – verschoben nach: %s ", 
            target_path
        )
        return target_path

    def _archive_input_file(self, input_path: Path) -> Path:
        """
        Verschiebt eine erfolgreich verarbeitete Datei ins Archiv-Verzeichnis.

        Existiert eine Datei mit gleichem Namen bereits im Archiv,
        wird eine laufende Nummer angehängt.
        Wird nur aufgerufen wenn archive_after_processing: true.
        """
        target_path = self._build_archive_target(input_path, Path(self.config.archive_path))
        input_path.rename(target_path)
        logger.info(
            "Archiviert: %s -> %s", 
            input_path, 
            target_path
        )

        return target_path

    def _move_to_error(self, input_path: Path,
                        error_message: str) -> Path:
        """
        Verschiebt eine Datei die einen Verarbeitungsfehler verursacht hat
        in das error-Verzeichnis.

        Struktur: error/<YYYYMMDD>/<HHMMSS_mmm>_<dateiname>
        Analog zu _build_archive_target() mit Timestamp und Datumsordner.
        Die Originaldatei wird aus dem Input-Verzeichnis entfernt.
        """
        target_path = self._build_archive_target(
            input_path, Path(self.config.error_path)
        )
        shutil.move(str(input_path), str(target_path))
        logger.info(
            "Fehlerhafte Datei verschoben: %s -> %s  (Fehler: %s)",
            input_path, target_path, error_message
        )
        return target_path

    def _build_archive_target(self, input_path: Path, base_dir: Path) -> Path:
        """
        Generiert Zielpfad für Archiv- und Not-Supported Dateien

        Beispiel:
        archive/20260504/140322_pacs008.xml
        not_supported/20260504/140322_pacs008.xml
        """

        now         = datetime.now()
        date_dir    = now.strftime('%Y%m%d')
        timestamp   = now.strftime('%H%M%S_%f')[:9]

        target_dir = base_dir / date_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        new_name    = f"{date_dir}_{timestamp}_{input_path.name}"
        target_path = target_dir / new_name

        if target_path.exists():
            counter = 1
            while target_path.exists():
                new_name = (
                    f"{timestamp}_{input_path.stem}" 
                    f"_{counter}{input_path.suffix}"
                )
                target_path = target_dir / new_name
                counter += 1

        return target_path    
                        

    # -------------------------------------------------------------------------
    # Einzeldatei verarbeiten
    # -------------------------------------------------------------------------

    def process_file(self, input_path: Path) -> AnonymizationResult:
        """Verarbeitet eine einzelne Datei."""
        start_time  = datetime.now()
        output_path = self._get_output_filename(input_path)

        result = AnonymizationResult(
            input_file=str(input_path),
            output_file=str(output_path),
            message_type='UNKNOWN',
            status='ERROR',
            fields_anonymized=0,
            validation_status='SKIPPED'
        )

        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                content = f.read()

            file_type = self._detect_file_type(content)

            if file_type == 'ISO20022':
                anonymizer = self.iso_anonymizer
                namespace  = anonymizer._detect_namespace(
                    etree.fromstring(content.encode('utf-8'))
                )
                result.message_type = anonymizer._detect_message_type(namespace)

            elif file_type == 'SWIFT_MT':
                anonymizer          = self.mt_anonymizer
                result.message_type = anonymizer._detect_message_type(content)

            else:
                result.status        = 'SKIPPED'
                result.error_message = 'Unbekannter Dateityp'
                return result

            # ── Unterstützten Nachrichtentyp prüfen ──────────────────────
            if not self._is_supported_type(result.message_type):
                moved_to             = self._move_to_not_supported(input_path)
                result.status        = 'SKIPPED'
                result.error_message = (
                    f"Nachrichtentyp '{result.message_type}' nicht unterstützt – "
                    f"kopiert nach: {moved_to}"
                )
                logger.warning(result.error_message)
                return result

            result.message_id = anonymizer.extract_message_id(content)
            anonymizer.reset()
            anonymized_content, fields_count = anonymizer.anonymize(content)
            result.fields_anonymized = fields_count
            result.mappings          = list(anonymizer.mappings.values())

            validate_after = self.config.data.get('message_types', {}).get(
                'iso20022' if file_type == 'ISO20022' else 'swift_mt', {}
            ).get('validate_after', False)

            if validate_after:
                is_valid, errors         = anonymizer.validate(anonymized_content)
                result.validation_status = 'VALID' if is_valid else 'INVALID'
                result.validation_errors = errors

            if not self.config.overwrite_existing:
                counter = 1
                while output_path.exists():
                    new_name = (
                        f"{self.config.prefix}"
                        f"{input_path.stem}"
                        f"{self.config.suffix}"
                        f"_{counter}"
                        f"{input_path.suffix}"
                    )
                    output_path = Path(self.config.output_path) / new_name
                    counter += 1
                result.output_file = str(output_path)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(anonymized_content)

            result.status = 'SUCCESS'
            logger.info(
                "Erfolgreich anonymisiert: %s -> %s (%d Felder)",
                input_path, output_path, fields_count
            )

            # ── Eingabedatei archivieren wenn konfiguriert ────────────────
            if self.config.archive_after_processing:
                archived_path = self._archive_input_file(input_path)
                result.archive_file = str(archived_path)                

        except Exception as e:
            result.status        = 'ERROR'
            result.error_message = str(e)
            logger.error("Fehler bei %s: %s", input_path, e)
            # Fehlerhafte Datei ins error-Verzeichnis verschieben
            try:
                error_path        = self._move_to_error(input_path, str(e))
                result.error_file = str(error_path)
            except Exception as move_err:
                logger.warning(
                    "Datei konnte nicht ins error-Verzeichnis verschoben "
                    "werden: %s – %s", input_path, move_err
                )

        finally:
            end_time                  = datetime.now()
            result.processing_time_ms = (
                (end_time - start_time).total_seconds() * 1000
            )

        return result

    # -------------------------------------------------------------------------
    # Mehrere Dateien / Wildcard verarbeiten
    # -------------------------------------------------------------------------

    def process_files(self, pattern) -> List[AnonymizationResult]:
        """
        Verarbeitet alle Dateien die einem Pfad-Muster entsprechen.

        Akzeptiert:
        - str:  Einzelnes Muster oder kommagetrennte Muster
        - list: Liste von Pfaden (Shell-Expansion via nargs='+')
        """
        results = []

        # Liste und String vereinheitlichen
        if isinstance(pattern, list):
            patterns = [p.strip() for p in pattern if p.strip()]
        else:
            patterns = [p.strip() for p in pattern.split(',') if p.strip()]

        for pat in patterns:
            matched = self._resolve_pattern(pat)

            if not matched:
                logger.warning("Keine Dateien gefunden für Muster: %s", pat)
                results.append(AnonymizationResult(
                    input_file=pat,
                    output_file='',
                    message_type='UNKNOWN',
                    status='SKIPPED',
                    fields_anonymized=0,
                    validation_status='SKIPPED',
                    error_message=f"Keine Dateien gefunden für Muster: {pat}"
                ))
                continue

            logger.info(
                "Muster '%s' – %d Datei(en) gefunden.", pat, len(matched)
            )
            for file_path in sorted(matched):
                result = self.process_file(file_path)
                results.append(result)
                self.logger.add_result(result)

        if results:
            self.logger.write_log()

        return results

    def _resolve_pattern(self, pattern: str) -> List[Path]:
        """
        Löst ein Pfad-Muster in eine Liste von Path-Objekten auf.
        Unterstützt glob-Wildcards (* ? **).
        """
        path = Path(pattern)

        # Direkter Dateipfad ohne Wildcard
        if '*' not in pattern and '?' not in pattern:
            if path.is_file():
                logger.debug("Direkte Datei: %s", pattern)
                return [path]
            logger.warning("Datei nicht gefunden: %s", pattern)
            return []

        # Rekursives Glob wenn ** enthalten
        if '**' in pattern:
            matched = list(Path('.').glob(pattern))
        else:
            parent  = path.parent if str(path.parent) != '.' else Path('.')
            matched = list(parent.glob(path.name))

        return [p for p in matched if p.is_file()]

    # -------------------------------------------------------------------------
    # Verzeichnis verarbeiten
    # -------------------------------------------------------------------------

    def process_directory(self) -> List[AnonymizationResult]:
        """Verarbeitet alle Dateien im Input-Verzeichnis."""
        input_dir = Path(self.config.input_path)

        if not input_dir.exists():
            logger.error("Input-Verzeichnis nicht gefunden: %s", input_dir)
            return []

        results = []
        for ext in self.config.file_extensions:
            for file_path in input_dir.glob(f"*{ext}"):
                result = self.process_file(file_path)
                results.append(result)
                self.logger.add_result(result)

        if results:
            self.logger.write_log()

        return results

    # -------------------------------------------------------------------------
    # Zusammenfassung
    # -------------------------------------------------------------------------

    def print_summary(self, results: List[AnonymizationResult]):
        """Gibt eine Zusammenfassung aus."""
        total         = len(results)
        successful    = sum(1 for r in results if r.status == 'SUCCESS')
        failed        = sum(1 for r in results if r.status == 'ERROR')
        not_supported = sum(
            1 for r in results
            if r.status == 'SKIPPED'
            and 'nicht unterstützt' in r.error_message
        )
        skipped      = sum(1 for r in results if r.status == 'SKIPPED') - not_supported
        total_fields = sum(r.fields_anonymized for r in results)

        print("\n" + "=" * 60)
        print("ANONYMISIERUNG ABGESCHLOSSEN")
        print("=" * 60)
        print(f"Gesamt Dateien:       {total}")
        print(f"Erfolgreich:          {successful}")
        print(f"Fehlgeschlagen:       {failed}")
        print(f"Übersprungen:         {skipped}")
        print(f"Nicht unterstützt:    {not_supported}")
        print(f"Felder anonymisiert:  {total_fields}")
        print("=" * 60)

        # Unterstützte Nachrichtentypen aus Config
        iso_types = self.config.data.get(
            'supported_message_types', {}
        ).get('iso20022', [])
        mt_types  = self.config.data.get(
            'supported_message_types', {}
        ).get('swift_mt', [])
        print(f"\nUnterstützte Nachrichtentypen:")
        print(f"  ISO 20022: {', '.join(iso_types) if iso_types else '–'}")
        print(f"  SWIFT MT:  {', '.join(mt_types)  if mt_types  else '–'}")

        # Verhalten nach Verarbeitung
        archive_enabled = self.config.archive_after_processing
        print(f"\nVerhalten nach Verarbeitung:")
        print(f"  - Archivierung (input → archive): "
              f"{'Ja (' + self.config.archive_path + ')' if archive_enabled else 'Nein'}")

        print("\nAktive Anonymisierungseinstellungen:")
        print(f"  - IBAN:              {'Ja' if self.config.anonymize_iban else 'Nein'}")
        print(f"  - BIC:               {'Ja' if self.config.anonymize_bic else 'Nein'}")
        print(f"  - Adressen:          {'Ja' if self.config.anonymize_address_field else 'Nein'}")
        print(f"  - Verwendungszweck:  {'Ja' if self.config.anonymize_remittance else 'Nein'}")
        print(f"  - Kontaktdaten:      {'Ja' if self.config.anonymize_contact else 'Nein'}")
        print(f"  - Namen:             {'Ja' if self.config.anonymize_name else 'Nein'}")
        print(f"  - MT :86:-Feld:      {'Ja' if self.config.anonymize_mt_field_86 else 'Nein'}")

        print("\nAktive Header-Modifikationen:")
        print(f"  - GrpHdr/SWIFT Header BIC: "
              f"{'Ja' if self.config.grphdr_bic_enabled else 'Nein'}", end="")
        if self.config.grphdr_bic_enabled:
            replacements = self.config.grphdr_bic_replacements
            if replacements:
                pairs = ', '.join(f"{r['from']} → {r['to']}" for r in replacements)
                print(f"  ({pairs})  [ISO20022 GrpHdr + SWIFT Block 1/2]", end="")
        print()

        print(f"  - SWIFT MX Service:  "
              f"{'Ja' if self.config.swift_mx_service_enabled else 'Nein'}", end="")
        if self.config.swift_mx_service_enabled:
            prod = self.config.swift_mx_service_prod
            test = self.config.swift_mx_service_test
            if prod and test:
                print(f"  ({prod} → {test})", end="")
            else:
                print("  !! prod_value oder test_value fehlt in config.json !!", end="")
        print()

        print(f"  - SEPA Service:      "
              f"{'Ja' if self.config.sepa_service_enabled else 'Nein'}", end="")
        if self.config.sepa_service_enabled:
            prod = self.config.sepa_service_prod
            test = self.config.sepa_service_test
            if prod and test:
                print(f"  ({prod} → {test})", end="")
            else:
                print("  !! prod_value oder test_value fehlt in config.json !!", end="")
        print()
        print("=" * 60 + "\n")
