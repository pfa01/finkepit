# -*- coding: utf-8 -*-
"""
payment_anonymizer.py
=====================
Hauptprozessor: koordiniert Dateierkennung, Anonymisierung,
Validierung und Logging.
"""

import logging
import re
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
        }
        for name, path in dirs.items():
            p = Path(path)
            p.mkdir(parents=True, exist_ok=True)
            logger.debug("Verzeichnis sichergestellt: %s → %s", name, p)

    # -------------------------------------------------------------------------
    # Dateityp-Erkennung
    # -------------------------------------------------------------------------

    def _detect_file_type(self, content: str) -> str:
        """Erkennt den Dateityp (ISO20022 oder SWIFT MT)."""
        if '<?xml' in content[:100] or '<Document' in content[:500]:
            return 'ISO20022'
        if '{1:' in content and '{4:' in content:
            return 'SWIFT_MT'
        if re.search(r':\d{2}[A-Z]?:', content):
            return 'SWIFT_MT'
        return 'UNKNOWN'

    def _get_output_filename(self, input_path: Path) -> Path:
        """Generiert den Output-Dateinamen."""
        output_dir = Path(self.config.output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        new_name = (
            f"{self.config.prefix}"
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
        Verschiebt eine nicht unterstützte Datei in den not_supported_path.

        Existiert eine Datei mit gleichem Namen bereits im Zielordner,
        wird eine laufende Nummer angehängt.
        """
        target_dir = Path(self.config.not_supported_path)
        target_dir.mkdir(parents=True, exist_ok=True)

        target_path = target_dir / input_path.name
        if target_path.exists():
            counter = 1
            while target_path.exists():
                target_path = target_dir / (
                    f"{input_path.stem}_{counter}{input_path.suffix}"
                )
                counter += 1

        input_path.rename(target_path)
        logger.info(
            "Nicht unterstützter Nachrichtentyp – verschoben nach: %s",
            target_path
        )
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
                    f"verschoben nach: {moved_to}"
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

            if not self.config.data.get('behavior', {}).get('overwrite_existing', False):
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

        except Exception as e:
            result.status        = 'ERROR'
            result.error_message = str(e)
            logger.error("Fehler bei %s: %s", input_path, e)

        finally:
            end_time                   = datetime.now()
            result.processing_time_ms  = (
                (end_time - start_time).total_seconds() * 1000
            )

        return result

    # -------------------------------------------------------------------------
    # Mehrere Dateien / Wildcard verarbeiten
    # -------------------------------------------------------------------------

    def process_files(self, pattern: str) -> List[AnonymizationResult]:
        """
        Verarbeitet alle Dateien die einem Pfad-Muster entsprechen.

        Unterstützt:
        - Einzelne Datei:     'input/pacs.008.xml'
        - Wildcard Dateiname: 'input/pacs.*.xml'
        - Wildcard Verz.:     'input/*/pacs.008.xml'
        - Mehrere Muster:     'input/pacs.008.xml,input/pacs.009.xml'
                              (kommagetrennt)
        - Rekursiv:           'input/**/*.xml'

        Gibt alle Ergebnisse zurück und schreibt das Log.
        """
        results  = []
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
        Ist pattern ein direkter Dateipfad ohne Wildcards und die Datei
        existiert, wird sie direkt zurückgegeben.
        """
        path = Path(pattern)

        # Direkter Dateipfad ohne Wildcard
        if '*' not in pattern and '?' not in pattern:
            if path.is_file():
                return [path]
            logger.warning("Datei nicht gefunden: %s", pattern)
            return []

        # Rekursives Glob wenn ** enthalten
        if '**' in pattern:
            matched = list(Path('.').glob(pattern))
        else:
            parent  = path.parent if str(path.parent) != '.' else Path('.')
            matched = list(parent.glob(path.name))

        # Nur Dateien, keine Verzeichnisse
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

        print("\nAktive Anonymisierungseinstellungen:")
        print(f"  - IBAN:              {'Ja' if self.config.anonymize_iban else 'Nein'}")
        print(f"  - BIC:               {'Ja' if self.config.anonymize_bic else 'Nein'}")
        print(f"  - Adressen:          {'Ja' if self.config.anonymize_address_field else 'Nein'}")
        print(f"  - Verwendungszweck:  {'Ja' if self.config.anonymize_remittance else 'Nein'}")
        print(f"  - Kontaktdaten:      {'Ja' if self.config.anonymize_contact else 'Nein'}")
        print(f"  - Namen:             {'Ja' if self.config.anonymize_name else 'Nein'}")
        print(f"  - MT :86:-Feld:      {'Ja' if self.config.anonymize_mt_field_86 else 'Nein'}")

        print("\nAktive Header-Modifikationen:")
        print(f"  - GrpHdr BIC:        {'Ja' if self.config.grphdr_bic_enabled else 'Nein'}", end="")
        if self.config.grphdr_bic_enabled:
            replacements = self.config.grphdr_bic_replacements
            if replacements:
                pairs = ', '.join(f"{r['from']} → {r['to']}" for r in replacements)
                print(f"  ({pairs})", end="")
        print()

        print(f"  - SWIFT MX Service:  {'Ja' if self.config.swift_mx_service_enabled else 'Nein'}", end="")
        if self.config.swift_mx_service_enabled:
            prod = self.config.swift_mx_service_prod
            test = self.config.swift_mx_service_test
            if prod and test:
                print(f"  ({prod} → {test})", end="")
            else:
                print("  !! prod_value oder test_value fehlt in config.json !!", end="")
        print()

        print(f"  - SEPA Service:      {'Ja' if self.config.sepa_service_enabled else 'Nein'}", end="")
        if self.config.sepa_service_enabled:
            prod = self.config.sepa_service_prod
            test = self.config.sepa_service_test
            if prod and test:
                print(f"  ({prod} → {test})", end="")
            else:
                print("  !! prod_value oder test_value fehlt in config.json !!", end="")
        print()
        print("=" * 60 + "\n")
