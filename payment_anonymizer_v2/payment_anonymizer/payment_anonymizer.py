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

    def process_file(self, input_path: Path) -> AnonymizationResult:
        """Verarbeitet eine einzelne Datei."""
        start_time = datetime.now()
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
                namespace = anonymizer._detect_namespace(
                    etree.fromstring(content.encode('utf-8'))
                )
                result.message_type = anonymizer._detect_message_type(namespace)

            elif file_type == 'SWIFT_MT':
                anonymizer = self.mt_anonymizer
                result.message_type = anonymizer._detect_message_type(content)

            else:
                result.status = 'SKIPPED'
                result.error_message = 'Unbekannter Dateityp'
                return result

            anonymizer.reset()
            anonymized_content, fields_count = anonymizer.anonymize(content)
            result.fields_anonymized = fields_count

            validate_after = self.config.data.get('message_types', {}).get(
                'iso20022' if file_type == 'ISO20022' else 'swift_mt', {}
            ).get('validate_after', False)

            if validate_after:
                is_valid, errors = anonymizer.validate(anonymized_content)
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
                f"Erfolgreich anonymisiert: {input_path} -> "
                f"{output_path} ({fields_count} Felder)"
            )

        except Exception as e:
            result.status = 'ERROR'
            result.error_message = str(e)
            logger.error(f"Fehler bei {input_path}: {e}")

        finally:
            end_time = datetime.now()
            result.processing_time_ms = (end_time - start_time).total_seconds() * 1000

        return result

    def process_directory(self) -> List[AnonymizationResult]:
        """Verarbeitet alle Dateien im Input-Verzeichnis."""
        input_dir = Path(self.config.input_path)

        if not input_dir.exists():
            logger.error(f"Input-Verzeichnis nicht gefunden: {input_dir}")
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

    def print_summary(self, results: List[AnonymizationResult]):
        """Gibt eine Zusammenfassung aus."""
        total        = len(results)
        successful   = sum(1 for r in results if r.status == 'SUCCESS')
        failed       = sum(1 for r in results if r.status == 'ERROR')
        skipped      = sum(1 for r in results if r.status == 'SKIPPED')
        total_fields = sum(r.fields_anonymized for r in results)

        print("\n" + "=" * 60)
        print("ANONYMISIERUNG ABGESCHLOSSEN")
        print("=" * 60)
        print(f"Gesamt Dateien:       {total}")
        print(f"Erfolgreich:          {successful}")
        print(f"Fehlgeschlagen:       {failed}")
        print(f"Übersprungen:         {skipped}")
        print(f"Felder anonymisiert:  {total_fields}")
        print("=" * 60)
        print("\nAktive Anonymisierungseinstellungen:")
        print(f"  - IBAN:              {'Ja' if self.config.anonymize_iban else 'Nein'}")
        print(f"  - BIC:               {'Ja' if self.config.anonymize_bic else 'Nein'}")
        print(f"  - Adressen:          {'Ja' if self.config.anonymize_address_field else 'Nein'}")
        print(f"  - Verwendungszweck:  {'Ja' if self.config.anonymize_remittance else 'Nein'}")
        print(f"  - Kontaktdaten:      {'Ja' if self.config.anonymize_contact else 'Nein'}")
        print(f"  - Namen:             {'Ja' if self.config.anonymize_name else 'Nein'}")
        print("=" * 60 + "\n")
