# -*- coding: utf-8 -*-
"""
result_logger.py
================
Schreibt Anonymisierungsergebnisse in zwei Log-Dateien:

Zusammenfassung  (anonymization_log_TIMESTAMP.csv / .json)
    Eine Zeile pro verarbeiteter Datei mit Status, Feldanzahl, Dauer usw.

Detail-Log       (anonymization_detail_log_TIMESTAMP.csv)
    Eine Zeile pro Ersetzung mit Feldtyp, alt wert und neuer wert.
    Wird nur geschrieben wenn mindestens eine Ersetzung vorliegt.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from .models import AnonymizationResult

logger = logging.getLogger(__name__)


class ResultLogger:
    """Logger für Anonymisierungsergebnisse (Zusammenfassung + Detail)."""

    def __init__(self, log_path: str, log_format: str = 'csv'):
        self.log_path = Path(log_path)
        self.log_format = log_format
        self.results: List[AnonymizationResult] = []
        self.log_path.mkdir(parents=True, exist_ok=True)

    def add_result(self, result: AnonymizationResult):
        """Fügt ein Ergebnis zur internen Liste hinzu."""
        self.results.append(result)

    def write_log(self):
        """
        Schreibt Zusammenfassungs- und Detail-Log.

        Beide Dateien erhalten denselben Zeitstempel im Dateinamen,
        sodass sie eindeutig einander zugeordnet werden können.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.log_format == 'csv':
            self._write_summary_csv(timestamp)
        else:
            self._write_summary_json(timestamp)
        self._write_detail_csv(timestamp)

    # -------------------------------------------------------------------------
    # Zusammenfassungs-Log
    # -------------------------------------------------------------------------

    def _write_summary_csv(self, timestamp: str):
        """Schreibt eine Zeile pro Datei in die Zusammenfassungs-CSV."""
        log_file = self.log_path / f"anonymization_log_{timestamp}.csv"
        with open(log_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow([
                'Input File',
                'Archive File',        # Bug-Fix: archive_file ergänzt
                'Output File',
                'Message Type',
                'Status',
                'Fields Anonymized',
                'Validation Status',
                'Validation Errors',
                'Error Message',
                'Processing Time (ms)'
            ])
            for r in self.results:
                writer.writerow([
                    r.input_file,
                    r.archive_file,    # Bug-Fix: archive_file ausgeben
                    r.output_file,
                    r.message_type,
                    r.status,
                    r.fields_anonymized,
                    r.validation_status,
                    '; '.join(r.validation_errors),
                    r.error_message,
                    f"{r.processing_time_ms:.2f}"
                ])
        logger.info(f"Zusammenfassungs-Log geschrieben: {log_file}")

    def _write_summary_json(self, timestamp: str):
        """Schreibt ein JSON-Zusammenfassungs-Log."""
        log_file = self.log_path / f"anonymization_log_{timestamp}.json"
        data = {
            'timestamp': timestamp,
            'total_files': len(self.results),
            'successful': sum(1 for r in self.results if r.status == 'SUCCESS'),
            'failed':     sum(1 for r in self.results if r.status == 'ERROR'),
            'results': [
                {
                    'input_file':         r.input_file,
                    'archive_file':       r.archive_file,   # Bug-Fix
                    'output_file':        r.output_file,
                    'message_type':       r.message_type,
                    'status':             r.status,
                    'fields_anonymized':  r.fields_anonymized,
                    'validation_status':  r.validation_status,
                    'validation_errors':  r.validation_errors,
                    'error_message':      r.error_message,
                    'processing_time_ms': r.processing_time_ms,
                }
                for r in self.results
            ]
        }
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Zusammenfassungs-Log geschrieben: {log_file}")

    # -------------------------------------------------------------------------
    # Detail-Log  (eine Zeile pro Ersetzung)
    # -------------------------------------------------------------------------

    def _write_detail_csv(self, timestamp: str):
        """
        Schreibt eine Zeile pro Ersetzung in die Detail-CSV.

        Spalten:
            Input File  – Quelldatei der Nachricht
            Archive File – Archivpfad der Eingabedatei (leer wenn nicht archiviert)
            Output File – Ausgabedatei
            Message ID  – Eindeutige Nachrichten-ID
            Field Type  – Typ des ersetzten Feldes (NAME, IBAN, BIC, …)
            Alt Wert    – Originalwert vor der Anonymisierung
            Neuer Wert  – Ersatzwert nach der Anonymisierung
        """
        total_mappings = sum(len(r.mappings) for r in self.results)
        if total_mappings == 0:
            logger.debug("Keine Ersetzungen vorhanden – Detail-Log wird nicht geschrieben.")
            return

        log_file = self.log_path / f"anonymization_detail_log_{timestamp}.csv"
        with open(log_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow([
                'Input File',
                'Archive File',    # Bug-Fix: archive_file ergänzt
                'Output File',
                'Message ID',
                'Field Type',
                'Alt Wert',
                'Neuer Wert'
            ])
            for r in self.results:
                for mapping in r.mappings:
                    writer.writerow([
                        r.input_file,
                        r.archive_file,    # Bug-Fix: archive_file ausgeben
                        r.output_file,
                        r.message_id,
                        mapping.field_type,
                        mapping.original,
                        mapping.anonymized,
                    ])
        logger.info(
            f"Detail-Log geschrieben: {log_file}  ({total_mappings} Ersetzungen)"
        )
# -*- coding: utf-8 -*-
"""
result_logger.py
================
Schreibt Anonymisierungsergebnisse in zwei Log-Dateien:

Zusammenfassung  (anonymization_log_TIMESTAMP.csv / .json)
    Eine Zeile pro verarbeiteter Datei mit Status, Feldanzahl, Dauer usw.

Detail-Log       (anonymization_detail_log_TIMESTAMP.csv)
    Eine Zeile pro Ersetzung mit Feldtyp, alt wert und neuer wert.
    Wird nur geschrieben wenn mindestens eine Ersetzung vorliegt.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from .models import AnonymizationResult

logger = logging.getLogger(__name__)


class ResultLogger:
    """Logger für Anonymisierungsergebnisse (Zusammenfassung + Detail)."""

    def __init__(self, log_path: str, log_format: str = 'csv'):
        self.log_path = Path(log_path)
        self.log_format = log_format
        self.results: List[AnonymizationResult] = []
        self.log_path.mkdir(parents=True, exist_ok=True)

    def add_result(self, result: AnonymizationResult):
        """Fügt ein Ergebnis zur internen Liste hinzu."""
        self.results.append(result)

    def write_log(self):
        """
        Schreibt Zusammenfassungs- und Detail-Log.

        Beide Dateien erhalten denselben Zeitstempel im Dateinamen,
        sodass sie eindeutig einander zugeordnet werden können.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.log_format == 'csv':
            self._write_summary_csv(timestamp)
        else:
            self._write_summary_json(timestamp)
        self._write_detail_csv(timestamp)

    # -------------------------------------------------------------------------
    # Zusammenfassungs-Log
    # -------------------------------------------------------------------------

    def _write_summary_csv(self, timestamp: str):
        """Schreibt eine Zeile pro Datei in die Zusammenfassungs-CSV."""
        log_file = self.log_path / f"anonymization_log_{timestamp}.csv"
        with open(log_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow([
                'Input File', 'Output File', 'Message Type', 'Status',
                'Fields Anonymized', 'Validation Status', 'Validation Errors',
                'Error Message', 'Processing Time (ms)'
            ])
            for r in self.results:
                writer.writerow([
                    r.input_file,
                    r.output_file,
                    r.message_type,
                    r.status,
                    r.fields_anonymized,
                    r.validation_status,
                    '; '.join(r.validation_errors),
                    r.error_message,
                    f"{r.processing_time_ms:.2f}"
                ])
        logger.info(f"Zusammenfassungs-Log geschrieben: {log_file}")

    def _write_summary_json(self, timestamp: str):
        """Schreibt ein JSON-Zusammenfassungs-Log."""
        log_file = self.log_path / f"anonymization_log_{timestamp}.json"
        data = {
            'timestamp': timestamp,
            'total_files': len(self.results),
            'successful': sum(1 for r in self.results if r.status == 'SUCCESS'),
            'failed':     sum(1 for r in self.results if r.status == 'ERROR'),
            'results': [
                {
                    'input_file':         r.input_file,
                    'output_file':        r.output_file,
                    'message_type':       r.message_type,
                    'status':             r.status,
                    'fields_anonymized':  r.fields_anonymized,
                    'validation_status':  r.validation_status,
                    'validation_errors':  r.validation_errors,
                    'error_message':      r.error_message,
                    'processing_time_ms': r.processing_time_ms,
                }
                for r in self.results
            ]
        }
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Zusammenfassungs-Log geschrieben: {log_file}")

    # -------------------------------------------------------------------------
    # Detail-Log  (eine Zeile pro Ersetzung)
    # -------------------------------------------------------------------------

    def _write_detail_csv(self, timestamp: str):
        """
        Schreibt eine Zeile pro Ersetzung in die Detail-CSV.

        Spalten:
            Input File  – Quelldatei der Nachricht
            Message ID  – Eindeutige Nachrichten-ID
                          (ISO 20022: GrpHdr/MsgId | SWIFT MT: :20: Feld)
            Field Type  – Typ des ersetzten Feldes (NAME, IBAN, BIC, …)
            Alt Wert    – Originalwert vor der Anonymisierung
            Neuer Wert  – Ersatzwert nach der Anonymisierung

        Dateien ohne Ersetzungen (Status SKIPPED / ERROR ohne Mappings)
        erzeugen keinen Eintrag.
        """
        # Nur schreiben wenn überhaupt Ersetzungen vorhanden sind
        total_mappings = sum(len(r.mappings) for r in self.results)
        if total_mappings == 0:
            logger.debug("Keine Ersetzungen vorhanden – Detail-Log wird nicht geschrieben.")
            return

        log_file = self.log_path / f"anonymization_detail_log_{timestamp}.csv"
        with open(log_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow([
                'Input File', 'Output File', 'Message ID', 'Field Type', 'Alt Wert', 'Neuer Wert'
            ])
            for r in self.results:
                for mapping in r.mappings:
                    writer.writerow([
                        r.input_file,
                        r.output_file,
                        r.message_id,
                        mapping.field_type,
                        mapping.original,
                        mapping.anonymized,
                    ])
        logger.info(
            f"Detail-Log geschrieben: {log_file}  ({total_mappings} Ersetzungen)"
        )
