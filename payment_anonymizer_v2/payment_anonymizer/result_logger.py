# -*- coding: utf-8 -*-
"""
result_logger.py
================
Schreibt Anonymisierungsergebnisse als CSV- oder JSON-Log.
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
    """Logger für Anonymisierungsergebnisse."""

    def __init__(self, log_path: str, log_format: str = 'csv'):
        self.log_path = Path(log_path)
        self.log_format = log_format
        self.results: List[AnonymizationResult] = []
        self.log_path.mkdir(parents=True, exist_ok=True)

    def add_result(self, result: AnonymizationResult):
        """Fügt ein Ergebnis zur internen Liste hinzu."""
        self.results.append(result)

    def write_log(self):
        """Schreibt alle gesammelten Ergebnisse in die Log-Datei."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.log_format == 'csv':
            self._write_csv(timestamp)
        else:
            self._write_json(timestamp)

    def _write_csv(self, timestamp: str):
        """Schreibt ein CSV-Log."""
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
        logger.info(f"Log geschrieben: {log_file}")

    def _write_json(self, timestamp: str):
        """Schreibt ein JSON-Log."""
        log_file = self.log_path / f"anonymization_log_{timestamp}.json"
        data = {
            'timestamp': timestamp,
            'total_files': len(self.results),
            'successful': sum(1 for r in self.results if r.status == 'SUCCESS'),
            'failed': sum(1 for r in self.results if r.status == 'ERROR'),
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
                    'processing_time_ms': r.processing_time_ms
                }
                for r in self.results
            ]
        }
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Log geschrieben: {log_file}")
