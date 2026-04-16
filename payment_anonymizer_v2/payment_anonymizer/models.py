# -*- coding: utf-8 -*-
"""
models.py
=========
Gemeinsame Datenklassen für den Payment Message Anonymizer.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class FieldMapping:
    """Mapping von Original- zu anonymisierten Werten."""
    original: str
    anonymized: str
    field_type: str                 # NAME, IBAN, BIC, ADDRESS, REMITTANCE, CONTACT


@dataclass
class AnonymizationResult:
    """Ergebnis einer Anonymisierung."""
    input_file: str
    output_file: str
    message_type: str
    status: str                     # SUCCESS, ERROR, SKIPPED
    fields_anonymized: int
    validation_status: str          # VALID, INVALID, SKIPPED
    validation_errors: List[str] = field(default_factory=list)
    error_message: str = ""
    processing_time_ms: float = 0.0
    # Eindeutige Nachrichten-ID zur Identifikation im Detail-Log
    # ISO 20022: GrpHdr/MsgId  |  SWIFT MT: :20: Transaction Reference
    message_id: str = ""
    # Alle Ersetzungen dieser Datei (befüllt nach erfolgreicher Anonymisierung)
    mappings: List[FieldMapping] = field(default_factory=list)
