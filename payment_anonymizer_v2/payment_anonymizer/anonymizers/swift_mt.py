# -*- coding: utf-8 -*-
"""
anonymizers/swift_mt.py
=======================
Anonymisierer für SWIFT MT-Nachrichten (MT900, MT910).
"""

import logging
import re
from typing import List, Tuple

from ..config import Config
from .base import BaseAnonymizer

logger = logging.getLogger(__name__)


class SwiftMTAnonymizer(BaseAnonymizer):
    """Anonymisierer für SWIFT MT-Nachrichten (MT900, MT910)."""

    FIELDS_TO_ANONYMIZE = {
        ':50:':  'ordering_customer',
        ':50A:': 'ordering_customer',
        ':50F:': 'ordering_customer',
        ':50K:': 'ordering_customer',
        ':52A:': 'ordering_institution',
        ':52D:': 'ordering_institution',
        ':53A:': 'senders_correspondent',
        ':53B:': 'senders_correspondent',
        ':53D:': 'senders_correspondent',
        ':54A:': 'receivers_correspondent',
        ':54B:': 'receivers_correspondent',
        ':54D:': 'receivers_correspondent',
        ':56A:': 'intermediary',
        ':56D:': 'intermediary',
        ':57A:': 'account_institution',
        ':57B:': 'account_institution',
        ':57D:': 'account_institution',
        ':59:':  'beneficiary',
        ':59A:': 'beneficiary',
        ':59F:': 'beneficiary',
        ':70:':  'remittance',
        ':72:':  'sender_to_receiver',
        ':86:':  'information',
    }

    BIC_PATTERN  = re.compile(r'\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b')
    IBAN_PATTERN = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b')

    def __init__(self, config: Config):
        super().__init__(config)

    # -------------------------------------------------------------------------
    # Nachrichten-Erkennung
    # -------------------------------------------------------------------------

    def _detect_message_type(self, content: str) -> str:
        """Erkennt den MT-Nachrichtentyp."""
        match = re.search(r'\{2:[OI](\d{3})', content)
        if match:
            return f"MT{match.group(1)}"
        match = re.search(r'MT\s*(\d{3})', content, re.IGNORECASE)
        if match:
            return f"MT{match.group(1)}"
        return "MT_UNKNOWN"

    # -------------------------------------------------------------------------
    # Anonymisierung
    # -------------------------------------------------------------------------

    def _anonymize_party_field(self, content: str, field_type: str) -> str:
        """
        Anonymisiert ein Party-Feld (Name + Adresszeilen) zeilenweise.
        Delegiert die Feld-spezifische Logik an die jeweiligen Feld-Anonymisierer.
        """
        lines = content.split('\n')
        anonymized_lines = []

        for i, line in enumerate(lines):

            # BIC in der Zeile ersetzen
            if self.bic_anonymizer.is_enabled and self.BIC_PATTERN.search(line):
                line = self.BIC_PATTERN.sub(
                    lambda m: self.bic_anonymizer.anonymize(m.group(0)),
                    line
                )
                self.fields_anonymized += 1

            # IBAN in der Zeile ersetzen
            if self.iban_anonymizer.is_enabled and self.IBAN_PATTERN.search(line):
                line = self.IBAN_PATTERN.sub(
                    lambda m: self.iban_anonymizer.anonymize(m.group(0)),
                    line
                )
                self.fields_anonymized += 1

            # Erste Zeile: Name (sofern kein BIC / keine IBAN)
            if (
                self.name_anonymizer.is_enabled
                and i == 0
                and not self.BIC_PATTERN.match(line)
                and not self.IBAN_PATTERN.match(line)
            ):
                if line.strip() and not line.startswith('/'):
                    line = self.name_anonymizer.anonymize(line.strip())
                    self.fields_anonymized += 1

            # Folgezeilen: Adresse (sofern kein BIC)
            if (
                self.address_anonymizer.is_enabled
                and i > 0
                and line.strip()
                and not self.BIC_PATTERN.match(line)
            ):
                line = self.address_anonymizer.anonymize_swift_line(line, i)
                self.fields_anonymized += 1

            anonymized_lines.append(line)

        return '\n'.join(anonymized_lines)

    def _anonymize_remittance_field(self, content: str) -> str:
        """Anonymisiert ein Verwendungszweck-Feld."""
        if not self.remittance_anonymizer.is_enabled:
            return content
        self.fields_anonymized += 1
        return self.remittance_anonymizer.anonymize(content)

    def anonymize(self, content: str) -> Tuple[str, int]:
        """Anonymisiert eine SWIFT MT-Nachricht."""
        self.fields_anonymized = 0
        result = content

        for tag, field_type in self.FIELDS_TO_ANONYMIZE.items():
            pattern = re.compile(
                rf'({re.escape(tag)})(.*?)(?=\n:[0-9]{{2}}[A-Z]?:|$|\n-\}})',
                re.DOTALL
            )

            def replace_field(match, ft=field_type):
                tag_part     = match.group(1)
                content_part = match.group(2)
                if ft == 'remittance':
                    anonymized = self._anonymize_remittance_field(content_part)
                else:
                    anonymized = self._anonymize_party_field(content_part, ft)
                return tag_part + anonymized

            result = pattern.sub(replace_field, result)

        # Kontonummern in :25: Feldern
        if self.iban_anonymizer.is_enabled:
            account_pattern = re.compile(r'(:25:)([A-Z]{2}\d{2}[A-Z0-9]{4,30})')
            result = account_pattern.sub(
                lambda m: m.group(1) + self.iban_anonymizer.anonymize(m.group(2)),
                result
            )

        return result, self.fields_anonymized

    # -------------------------------------------------------------------------
    # Validierung
    # -------------------------------------------------------------------------

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """Validiert eine SWIFT MT Nachricht (Basis-Validierung)."""
        errors = []

        if not re.search(r'\{1:', content):
            errors.append("Kein SWIFT Basic Header Block gefunden")
        if not re.search(r'\{2:', content):
            errors.append("Kein SWIFT Application Header Block gefunden")
        if not re.search(r'\{4:', content):
            errors.append("Kein SWIFT Text Block gefunden")

        field_pattern = re.compile(r':(\d{2}[A-Z]?):')
        if not field_pattern.findall(content):
            errors.append("Keine gültigen SWIFT-Feldtags gefunden")

        return len(errors) == 0, errors

    def extract_message_id(self, content: str) -> str:
        """
        Extrahiert die Transaction Reference Number aus dem :20:-Feld.

        Das :20:-Feld ist der eindeutige technische Bezeichner einer SWIFT-
        MT-Nachricht (Transaction Reference Number) und wird nicht anonymisiert.
        """
        match = re.search(r':20:([^\r\n]+)', content)
        if match:
            return match.group(1).strip()
        return ""
