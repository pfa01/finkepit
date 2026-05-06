# -*- coding: utf-8 -*-
"""
anonymizers/swift_mt.py
=======================
Anonymisierer fuer SWIFT MT-Nachrichten (MT900/910/940/941/942/950).
Unterstuetzt Einzel- und Multi-Message-Dateien (ISO 15022).
"""

import logging
import re
from typing import List, Tuple

from ..config import Config
from .base import BaseAnonymizer

logger = logging.getLogger(__name__)


class SwiftMTAnonymizer(BaseAnonymizer):
    """Anonymisierer fuer SWIFT MT-Nachrichten."""

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
        ':61:':  'statement_line',
    }

    STATEMENT_86_SUBFIELDS = {
        'ABWA': 'name',
        'ABWE': 'name',
        'NAME': 'name',
        'ENAM': 'name',
        'IBAN': 'iban',
        'BIC':  'bic',
        'SVWZ': 'remittance',
        'KREF': 'remittance',
        'EREF': 'remittance',
    }

    _STATEMENT_REQUIRED_FIELDS = {
        'MT940': [':20:', ':25:', ':28C:', ':62F:'],
        'MT941': [':20:', ':25:', ':34F:'],
        'MT942': [':20:', ':25:', ':34F:'],
        'MT950': [':20:', ':25:', ':28C:', ':62F:'],
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
    # Multi-Message Splitting
    # -------------------------------------------------------------------------

    def _split_messages(self, content: str) -> list:
        """
        Teilt eine Multi-Message-Datei in einzelne MT-Nachrichten auf.
        Mechanismus 1: ISO 15022-Trennzeichen (konfigurierbar, Standard '$')
        Mechanismus 2: {1:-Block als Nachrichtenbeginn (SWIFT-Standard)
        """
        separator = self.config.swift_mt_message_separator

        sep_pattern = re.compile(
            rf'^\s*{re.escape(separator)}\s*$',
            re.MULTILINE
        )
        if sep_pattern.search(content):
            raw_parts = sep_pattern.split(content)
            messages  = [p.strip() for p in raw_parts if p.strip()]
            if len(messages) > 1:
                logger.debug(
                    "Multi-Message erkannt via ISO-15022-Trennzeichen '%s': "
                    "%d Nachrichten", separator, len(messages)
                )
                return messages

        raw_parts = re.split(r'(?=\{1:)', content)
        messages  = [p.strip() for p in raw_parts if p.strip()]

        if not messages:
            return [content]

        valid = [m for m in messages if m.startswith('{1:')]
        if len(valid) > 1:
            logger.debug(
                "Multi-Message erkannt via {1:-Block: %d Nachrichten",
                len(valid)
            )
        return valid if valid else [content]

    # -------------------------------------------------------------------------
    # Anonymisierung – Party-Felder
    # -------------------------------------------------------------------------

    def _anonymize_party_field(self, content: str, field_type: str) -> str:
        """
        Anonymisiert ein Party-Feld zeilenweise.
        Alle Felder eines Party-Felds verwenden dieselbe Entitaet.
        """
        lines = content.split('\n')
        anonymized_lines = []

        original_name = None
        if lines:
            first_line = lines[0].strip()
            if (first_line
                    and not first_line.startswith('/')
                    and not self.BIC_PATTERN.match(first_line)
                    and not self.IBAN_PATTERN.match(first_line)):
                original_name = first_line

        is_company = (
            original_name is not None
            and self.name_anonymizer._is_company(original_name)
        )
        if original_name:
            entity = self.config.get_or_assign_entity(original_name, is_company)
        else:
            entity = self.config.get_next_entity()

        for i, line in enumerate(lines):
            if self.bic_anonymizer.is_enabled and self.BIC_PATTERN.search(line):
                line = self.BIC_PATTERN.sub(
                    lambda m, e=entity: self.bic_anonymizer.anonymize_with_entity(
                        m.group(0), e
                    ),
                    line
                )
                self.fields_anonymized += 1

            if self.iban_anonymizer.is_enabled and self.IBAN_PATTERN.search(line):
                line = self.IBAN_PATTERN.sub(
                    lambda m, e=entity: self.iban_anonymizer.anonymize_with_entity(
                        m.group(0), e
                    ),
                    line
                )
                self.fields_anonymized += 1

            if (
                self.name_anonymizer.is_enabled
                and i == 0
                and not self.BIC_PATTERN.match(line)
                and not self.IBAN_PATTERN.match(line)
            ):
                if line.strip() and not line.startswith('/'):
                    line = self.name_anonymizer.anonymize_with_entity(
                        line.strip(), entity, is_company
                    )
                    self.fields_anonymized += 1

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

    # -------------------------------------------------------------------------
    # Anonymisierung – MT940/941/942/950 Statement-Felder
    # -------------------------------------------------------------------------

    def _anonymize_statement_line(self, content: str) -> str:
        """
        Anonymisiert eine :61:-Buchungszeile.
        Datum und Betrag bleiben unveraendert, Referenz wird ersetzt.
        """
        if not content or not content.strip():
            return content

        pattern = re.compile(
            r'^(\d{6}(?:\d{4})?[CD]\d+,\d{2}[A-Z]{4})'
            r'(.+)$',
            re.DOTALL
        )
        match = pattern.match(content.strip())
        if match:
            prefix    = match.group(1)
            reference = match.group(2)
            if self.remittance_anonymizer.is_enabled:
                reference = self.remittance_anonymizer.anonymize(
                    reference.strip()
                )
                self.fields_anonymized += 1
            return prefix + reference
        return content

    def _anonymize_multiline_remittance(self, value: str,
                                         entity: dict,
                                         start_line_nr: int = 1) -> str:
        """
        Anonymisiert einen moeglicherweise mehrzeiligen Verwendungszweck-Wert.
        """
        if not self.remittance_anonymizer.is_enabled or not value.strip():
            return value

        default    = self.config.get_default()
        remittance = entity.get('remittance', default.get('remittance', ''))
        iban       = entity.get('iban',       default.get('iban', ''))

        lines   = value.split('\n')
        result  = []
        line_nr = start_line_nr

        for line in lines:
            stripped = line.strip()
            if not stripped:
                result.append(line)
                continue

            replacement = f"{remittance} {iban} {line_nr}"

            if (stripped.startswith('/')
                    and not re.match(r'^/[A-Z]{2,4}/', stripped)):
                result.append('/' + replacement)
            else:
                result.append(replacement)

            self.fields_anonymized += 1
            line_nr += 1

        return '\n'.join(result)

    def _anonymize_86_subfields(self, content: str) -> str:
        """
        Anonymisiert strukturierte Subfelder in :86: bei MT940/941/942/950.
        """
        if not content or not content.strip():
            return content

        block_entity = None
        name_match   = re.search(r'/(?:ABWA|ABWE|NAME|ENAM)/([^/\n]+)', content)
        if name_match:
            candidate = name_match.group(1).strip()
            if candidate:
                is_co        = self.name_anonymizer._is_company(candidate)
                block_entity = self.config.get_or_assign_entity(candidate, is_co)
        if block_entity is None:
            block_entity = self.config.get_next_entity()

        remittance_line_nr = [1]

        if not re.search(r'/[A-Z]{2,4}/', content):
            return self._anonymize_multiline_remittance(
                content, block_entity, start_line_nr=1
            )

        parts  = re.split(r'(/[A-Z]{2,4}/)', content)
        result = []
        i      = 0

        if parts and not re.match(r'^/[A-Z]{2,4}/$', parts[0]):
            result.append(parts[0])
            i = 1

        while i < len(parts):
            key_tag      = parts[i]
            value        = parts[i + 1] if i + 1 < len(parts) else ''
            key          = key_tag.strip('/')
            field_action = self.STATEMENT_86_SUBFIELDS.get(key)

            if field_action == 'name' and self.name_anonymizer.is_enabled:
                is_company = self.name_anonymizer._is_company(value.strip())
                entity     = self.config.get_or_assign_entity(
                    value.strip(), is_company
                ) if value.strip() else block_entity
                value = self.name_anonymizer.anonymize_with_entity(
                    value.strip(), entity, is_company
                )
                self.fields_anonymized += 1

            elif field_action == 'iban' and self.iban_anonymizer.is_enabled:
                if self.IBAN_PATTERN.search(value):
                    value = self.IBAN_PATTERN.sub(
                        lambda m, e=block_entity: self.iban_anonymizer.anonymize_with_entity(
                            m.group(0), e
                        ),
                        value
                    )
                    self.fields_anonymized += 1

            elif field_action == 'bic' and self.bic_anonymizer.is_enabled:
                if self.BIC_PATTERN.search(value):
                    value = self.BIC_PATTERN.sub(
                        lambda m, e=block_entity: self.bic_anonymizer.anonymize_with_entity(
                            m.group(0), e
                        ),
                        value
                    )
                    self.fields_anonymized += 1

            elif field_action == 'remittance':
                if self.remittance_anonymizer.is_enabled and value.strip():
                    value = self._anonymize_multiline_remittance(
                        value, block_entity,
                        start_line_nr=remittance_line_nr[0]
                    )
                    remittance_line_nr[0] += value.count('\n') + 1

            result.append(key_tag)
            result.append(value)
            i += 2

        return ''.join(result)

    # -------------------------------------------------------------------------
    # Anonymisierung – Haupt-Methoden
    # -------------------------------------------------------------------------

    def anonymize(self, content: str) -> Tuple[str, int]:
        """
        Anonymisiert eine oder mehrere SWIFT MT-Nachrichten.
        Bei Multi-Message wird jede Nachricht einzeln verarbeitet.
        """
        self.fields_anonymized = 0

        messages = self._split_messages(content)

        if len(messages) <= 1:
            return self._anonymize_single(content)

        anonymized_parts = []
        total_fields     = 0
        separator        = self.config.swift_mt_message_separator

        for i, message in enumerate(messages, 1):
            logger.debug(
                "Multi-Message: verarbeite Nachricht %d von %d",
                i, len(messages)
            )
            self.mappings.clear()
            anonymized_msg, fields = self._anonymize_single(message)
            anonymized_parts.append(anonymized_msg)
            total_fields += fields

        self.fields_anonymized = total_fields
        return f'\n{separator}\n'.join(anonymized_parts), total_fields

    def _anonymize_single(self, content: str) -> Tuple[str, int]:
        """Anonymisiert eine einzelne SWIFT MT-Nachricht."""
        self.fields_anonymized = 0
        result                 = content

        msg_type     = self._detect_message_type(content)
        is_statement = msg_type in ('MT940', 'MT941', 'MT942', 'MT950')

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
                elif ft == 'statement_line':
                    anonymized = self._anonymize_statement_line(content_part)
                elif ft == 'information' and is_statement:
                    if self.config.anonymize_mt_field_86:
                        anonymized = self._anonymize_86_subfields(content_part)
                    else:
                        anonymized = content_part
                else:
                    anonymized = self._anonymize_party_field(content_part, ft)
                if anonymized is None:
                    logger.warning(
                        "[REPLACE_FIELD] None-Rueckgabe fuer ft=%s – "
                        "Originalinhalt beibehalten.", ft
                    )
                    anonymized = content_part
                return tag_part + anonymized

            result = pattern.sub(replace_field, result)

        # :25: Kontonummern
        if self.iban_anonymizer.is_enabled:
            account_pattern = re.compile(r'(:25:)([A-Z]{2}\d{2}[A-Z0-9]{4,30})')
            result = account_pattern.sub(
                lambda m: m.group(1) + self.iban_anonymizer.anonymize(m.group(2)),
                result
            )

        # BICs in Header-Blöcken 1 und 2
        result = self._replace_header_bics(result)

        # Globale BIC-Ersetzung im Nachrichteninhalt (Felder)
        result = self._replace_all_bics(result)

        count = self.fields_anonymized
        return result, count

    # -------------------------------------------------------------------------
    # Header-BIC Ersetzung
    # -------------------------------------------------------------------------

    def _replace_header_bics(self, content: str) -> str:
        """
        Ersetzt BICs in SWIFT-Header-Blöcken {1:} und {2:}.

        Verwendet einen inhaltsbasierten Ansatz: der gesamte Block-Inhalt
        wird nach konfigurierten BIC-Praefixen durchsucht und ersetzt.
        Damit werden alle Block-2-Formate korrekt verarbeitet:

        Block 1:        {1:F01GENODESTAXXX...}
        Block 2 Input:  {2:I103GENOLULLXXXN}
        Block 2 Output: {2:O9500433260416GENOLULLXXX83587640042604160434N}
                                       ^^^^^^^^^^^ BIC an variabler Position

        Vorteil gegenueber positionsbasiertem Ansatz: der Regex muss die
        genaue Struktur (Input/Output, Zeit+Datum-Offset) nicht kennen.
        Das BIC wird als 8-Zeichen-Praefix direkt im Block-Inhalt gefunden.
        """
        if not self.config.grphdr_bic_enabled:
            return content

        replacements = self.config.grphdr_bic_replacements
        if not replacements:
            return content

        def replace_bics_in_block(block_content: str) -> str:
            """
            Ersetzt alle konfigurierten BICs im Block-Inhalt.

            Strategie: NUR den 8-Zeichen-BIC-Praefix ersetzen.
            Der Branch-Code (XXX, AXXX etc.) bleibt unveraendert.

            Begruendung: Im Block 2 Output folgt nach dem Branch-Code eine
            Ziffer (Sequenznummer), z.B. GENOLULLXXX8... Die Ziffer ist
            [A-Z0-9], daher scheitert jeder Lookahead (?![A-Z0-9]).
            Durch Ersetzen nur des 8-Zeichen-Praefixes entfaellt das Problem.

            Beispiele:
            GENOLULLXXX  -> GENOLUL0XXX   (BIC11, Block2-Output)
            GENOLULLAXXX -> GENOLUL0AXXX  (LT-Adresse, Block1)
            GENOLULLXXXN -> GENOLUL0XXXN  (BIC11 + Prio, Block2-Input)
            """
            for mapping in replacements:
                from_bic = mapping.get('from', '').strip().upper()
                to_bic   = mapping.get('to',   '').strip().upper()
                if not from_bic or not to_bic:
                    continue
                pat = re.compile(rf'{re.escape(from_bic[:8])}', re.IGNORECASE)
                def repl(m, to=to_bic[:8]):
                    logger.debug(
                        "[SWIFT_HEADER_BIC] alt=%s   neu=%s",
                        m.group(0), to
                    )
                    return to
                block_content = pat.sub(repl, block_content)
            return block_content

        # Block 1: {1:...}
        content = re.sub(
            r'(\{1:)([^}]*)(\})',
            lambda m: m.group(1) + replace_bics_in_block(m.group(2)) + m.group(3),
            content
        )

        # Block 2: {2:...} – Input und Output, alle Formate
        content = re.sub(
            r'(\{2:)([^}]*)(\})',
            lambda m: m.group(1) + replace_bics_in_block(m.group(2)) + m.group(3),
            content,
            flags=re.DOTALL
        )

        return content

    def _replace_all_bics(self, content: str) -> str:
        """
        Ersetzt alle Vorkommen der konfigurierten BICs im Nachrichteninhalt.

        Arbeitet auf dem rohen String – erfasst alle SWIFT-MT-Felder
        unabhaengig von ihrer Struktur (:52A:, :57A:, :86: etc.)

        Hinweis: In Header-Blöcken stehen vor dem BIC Ziffern (z.B. F01, 950),
        daher wuerde der Lookbehind (?<![A-Z0-9]) dort fehlschlagen.
        Header-Blöcke werden deshalb von _replace_header_bics() verarbeitet.
        """
        if not content or not isinstance(content, str):
            return content or ''
        if not self.config.grphdr_bic_enabled:
            return content

        replacements = self.config.grphdr_bic_replacements
        if not replacements:
            return content

        for mapping in replacements:
            from_bic = mapping.get('from', '').strip().upper()
            to_bic   = mapping.get('to',   '').strip().upper()
            if not from_bic or not to_bic:
                continue

            pattern = re.compile(
                rf'(?<![A-Z0-9])({re.escape(from_bic[:8])})([A-Z0-9]{{0,4}})(?![A-Z0-9])',
                re.IGNORECASE
            )

            def replace_match(m, to=to_bic[:8]):
                suffix  = m.group(2).upper()
                new_bic = to + suffix
                if m.group(0).upper() != new_bic:
                    logger.debug(
                        "[SWIFT_BIC_GLOBAL] alt=%s   neu=%s",
                        m.group(0), new_bic
                    )
                return new_bic

            content = pattern.sub(replace_match, content)

        return content

    # -------------------------------------------------------------------------
    # Validierung
    # -------------------------------------------------------------------------

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """Validiert eine oder mehrere SWIFT MT-Nachrichten."""
        messages = self._split_messages(content)

        if len(messages) <= 1:
            return self._validate_single(content)

        all_errors = []
        all_valid  = True

        for i, message in enumerate(messages, 1):
            valid, errors = self._validate_single(message)
            if not valid:
                all_valid = False
                all_errors.extend(
                    [f"[Nachricht {i}] {e}" for e in errors]
                )

        return all_valid, all_errors

    def _validate_single(self, content: str) -> Tuple[bool, List[str]]:
        """Validiert eine einzelne SWIFT MT-Nachricht."""
        errors = []

        if not re.search(r'\{1:', content):
            errors.append("Kein SWIFT Basic Header Block gefunden")
        if not re.search(r'\{2:', content):
            errors.append("Kein SWIFT Application Header Block gefunden")
        if not re.search(r'\{4:', content):
            errors.append("Kein SWIFT Text Block gefunden")

        field_pattern = re.compile(r':(\d{2}[A-Z]?):')
        if not field_pattern.findall(content):
            errors.append("Keine gueltigen SWIFT-Feldtags gefunden")

        msg_type = self._detect_message_type(content)
        required = self._STATEMENT_REQUIRED_FIELDS.get(msg_type, [])
        for req_field in required:
            if req_field not in content:
                errors.append(
                    f"Pflichtfeld {req_field} fehlt in {msg_type}."
                )

        return len(errors) == 0, errors

    # -------------------------------------------------------------------------
    # Message-ID Extraktion
    # -------------------------------------------------------------------------

    def extract_message_id(self, content: str) -> str:
        """
        Extrahiert die Transaction Reference Number(s) aus dem :20:-Feld.
        Bei Multi-Message werden alle :20:-Felder kommagetrennt zurueckgegeben.
        """
        messages = self._split_messages(content)

        if len(messages) <= 1:
            match = re.search(r':20:([^\r\n]+)', content)
            return match.group(1).strip() if match else ""

        ids = []
        for message in messages:
            match = re.search(r':20:([^\r\n]+)', message)
            if match:
                ids.append(match.group(1).strip())

        return ', '.join(ids) if ids else ""
