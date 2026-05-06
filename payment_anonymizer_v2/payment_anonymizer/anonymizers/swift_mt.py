# -*- coding: utf-8 -*-
"""
anonymizers/swift_mt.py
=======================
Anonymisierer für SWIFT MT-Nachrichten (MT900/910/940/942/950).
Unterstützt Einzel- und Multi-Message-Dateien (ISO 15022).
"""

import logging
import re
from typing import List, Tuple

from ..config import Config
from .base import BaseAnonymizer

logger = logging.getLogger(__name__)


class SwiftMTAnonymizer(BaseAnonymizer):
    """Anonymisierer für SWIFT MT-Nachrichten."""

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
        ':61:':  'statement_line',      # MT940/942/950: Buchungszeile
    }

    # Subfeld-Schlüssel in :86: bei MT940/942/950
    STATEMENT_86_SUBFIELDS = {
        'ABWA': 'name',         # Abweichender Auftraggeber
        'ABWE': 'name',         # Abweichender Empfänger
        'NAME': 'name',         # Name
        'ENAM': 'name',         # Name des Begünstigten
        'IBAN': 'iban',         # IBAN
        'BIC':  'bic',          # BIC
        'SVWZ': 'remittance',   # Verwendungszweck
        'KREF': 'remittance',   # Kundenreferenz
        'EREF': 'remittance',   # End-to-End-Referenz
    }

    # Pflichtfelder pro Statement-Nachrichtentyp
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
        # Stufe 1: Swift Appliation Header
        match = re.search(r'\{2:[OI](\d{3})', content)
        if match:
            return f"MT{match.group(1)}"
        
        # Stufe 2: Explizite MT-Angabe im Inhalt
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

        Trennlogik – zwei Mechanismen, beide werden geprüft:

        1. ISO 15022-Trennzeichen (konfigurierbar, Standard '$'):
           Nachrichten werden durch das Trennzeichen in einer eigenen
           Zeile getrennt. Das Trennzeichen selbst wird entfernt.

        2. {1:-Block als Nachrichtenbeginn (SWIFT-Standard):
           Lookahead-Split damit der {1:-Trenner erhalten bleibt.

        Enthält die Datei nur eine Nachricht, wird eine Liste mit einem
        Element zurückgegeben.
        """
        separator = self.config.swift_mt_message_separator

        # ── Mechanismus 1: ISO 15022-Trennzeichen ─────────────────────────
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
                    "%d Nachrichten",
                    separator, len(messages)
                )
                return messages

        # ── Mechanismus 2: {1:-Block als Nachrichtenbeginn ────────────────
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
        Anonymisiert ein Party-Feld (Name + Adresszeilen + BIC/IBAN) zeilenweise.

        Partei-weise Logik
        ------------------
        1. Name aus Zeile 0 extrahieren → Entität über Config zuweisen.
        2. Alle Felder dieses Party-Felds verwenden dieselbe Entität.
        """
        lines = content.split('\n')
        anonymized_lines = []

        # ── Entität bestimmen (einmalig pro Party-Feld) ───────────────────
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

        # ── Zeilen verarbeiten ────────────────────────────────────────────
        for i, line in enumerate(lines):

            # BIC in der Zeile mit Entitäts-BIC ersetzen
            if self.bic_anonymizer.is_enabled and self.BIC_PATTERN.search(line):
                line = self.BIC_PATTERN.sub(
                    lambda m, e=entity: self.bic_anonymizer.anonymize_with_entity(
                        m.group(0), e
                    ),
                    line
                )
                self.fields_anonymized += 1

            # IBAN in der Zeile mit Entitäts-IBAN ersetzen
            if self.iban_anonymizer.is_enabled and self.IBAN_PATTERN.search(line):
                line = self.IBAN_PATTERN.sub(
                    lambda m, e=entity: self.iban_anonymizer.anonymize_with_entity(
                        m.group(0), e
                    ),
                    line
                )
                self.fields_anonymized += 1

            # Zeile 0: Name mit Entitäts-Name ersetzen
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

            # Folgezeilen: Adresse mit Entitäts-Adresse ersetzen
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
    # Anonymisierung – MT940/942/950 Statement-Felder
    # -------------------------------------------------------------------------

    def _anonymize_statement_line(self, content: str) -> str:
        """
        Anonymisiert eine :61:-Buchungszeile (MT940/942/950).

        Datum und Betrag bleiben unveraendert.
        Nur das Referenzfeld (nach dem 4-stelligen Buchungsschluessel)
        wird anonymisiert.
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

        Format pro Zeile:
            {entity.remittance} {entity.iban} {zeilen_nr}

        Fortsetzungszeilen (beginnen mit / aber kein /KEY/-Muster) behalten
        ihr fuehrendes / und erhalten ebenfalls das Format.
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

            # Fortsetzungszeile: beginnt mit / aber kein /KEY/-Subfeld
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
        Anonymisiert strukturierte Subfelder in :86: bei MT940/942/950.

        Verwendungszweck-Zeilen (SVWZ, KREF, EREF, Fallback, Fortsetzungszeilen)
        werden im Format  {entity.remittance} {entity.iban} {zeilen_nr}  ersetzt.
        Die Entity wird einmalig pro :86:-Block bestimmt.
        """
        if not content or not content.strip():
            return content

        # ── Entity einmalig für den gesamten :86:-Block bestimmen ─────────
        block_entity = None
        name_match   = re.search(r'/(?:ABWA|ABWE|NAME|ENAM)/([^/\n]+)', content)
        if name_match:
            candidate = name_match.group(1).strip()
            if candidate:
                is_co        = self.name_anonymizer._is_company(candidate)
                block_entity = self.config.get_or_assign_entity(candidate, is_co)
        if block_entity is None:
            block_entity = self.config.get_next_entity()

        # Laufender Zeilenzähler für Verwendungszweck-Zeilen
        remittance_line_nr = [1]

        # ── Fallback: kein strukturiertes Subfeld-Format ──────────────────
        if not re.search(r'/[A-Z]{2,4}/', content):
            return self._anonymize_multiline_remittance(
                content, block_entity, start_line_nr=1
            )

        parts  = re.split(r'(/[A-Z]{2,4}/)', content)
        result = []
        i      = 0

        # Vorangestellter Text vor dem ersten Subfeld
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

        Multi-Message-Unterstuetzung
        ----------------------------
        Enthält die Datei mehrere Nachrichten (getrennt durch '$' oder {1:}),
        wird jede Nachricht einzeln anonymisiert und das Ergebnis wieder
        zusammengefügt. Jede Nachricht bekommt eigene Ersetzungen
        (Mappings-Cache wird pro Nachricht zurückgesetzt).
        """
        self.fields_anonymized = 0

        messages = self._split_messages(content)

        if len(messages) <= 1:
            return self._anonymize_single(content)

        # Multi-Message – jede Nachricht einzeln verarbeiten
        anonymized_parts = []
        total_fields     = 0
        separator        = self.config.swift_mt_message_separator

        for i, message in enumerate(messages, 1):
            logger.debug(
                "Multi-Message: verarbeite Nachricht %d von %d",
                i, len(messages)
            )
            # Mappings-Cache pro Nachricht zurücksetzen
            self.mappings.clear()

            anonymized_msg, fields = self._anonymize_single(message)
            anonymized_parts.append(anonymized_msg)
            total_fields += fields

        self.fields_anonymized = total_fields
        # Nachrichten mit Original-Trennzeichen wieder zusammenfügen
        return f'\n{separator}\n'.join(anonymized_parts), total_fields

    def _anonymize_single(self, content: str) -> Tuple[str, int]:
        """
        Anonymisiert eine einzelne SWIFT MT-Nachricht.

        Enthält die gesamte Anonymisierungslogik für eine Nachricht.
        Wird für Einzel- und für jede Nachricht in Multi-Message aufgerufen.
        """
        self.fields_anonymized = 0
        result                 = content

        # MT940/942/950: :86: mit Subfeld-Parser verarbeiten
        msg_type     = self._detect_message_type(content)
        is_statement = msg_type in ('MT940', 'MT942', 'MT950')

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
                return tag_part + anonymized

            result = pattern.sub(replace_field, result)

        # Kontonummern in :25: Feldern
        if self.iban_anonymizer.is_enabled:
            account_pattern = re.compile(r'(:25:)([A-Z]{2}\d{2}[A-Z0-9]{4,30})')
            result = account_pattern.sub(
                lambda m: m.group(1) + self.iban_anonymizer.anonymize(m.group(2)),
                result
            )

        # BICs in SWIFT-Header-Blöcken 1 und 2 ersetzen
        result = self._replace_header_bics(result)

        # Globale BIC-Ersetzung über den gesamten Nachrichteninhalt
        result = self._replace_header_bics(result)

        count = self.fields_anonymized
        return result, count

    # -------------------------------------------------------------------------
    # Header-BIC Ersetzung
    # -------------------------------------------------------------------------

    def _replace_header_bics(self, content: str) -> str:
        """
        Ersetzt BICs in den SWIFT-Header-Blöcken 1 und 2.

        Block 1 – Basic Header:
            {1:F01BANKLULLXXX0000000000}
                   ^^^^^^^^ BIC beginnt nach F01/F21 etc.

        Block 2 – Application Header:
            {2:I103BANKLULLXXXXN}   Input
            {2:O103BANKLULLXXX...}  Output
                    ^^^^^^^^ BIC beginnt nach I/O + 3-stelligem MT-Typ

        Verwendet dieselbe bic_replacements-Liste wie iso20022.py.
        """
        if not self.config.grphdr_bic_enabled:
            return content

        replacements = self.config.grphdr_bic_replacements
        if not replacements:
            return content

        def replace_bic(bic_value: str) -> str:
            bic_upper = bic_value.upper()
            for mapping in replacements:
                from_bic = mapping.get('from', '').upper()
                to_bic   = mapping.get('to', '')
                if not from_bic or not to_bic:
                    continue
                if bic_upper[:8] == from_bic[:8]:
                    branch  = bic_upper[8:] if len(bic_upper) > 8 else ''
                    new_bic = to_bic[:8] + branch
                    logger.debug(
                        "[SWIFT_HEADER_BIC] alt wert=%s   neuer wert=%s",
                        bic_value, new_bic
                    )
                    return new_bic
            return bic_value

        # ── Block 1: {1:F01<BIC>...} ─────────────────────────────────────
        def replace_block1(match):
            return match.group(1) + replace_bic(match.group(2)) + match.group(3)

        content = re.sub(
            r'(\{1:[A-Z]\d{2})([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(.*?\})',
            replace_block1,
            content
        )

    def _replace_all_bics(self, content: str) -> str:
        """
        Ersetzt alle Vorkommen der konf. BICs im gesamten Nachrichteninhalt
        als globale Textersetzung.
        """

        if not self.config.grphdr_bic_enabled:
            return content

        replacements = self.config.grphdr_bic_replacements
        if not replacements:
            return content
        
        for mapping in replacements:
            from_bic = mapping.get('from', '').strip().upper()
            to_bic = mapping.get('to', '').strip().upper()

            if not from_bic or to_bic:
                continue

            pattern = re.compile(
                rf'(?<![A-Z0-9])({re.escape(from_bic[:8])}([A-Z0-9{{0,4}}])(?![A-Z0-9])',
                re.IGNORECASE
            )

            def replace_match(m, to=to_bic[:8]):
                suffix  = m.group(2).upper()
                new_bic = to + suffix

                if m.group(0).upper() != new_bic:
                    logger.debug(
                        "[SWIFT_BIC_GLOBAL] alt=%s  neu%s",
                        m.group(0), 
                        new_bic
                    )
                return new_bic
        
            content = pattern.sub(replace_match, content)
        return content                

        # ── Block 2: {2:I<MT><BIC>...} oder {2:O<MT><BIC>...} ────────────
        def replace_block2(match):
            return match.group(1) + replace_bic(match.group(2)) + match.group(3)

        content = re.sub(
            r'(\{2:[IO]\d{3})([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(.*?\})',
            replace_block2,
            content,
            flags=re.DOTALL
        )

        return content

    # -------------------------------------------------------------------------
    # Validierung
    # -------------------------------------------------------------------------

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validiert eine oder mehrere SWIFT MT-Nachrichten.

        Bei Multi-Message-Dateien wird jede Nachricht einzeln geprüft.
        Fehler werden mit Nachrichtennummer präfixiert.
        """
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

        Bei Multi-Message-Dateien werden alle :20:-Felder kommagetrennt
        zurückgegeben.
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

        return ', '.join(ids) if ids else ""# -*- coding: utf-8 -*-
"""
anonymizers/swift_mt.py
=======================
Anonymisierer für SWIFT MT-Nachrichten (MT900/910/940/942/950).
Unterstützt Einzel- und Multi-Message-Dateien (ISO 15022).
"""

import logging
import re
from typing import List, Tuple

from ..config import Config
from .base import BaseAnonymizer

logger = logging.getLogger(__name__)


class SwiftMTAnonymizer(BaseAnonymizer):
    """Anonymisierer für SWIFT MT-Nachrichten."""

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
        ':61:':  'statement_line',      # MT940/942/950: Buchungszeile
    }

    # Subfeld-Schlüssel in :86: bei MT940/942/950
    STATEMENT_86_SUBFIELDS = {
        'ABWA': 'name',         # Abweichender Auftraggeber
        'ABWE': 'name',         # Abweichender Empfänger
        'NAME': 'name',         # Name
        'ENAM': 'name',         # Name des Begünstigten
        'IBAN': 'iban',         # IBAN
        'BIC':  'bic',          # BIC
        'SVWZ': 'remittance',   # Verwendungszweck
        'KREF': 'remittance',   # Kundenreferenz
        'EREF': 'remittance',   # End-to-End-Referenz
    }

    # Pflichtfelder pro Statement-Nachrichtentyp
    _STATEMENT_REQUIRED_FIELDS = {
        'MT940': [':20:', ':25:', ':28C:', ':62F:'],
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

        Trennlogik – zwei Mechanismen, beide werden geprüft:

        1. ISO 15022-Trennzeichen (konfigurierbar, Standard '$'):
           Nachrichten werden durch das Trennzeichen in einer eigenen
           Zeile getrennt. Das Trennzeichen selbst wird entfernt.

        2. {1:-Block als Nachrichtenbeginn (SWIFT-Standard):
           Lookahead-Split damit der {1:-Trenner erhalten bleibt.

        Enthält die Datei nur eine Nachricht, wird eine Liste mit einem
        Element zurückgegeben.
        """
        separator = self.config.swift_mt_message_separator

        # ── Mechanismus 1: ISO 15022-Trennzeichen ─────────────────────────
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
                    "%d Nachrichten",
                    separator, len(messages)
                )
                return messages

        # ── Mechanismus 2: {1:-Block als Nachrichtenbeginn ────────────────
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
        Anonymisiert ein Party-Feld (Name + Adresszeilen + BIC/IBAN) zeilenweise.

        Partei-weise Logik
        ------------------
        1. Name aus Zeile 0 extrahieren → Entität über Config zuweisen.
        2. Alle Felder dieses Party-Felds verwenden dieselbe Entität.
        """
        lines = content.split('\n')
        anonymized_lines = []

        # ── Entität bestimmen (einmalig pro Party-Feld) ───────────────────
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

        # ── Zeilen verarbeiten ────────────────────────────────────────────
        for i, line in enumerate(lines):

            # BIC in der Zeile mit Entitäts-BIC ersetzen
            if self.bic_anonymizer.is_enabled and self.BIC_PATTERN.search(line):
                line = self.BIC_PATTERN.sub(
                    lambda m, e=entity: self.bic_anonymizer.anonymize_with_entity(
                        m.group(0), e
                    ),
                    line
                )
                self.fields_anonymized += 1

            # IBAN in der Zeile mit Entitäts-IBAN ersetzen
            if self.iban_anonymizer.is_enabled and self.IBAN_PATTERN.search(line):
                line = self.IBAN_PATTERN.sub(
                    lambda m, e=entity: self.iban_anonymizer.anonymize_with_entity(
                        m.group(0), e
                    ),
                    line
                )
                self.fields_anonymized += 1

            # Zeile 0: Name mit Entitäts-Name ersetzen
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

            # Folgezeilen: Adresse mit Entitäts-Adresse ersetzen
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
    # Anonymisierung – MT940/942/950 Statement-Felder
    # -------------------------------------------------------------------------

    def _anonymize_statement_line(self, content: str) -> str:
        """
        Anonymisiert eine :61:-Buchungszeile (MT940/942/950).

        Datum und Betrag bleiben unveraendert.
        Nur das Referenzfeld (nach dem 4-stelligen Buchungsschluessel)
        wird anonymisiert.
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

        Format pro Zeile:
            {entity.remittance} {entity.iban} {zeilen_nr}

        Fortsetzungszeilen (beginnen mit / aber kein /KEY/-Muster) behalten
        ihr fuehrendes / und erhalten ebenfalls das Format.
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

            # Fortsetzungszeile: beginnt mit / aber kein /KEY/-Subfeld
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
        Anonymisiert strukturierte Subfelder in :86: bei MT940/942/950.

        Verwendungszweck-Zeilen (SVWZ, KREF, EREF, Fallback, Fortsetzungszeilen)
        werden im Format  {entity.remittance} {entity.iban} {zeilen_nr}  ersetzt.
        Die Entity wird einmalig pro :86:-Block bestimmt.
        """
        if not content or not content.strip():
            return content

        # ── Entity einmalig für den gesamten :86:-Block bestimmen ─────────
        block_entity = None
        name_match   = re.search(r'/(?:ABWA|ABWE|NAME|ENAM)/([^/\n]+)', content)
        if name_match:
            candidate = name_match.group(1).strip()
            if candidate:
                is_co        = self.name_anonymizer._is_company(candidate)
                block_entity = self.config.get_or_assign_entity(candidate, is_co)
        if block_entity is None:
            block_entity = self.config.get_next_entity()

        # Laufender Zeilenzähler für Verwendungszweck-Zeilen
        remittance_line_nr = [1]

        # ── Fallback: kein strukturiertes Subfeld-Format ──────────────────
        if not re.search(r'/[A-Z]{2,4}/', content):
            return self._anonymize_multiline_remittance(
                content, block_entity, start_line_nr=1
            )

        parts  = re.split(r'(/[A-Z]{2,4}/)', content)
        result = []
        i      = 0

        # Vorangestellter Text vor dem ersten Subfeld
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

        Multi-Message-Unterstuetzung
        ----------------------------
        Enthält die Datei mehrere Nachrichten (getrennt durch '$' oder {1:}),
        wird jede Nachricht einzeln anonymisiert und das Ergebnis wieder
        zusammengefügt. Jede Nachricht bekommt eigene Ersetzungen
        (Mappings-Cache wird pro Nachricht zurückgesetzt).
        """
        self.fields_anonymized = 0

        messages = self._split_messages(content)

        if len(messages) <= 1:
            return self._anonymize_single(content)

        # Multi-Message – jede Nachricht einzeln verarbeiten
        anonymized_parts = []
        total_fields     = 0
        separator        = self.config.swift_mt_message_separator

        for i, message in enumerate(messages, 1):
            logger.debug(
                "Multi-Message: verarbeite Nachricht %d von %d",
                i, len(messages)
            )
            # Mappings-Cache pro Nachricht zurücksetzen
            self.mappings.clear()

            anonymized_msg, fields = self._anonymize_single(message)
            anonymized_parts.append(anonymized_msg)
            total_fields += fields

        self.fields_anonymized = total_fields
        # Nachrichten mit Original-Trennzeichen wieder zusammenfügen
        return f'\n{separator}\n'.join(anonymized_parts), total_fields

    def _anonymize_single(self, content: str) -> Tuple[str, int]:
        """
        Anonymisiert eine einzelne SWIFT MT-Nachricht.

        Enthält die gesamte Anonymisierungslogik für eine Nachricht.
        Wird für Einzel- und für jede Nachricht in Multi-Message aufgerufen.
        """
        self.fields_anonymized = 0
        result                 = content

        # MT940/942/950: :86: mit Subfeld-Parser verarbeiten
        msg_type     = self._detect_message_type(content)
        is_statement = msg_type in ('MT940', 'MT942', 'MT950')

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
                return tag_part + anonymized

            result = pattern.sub(replace_field, result)

        # Kontonummern in :25: Feldern
        if self.iban_anonymizer.is_enabled:
            account_pattern = re.compile(r'(:25:)([A-Z]{2}\d{2}[A-Z0-9]{4,30})')
            result = account_pattern.sub(
                lambda m: m.group(1) + self.iban_anonymizer.anonymize(m.group(2)),
                result
            )

        # BICs in SWIFT-Header-Blöcken 1 und 2 ersetzen
        result = self._replace_header_bics(result)

        count = self.fields_anonymized
        return result, count

    # -------------------------------------------------------------------------
    # Header-BIC Ersetzung
    # -------------------------------------------------------------------------

    def _replace_header_bics(self, content: str) -> str:
        """
        Ersetzt BICs in den SWIFT-Header-Blöcken 1 und 2.

        Block 1 – Basic Header:
            {1:F01BANKLULLXXX0000000000}
                   ^^^^^^^^ BIC beginnt nach F01/F21 etc.

        Block 2 – Application Header:
            {2:I103BANKLULLXXXXN}   Input
            {2:O103BANKLULLXXX...}  Output
                    ^^^^^^^^ BIC beginnt nach I/O + 3-stelligem MT-Typ

        Verwendet dieselbe bic_replacements-Liste wie iso20022.py.
        """
        if not self.config.grphdr_bic_enabled:
            return content

        replacements = self.config.grphdr_bic_replacements
        if not replacements:
            return content

        def replace_bic(bic_value: str) -> str:
            bic_upper = bic_value.upper()
            for mapping in replacements:
                from_bic = mapping.get('from', '').upper()
                to_bic   = mapping.get('to', '')
                if not from_bic or not to_bic:
                    continue
                if bic_upper[:8] == from_bic[:8]:
                    branch  = bic_upper[8:] if len(bic_upper) > 8 else ''
                    new_bic = to_bic[:8] + branch
                    logger.debug(
                        "[SWIFT_HEADER_BIC] alt wert=%s   neuer wert=%s",
                        bic_value, new_bic
                    )
                    return new_bic
            return bic_value

        # ── Block 1: {1:F01<BIC>...} ─────────────────────────────────────
        def replace_block1(match):
            return match.group(1) + replace_bic(match.group(2)) + match.group(3)

        content = re.sub(
            r'(\{1:[A-Z]\d{2})([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(.*?\})',
            replace_block1,
            content
        )

        # ── Block 2: {2:I<MT><BIC>...} oder {2:O<MT><BIC>...} ────────────
        def replace_block2(match):
            return match.group(1) + replace_bic(match.group(2)) + match.group(3)

        content = re.sub(
            r'(\{2:[IO]\d{3})([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(.*?\})',
            replace_block2,
            content,
            flags=re.DOTALL
        )

        return content

    # -------------------------------------------------------------------------
    # Validierung
    # -------------------------------------------------------------------------

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validiert eine oder mehrere SWIFT MT-Nachrichten.

        Bei Multi-Message-Dateien wird jede Nachricht einzeln geprüft.
        Fehler werden mit Nachrichtennummer präfixiert.
        """
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

        Bei Multi-Message-Dateien werden alle :20:-Felder kommagetrennt
        zurückgegeben.
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
