# -*- coding: utf-8 -*-
"""
field_anonymizers/name.py
=========================
Anonymisiert Personen- und Firmennamen.

Auswahllogik
------------
1. Enthält der Name einen Firmen-Indikator (z.B. 'GmbH', 'AG') →
   nächste Firmen-Entität aus dem Firmen-Pool (Round-Robin).
2. Sonst → nächste Personen-Entität aus dem Personen-Pool (Round-Robin).
3. Pool leer → Default-Eintrag aus der Konfiguration.

Jede Entität ist ein vollständiger Datensatz; der Name ist nur ein Feld
davon. Gleiches Original wird immer auf denselben Dummy-Namen gemappt
(Konsistenz via Mappings-Dict).
"""

from .base import BaseFieldAnonymizer


class NameFieldAnonymizer(BaseFieldAnonymizer):
    """Anonymisiert Personen- und Firmennamen anhand gebündelter Entitäten."""

    COMPANY_INDICATORS = [
        'GmbH', 'AG', 'SE', 'KG', 'Ltd', 'Inc', 'Corp',
        'Bank', 'Sparkasse', 'Holdings', 'Group'
    ]

    @property
    def is_enabled(self) -> bool:
        return self.config.anonymize_name

    def _is_company(self, name: str) -> bool:
        return any(ind.lower() in name.lower() for ind in self.COMPANY_INDICATORS)

    def anonymize(self, original: str, **kwargs) -> str:
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        if self._is_company(original):
            return self._get_or_create_mapping(
                original, 'COMPANY',
                lambda x: self.config.get_next_company_entity()['name']
            )

        return self._get_or_create_mapping(
            original, 'NAME',
            lambda x: self._next_full_name()
        )

    def _next_full_name(self) -> str:
        """Ruft die Entität einmalig ab, um den Index nur einmal zu erhöhen."""
        entity = self.config.get_next_person_entity()
        return f"{entity['first_name']} {entity['last_name']}"

    def anonymize_with_entity(self, original: str, entity: dict,
                               is_company: bool) -> str:
        """
        Anonymisiert einen Namen mit einer vorgegebenen Entität.

        Wird bei der partei-weisen Verarbeitung aufgerufen, damit Name,
        IBAN, BIC und Adresse einer Partei aus demselben Datensatz stammen.
        Die Konsistenzgarantie (gleicher Original → gleicher Dummy) bleibt
        durch das Mappings-Dict erhalten.
        """
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        if is_company:
            new_name   = entity.get('name', self.config.get_default()['company_name'])
            field_type = 'COMPANY'
        else:
            first = entity.get('first_name', '')
            last  = entity.get('last_name', '')
            new_name   = f"{first} {last}".strip()
            field_type = 'NAME'

        return self._get_or_create_mapping(
            original, field_type, lambda x: new_name
        )
