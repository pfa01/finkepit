# -*- coding: utf-8 -*-
"""
field_anonymizers/iban.py
=========================
Anonymisiert IBANs.

Auswahllogik
------------
Die Dummy-IBAN stammt direkt aus der nächsten Entität des kombinierten
Entity-Pools (Round-Robin über Persons + Companies).
Kein Hash, keine länderspezifische Generierung – die IBAN ist Bestandteil
der gebündelten Entitätsdefinition in der Konfiguration.

Gleiches Original wird immer auf dieselbe Dummy-IBAN gemappt
(Konsistenz via Mappings-Dict).
"""

from .base import BaseFieldAnonymizer


class IBANFieldAnonymizer(BaseFieldAnonymizer):
    """Anonymisiert IBANs anhand gebündelter Entitäten (kein Hash)."""

    @property
    def is_enabled(self) -> bool:
        return self.config.anonymize_iban

    def anonymize(self, original: str, **kwargs) -> str:
        if not original or len(original) < 2:
            return original
        if not self.is_enabled:
            return original

        original_clean = original.replace(" ", "").upper()

        return self._get_or_create_mapping(
            original_clean, 'IBAN',
            lambda x: self.config.get_next_entity().get(
                'iban', self.config.get_default()['iban']
            )
        )
