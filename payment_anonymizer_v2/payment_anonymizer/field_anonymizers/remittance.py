# -*- coding: utf-8 -*-
"""
field_anonymizers/remittance.py
================================
Anonymisiert Verwendungszwecke / Remittance-Informationen.

Auswahllogik
------------
Round-Robin über den ``remittance_texts``-Pool in der Konfiguration.
Fallback: ``default.remittance`` wenn der Pool leer ist.

Gleiches Original wird immer auf denselben Dummy-Text gemappt
(Konsistenz via Mappings-Dict).
"""

from .base import BaseFieldAnonymizer


class RemittanceFieldAnonymizer(BaseFieldAnonymizer):
    """Anonymisiert Verwendungszwecke (Round-Robin, kein Hash)."""

    @property
    def is_enabled(self) -> bool:
        return self.config.anonymize_remittance

    def anonymize(self, original: str, **kwargs) -> str:
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        return self._get_or_create_mapping(
            original, 'REMITTANCE',
            lambda x: self.config.get_next_remittance()
        )
