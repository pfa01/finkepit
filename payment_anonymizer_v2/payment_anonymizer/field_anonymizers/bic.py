# -*- coding: utf-8 -*-
"""
field_anonymizers/bic.py
========================
Anonymisiert BIC/SWIFT-Codes.

Auswahllogik
------------
Der Dummy-BIC stammt direkt aus der nächsten Entität des kombinierten
Entity-Pools (Round-Robin über Persons + Companies).
Kein Hash – der BIC ist Bestandteil der gebündelten Entitätsdefinition
in der Konfiguration.

Gleiches Original wird immer auf denselben Dummy-BIC gemappt
(Konsistenz via Mappings-Dict).
"""

from .base import BaseFieldAnonymizer


class BICFieldAnonymizer(BaseFieldAnonymizer):
    """Anonymisiert BIC/SWIFT-Codes anhand gebündelter Entitäten (kein Hash)."""

    @property
    def is_enabled(self) -> bool:
        return self.config.anonymize_bic

    def anonymize(self, original: str, **kwargs) -> str:
        if not original:
            return original
        if not self.is_enabled:
            return original

        return self._get_or_create_mapping(
            original, 'BIC',
            lambda x: self.config.get_next_entity().get(
                'bic', self.config.get_default()['bic']
            )
        )
