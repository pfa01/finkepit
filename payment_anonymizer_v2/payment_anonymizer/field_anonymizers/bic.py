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

    def anonymize_with_entity(self, original: str, entity: dict) -> str:
        """
        Anonymisiert einen BIC mit einer vorgegebenen Entität.

        Verwendet den BIC aus dem Entitätsdatensatz statt des allgemeinen
        Entity-Pools, so dass BIC und Name einer Partei zusammengehören.
        """
        if not original:
            return original
        if not self.is_enabled:
            return original

        dummy_bic = entity.get('bic', self.config.get_default()['bic'])
        return self._get_or_create_mapping(
            original, 'BIC', lambda x: dummy_bic
        )
