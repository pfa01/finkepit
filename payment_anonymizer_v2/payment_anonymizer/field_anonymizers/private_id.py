# -*- coding: utf-8 -*-
"""
field_anonymizers/private_id.py
================================
Anonymisiert private Identifikationsfelder (immer aktiv).

Private IDs (Geburtsdatum, Geburtsort, sonstige IDs) werden immer
anonymisiert – unabhängig von der Konfiguration.
"""

from .base import BaseFieldAnonymizer


class PrivateIDFieldAnonymizer(BaseFieldAnonymizer):
    """
    Anonymisiert private Identifikationsfelder.
    ``is_enabled`` gibt bedingungslos ``True`` zurück.
    """

    @property
    def is_enabled(self) -> bool:
        return True

    def anonymize(self, original: str, id_type: str = 'generic',
                  counter: int = 0, **kwargs) -> str:
        """
        Parameters
        ----------
        id_type : str
            'birth_date' | 'birth_city' | 'generic'
        counter : int
            Laufender Zähler für eindeutige Dummy-IDs
        """
        if not original:
            return original

        if id_type == 'birth_date':
            return "1990-01-01"
        if id_type == 'birth_city':
            return "Musterstadt"
        return f"ANON-ID-{counter:06d}"
