# -*- coding: utf-8 -*-
"""
field_anonymizers/contact.py
============================
Anonymisiert Kontaktdaten (E-Mail, Telefon, Fax, Mobil).

Auswahllogik
------------
E-Mail und Telefon stammen direkt aus der nächsten Entität des kombinierten
Entity-Pools (Round-Robin über Persons + Companies).
Fallback: Default-Kontaktdaten aus der Konfiguration.
"""

from .base import BaseFieldAnonymizer


class ContactFieldAnonymizer(BaseFieldAnonymizer):
    """Anonymisiert Kontaktdaten anhand gebündelter Entitäten."""

    @property
    def is_enabled(self) -> bool:
        return self.config.anonymize_contact

    def anonymize(self, original: str, contact_type: str = 'generic',
                  counter: int = 0, **kwargs) -> str:
        """
        Parameters
        ----------
        contact_type : str
            'email' | 'phone' | 'generic'
        counter : int
            Laufender Zähler als Fallback für den Typ 'generic'
        """
        if not original:
            return original
        if not self.is_enabled:
            return original

        entity  = self.config.get_next_entity()
        default = self.config.get_default()

        if contact_type == 'email':
            return entity.get('email', default['email'])
        if contact_type == 'phone':
            return entity.get('phone', default['phone'])
        return f"ANONYMIZED_{counter}"
