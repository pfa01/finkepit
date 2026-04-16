# -*- coding: utf-8 -*-
"""
field_anonymizers/address.py
============================
Anonymisiert strukturierte Adressfelder.

Auswahllogik
------------
Die Dummy-Adresse stammt direkt aus der nächsten Entität des kombinierten
Entity-Pools (Round-Robin über Persons + Companies).
Fallback: Default-Adresse aus der Konfiguration.

Methoden
--------
anonymize(value, field_type)
    Einzelnes ISO-20022-Adressfeld (street, postal, city, country).
anonymize_line(value)
    Kombiniertes AdrLine-Feld (Straße + PLZ + Stadt in einem Feld).
anonymize_swift_line(value, line_index)
    Zeilenbasierte SWIFT-Adresse (Zeile 1 → Straße, Zeile 2 → PLZ + Stadt).
"""

from typing import Dict, Any
from .base import BaseFieldAnonymizer


class AddressFieldAnonymizer(BaseFieldAnonymizer):
    """Anonymisiert Adressfelder anhand gebündelter Entitäten."""

    @property
    def is_enabled(self) -> bool:
        return self.config.anonymize_address_field

    def _get_address(self) -> Dict[str, Any]:
        """Holt die Adresse der nächsten Entität, Fallback auf Default."""
        entity = self.config.get_next_entity()
        return entity.get('address', self.config.get_default()['address'])

    def anonymize(self, original: str, field_type: str = 'generic',
                  counter: int = 0, **kwargs) -> str:
        """
        Anonymisiert ein einzelnes Adressfeld.

        Parameters
        ----------
        field_type : str
            'street' | 'postal' | 'city' | 'country' | 'generic'
        counter : int
            Fallback-Zähler für den Typ 'generic'
        """
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        address = self._get_address()
        mapping = {
            'street':  address.get('street',      self.config.get_default()['address']['street']),
            'postal':  address.get('postal_code',  self.config.get_default()['address']['postal_code']),
            'city':    address.get('city',         self.config.get_default()['address']['city']),
            'country': address.get('country',      self.config.get_default()['address']['country']),
        }
        return mapping.get(field_type, f"Anonymisiert {counter}")

    def anonymize_line(self, original: str) -> str:
        """Erstellt eine kombinierte Adresszeile (Straße, PLZ Stadt)."""
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        addr = self._get_address()
        street      = addr.get('street',      self.config.get_default()['address']['street'])
        postal_code = addr.get('postal_code', self.config.get_default()['address']['postal_code'])
        city        = addr.get('city',        self.config.get_default()['address']['city'])
        return f"{street}, {postal_code} {city}"

    def anonymize_swift_line(self, original: str, line_index: int) -> str:
        """
        Anonymisiert eine Adresszeile im SWIFT-MT-Format (zeilenindex-basiert).

        Parameters
        ----------
        line_index : int
            1 → Straße, 2 → PLZ + Stadt, sonst unverändert
        """
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        addr = self._get_address()
        if line_index == 1:
            return addr.get('street', self.config.get_default()['address']['street'])
        if line_index == 2:
            postal_code = addr.get('postal_code', self.config.get_default()['address']['postal_code'])
            city        = addr.get('city',        self.config.get_default()['address']['city'])
            return f"{postal_code} {city}"
        return original

    def anonymize_with_entity(self, original: str, entity: dict,
                               field_type: str = 'generic',
                               counter: int = 0) -> str:
        """
        Anonymisiert ein einzelnes Adressfeld mit einer vorgegebenen Entität.

        Parameters
        ----------
        field_type : str
            'street' | 'postal' | 'city' | 'country' | 'generic'
        """
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        addr    = entity.get('address', self.config.get_default()['address'])
        default = self.config.get_default()['address']
        mapping = {
            'street':  addr.get('street',      default['street']),
            'postal':  addr.get('postal_code',  default['postal_code']),
            'city':    addr.get('city',         default['city']),
            'country': addr.get('country',      default['country']),
        }
        return mapping.get(field_type, f"Anonymisiert {counter}")

    def anonymize_line_with_entity(self, original: str, entity: dict) -> str:
        """Erstellt eine kombinierte Adresszeile mit einer vorgegebenen Entität."""
        if not original or not original.strip():
            return original
        if not self.is_enabled:
            return original

        addr    = entity.get('address', self.config.get_default()['address'])
        default = self.config.get_default()['address']
        street  = addr.get('street',      default['street'])
        postal  = addr.get('postal_code', default['postal_code'])
        city    = addr.get('city',        default['city'])
        return f"{street}, {postal} {city}"
