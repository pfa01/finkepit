# -*- coding: utf-8 -*-
"""
anonymizers/base.py
===================
Abstrakte Basisklasse für Nachrichten-Anonymisierer.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple

from ..config import Config
from ..models import FieldMapping
from ..field_anonymizers import (
    NameFieldAnonymizer,
    IBANFieldAnonymizer,
    BICFieldAnonymizer,
    AddressFieldAnonymizer,
    RemittanceFieldAnonymizer,
    ContactFieldAnonymizer,
    PrivateIDFieldAnonymizer,
)


class BaseAnonymizer(ABC):
    """
    Abstrakte Basisklasse für Nachrichten-Anonymisierer.

    Instanziiert alle Feld-Anonymisierer und stellt ein gemeinsames
    ``mappings``-Dict bereit, damit konsistente Dummy-Werte über alle
    Feldtypen hinweg gewährleistet sind.

    ``reset()`` löscht das Dict **in-place** (`.clear()`), damit die
    Referenz in allen Feld-Anonymisierern erhalten bleibt.
    """

    def __init__(self, config: Config):
        self.config = config
        self.mappings: Dict[str, FieldMapping] = {}
        self.fields_anonymized = 0
        self._init_field_anonymizers()

    def _init_field_anonymizers(self):
        """Initialisiert alle Feld-Anonymisierer mit dem gemeinsamen Mappings-Dict."""
        self.name_anonymizer       = NameFieldAnonymizer(self.config, self.mappings)
        self.iban_anonymizer       = IBANFieldAnonymizer(self.config, self.mappings)
        self.bic_anonymizer        = BICFieldAnonymizer(self.config, self.mappings)
        self.address_anonymizer    = AddressFieldAnonymizer(self.config, self.mappings)
        self.remittance_anonymizer = RemittanceFieldAnonymizer(self.config, self.mappings)
        self.contact_anonymizer    = ContactFieldAnonymizer(self.config, self.mappings)
        self.private_id_anonymizer = PrivateIDFieldAnonymizer(self.config, self.mappings)

    def reset(self):
        """Setzt den Anonymisierer für eine neue Datei zurück."""
        self.mappings.clear()       # in-place, damit Feld-Anonymisierer dieselbe Referenz behalten
        self.fields_anonymized = 0
        self.config.reset_indices()

    @abstractmethod
    def anonymize(self, content: str) -> Tuple[str, int]:
        """Anonymisiert den Inhalt und gibt (Ergebnis, Anzahl Felder) zurück."""
        pass

    @abstractmethod
    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """Validiert den Inhalt und gibt (Erfolg, Fehler) zurück."""
        pass
