# -*- coding: utf-8 -*-
"""
field_anonymizers/base.py
=========================
Abstrakte Basisklasse für alle Feld-Anonymisierer.
"""

from abc import ABC, abstractmethod
from typing import Dict

from ..models import FieldMapping
from ..config import Config


class BaseFieldAnonymizer(ABC):
    """
    Abstrakte Basisklasse für alle Feld-Anonymisierer.

    Das gemeinsam genutzte ``mappings``-Dict (übergeben vom übergeordneten
    Nachrichten-Anonymisierer) stellt sicher, dass gleiche Ursprungswerte
    im gesamten Dokument konsistent auf denselben Dummy-Wert gemappt werden.

    Auswahllogik
    ------------
    Neue Mappings werden durch ``_get_or_create_mapping`` angelegt.
    Der Generator-Callback wird genau einmal pro Original-Wert aufgerufen
    und greift auf die Round-Robin-Methoden der Config zu.
    Damit ist die Ersetzung deterministisch und reproduzierbar.
    """

    def __init__(self, config: Config, mappings: Dict[str, FieldMapping]):
        self.config = config
        self.mappings = mappings        # geteilte Referenz auf das Mappings-Dict

    def _get_or_create_mapping(self, original: str, field_type: str,
                                generator_func) -> str:
        """
        Holt ein bestehendes Mapping oder legt ein neues an.

        Der ``generator_func`` wird nur aufgerufen, wenn noch kein Mapping
        für ``original`` existiert → garantiert dokumentweite Konsistenz.
        """
        key = f"{field_type}:{original}"
        if key not in self.mappings:
            anonymized = generator_func(original)
            self.mappings[key] = FieldMapping(original, anonymized, field_type)
        return self.mappings[key].anonymized

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Gibt zurück, ob dieser Anonymisierer laut Konfiguration aktiv ist."""
        pass

    @abstractmethod
    def anonymize(self, value: str, **kwargs) -> str:
        """
        Gibt den anonymisierten Wert zurück.
        Wenn ``is_enabled`` False oder der Wert leer ist, wird der
        Originalwert unverändert zurückgegeben.
        """
        pass
