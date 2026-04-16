# -*- coding: utf-8 -*-
"""
field_anonymizers/base.py
=========================
Abstrakte Basisklasse für alle Feld-Anonymisierer.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict

from ..models import FieldMapping
from ..config import Config

logger = logging.getLogger(__name__)


class BaseFieldAnonymizer(ABC):
    """
    Abstrakte Basisklasse für alle Feld-Anonymisierer.

    Das gemeinsam genutzte ``mappings``-Dict (übergeben vom übergeordneten
    Nachrichten-Anonymisierer) stellt sicher, dass gleiche Ursprungswerte
    im gesamten Dokument konsistent auf denselben Dummy-Wert gemappt werden.

    Debug-Logging
    -------------
    Bei jeder **neuen** Zuordnung wird auf Level DEBUG protokolliert::

        [FELDTYP] alt wert=<original>  neuer wert=<anonymized>

    Wiederholte Treffer desselben Originalwerts erzeugen keinen weiteren
    Log-Eintrag, da kein neues Mapping angelegt wird.
    """

    def __init__(self, config: Config, mappings: Dict[str, FieldMapping]):
        self.config = config
        self.mappings = mappings        # geteilte Referenz auf das Mappings-Dict

    def _get_or_create_mapping(self, original: str, field_type: str,
                                generator_func) -> str:
        """
        Holt ein bestehendes Mapping oder legt ein neues an.

        Jede neue Zuordnung wird auf DEBUG-Level protokolliert.
        Wiederholungen desselben Originals erzeugen keinen neuen Log-Eintrag.
        """
        key = f"{field_type}:{original}"
        if key not in self.mappings:
            anonymized = generator_func(original)
            self.mappings[key] = FieldMapping(original, anonymized, field_type)
            logger.debug(
                "[%s] alt wert=%s  neuer wert=%s",
                field_type, original, anonymized
            )
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
