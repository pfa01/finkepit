# -*- coding: utf-8 -*-
"""
config.py
=========
Konfigurationsmanager mit entitätsbasierter, deterministischer Auswahl.

Auswahllogik
------------
Alle Ersetzungen nutzen **einen gemeinsamen Entity-Index**, der für jede
neue Original→Dummy-Zuordnung um 1 erhöht wird (Round-Robin). Dadurch ist
die Reihenfolge der Ersetzungen innerhalb eines Dokuments vollständig
deterministisch und nachvollziehbar.

Config-Struktur (dummy_data)
----------------------------
  default   – vollständiger Fallback-Datensatz; wird verwendet wenn
              kein Pool-Eintrag vorhanden ist.
  persons   – Liste von Person-Entitäten (Name, IBAN, BIC, Adresse,
              Kontakt, Verwendungszweck)
  companies – Liste von Firmen-Entitäten (gleiche Felder, Firmenname
              statt Vor-/Nachname)
  remittance_texts – eigenständiger Fallback-Pool für Verwendungszwecke

Jede Entität im Pool ist ein vollständig in sich geschlossener Datensatz.
Es gibt keine getrennten Pools für IBANs, BICs oder Adressen.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Config:
    """
    Konfigurationsmanager.

    Indizes
    -------
    _person_index    – Round-Robin-Index für den Personen-Pool
    _company_index   – Round-Robin-Index für den Firmen-Pool
    _entity_index    – gemeinsamer Index für feldtyp-agnostische Abfragen
                       (IBAN, BIC, Adresse, Kontakt)
    _remittance_index – Round-Robin-Index für den Verwendungszweck-Pool
    """

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.data = self._load_config()
        self._validate_default()
        self._person_index = 0
        self._company_index = 0
        self._entity_index = 0
        self._remittance_index = 0

    # -------------------------------------------------------------------------
    # Laden & Validierung
    # -------------------------------------------------------------------------

    def _load_config(self) -> Dict[str, Any]:
        """Lädt die JSON-Konfiguration."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config nicht gefunden: {self.config_path}")
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _validate_default(self):
        """Stellt sicher, dass der Default-Eintrag vollständig ist."""
        required = {'first_name', 'last_name', 'company_name', 'iban', 'bic',
                    'address', 'email', 'phone', 'remittance'}
        default = self.data.get('dummy_data', {}).get('default', {})
        missing = required - set(default.keys())
        if missing:
            raise ValueError(
                f"Unvollständiger Default-Eintrag in config.json. "
                f"Fehlende Felder: {', '.join(sorted(missing))}"
            )
        addr_required = {'street', 'postal_code', 'city', 'country'}
        addr_missing = addr_required - set(default.get('address', {}).keys())
        if addr_missing:
            raise ValueError(
                f"Unvollständige Default-Adresse. "
                f"Fehlende Felder: {', '.join(sorted(addr_missing))}"
            )

    # -------------------------------------------------------------------------
    # Anonymisierungs-Einstellungen
    # -------------------------------------------------------------------------

    @property
    def anonymize_name(self) -> bool:
        return self.data.get('anonymization', {}).get('anonymize_name', True)

    @property
    def anonymize_iban(self) -> bool:
        return self.data.get('anonymization', {}).get('anonymize_iban', True)

    @property
    def anonymize_bic(self) -> bool:
        return self.data.get('anonymization', {}).get('anonymize_bic', True)

    @property
    def anonymize_address_field(self) -> bool:
        return self.data.get('anonymization', {}).get('anonymize_address_field', True)

    @property
    def anonymize_remittance(self) -> bool:
        return self.data.get('anonymization', {}).get('anonymize_remittance', True)

    @property
    def anonymize_contact(self) -> bool:
        return self.data.get('anonymization', {}).get('anonymize_contact', True)

    # -------------------------------------------------------------------------
    # Default-Entität
    # -------------------------------------------------------------------------

    def get_default(self) -> Dict[str, Any]:
        """
        Gibt den Default-Datensatz zurück.

        Der Default wird verwendet wenn:
        - ein Pool leer ist
        - keine passende Entität gefunden wird
        Er enthält alle Felder einer Entität vollständig.
        """
        return self.data['dummy_data']['default']

    # -------------------------------------------------------------------------
    # Personen-Pool
    # -------------------------------------------------------------------------

    def get_next_person_entity(self) -> Dict[str, Any]:
        """
        Gibt die nächste Personen-Entität zurück (Round-Robin).

        Enthält: first_name, last_name, iban, bic, address, email,
                 phone, remittance.
        Fallback: Default-Entität.
        """
        persons = self.data['dummy_data'].get('persons', [])
        if not persons:
            logger.warning("Personen-Pool leer – verwende Default.")
            return self._person_entity_from_default()
        entity = persons[self._person_index % len(persons)]
        self._person_index += 1
        return entity

    def _person_entity_from_default(self) -> Dict[str, Any]:
        """Erstellt eine Personen-Entität aus dem Default-Eintrag."""
        d = self.get_default()
        return {
            'first_name': d['first_name'],
            'last_name':  d['last_name'],
            'iban':       d['iban'],
            'bic':        d['bic'],
            'address':    d['address'],
            'email':      d['email'],
            'phone':      d['phone'],
            'remittance': d['remittance'],
        }

    # -------------------------------------------------------------------------
    # Firmen-Pool
    # -------------------------------------------------------------------------

    def get_next_company_entity(self) -> Dict[str, Any]:
        """
        Gibt die nächste Firmen-Entität zurück (Round-Robin).

        Enthält: name, iban, bic, address, email, phone, remittance.
        Fallback: Default-Entität.
        """
        companies = self.data['dummy_data'].get('companies', [])
        if not companies:
            logger.warning("Firmen-Pool leer – verwende Default.")
            return self._company_entity_from_default()
        entity = companies[self._company_index % len(companies)]
        self._company_index += 1
        return entity

    def _company_entity_from_default(self) -> Dict[str, Any]:
        """Erstellt eine Firmen-Entität aus dem Default-Eintrag."""
        d = self.get_default()
        return {
            'name':       d['company_name'],
            'iban':       d['iban'],
            'bic':        d['bic'],
            'address':    d['address'],
            'email':      d['email'],
            'phone':      d['phone'],
            'remittance': d['remittance'],
        }

    # -------------------------------------------------------------------------
    # Allgemeiner Entity-Pool (feldtyp-agnostisch)
    # -------------------------------------------------------------------------

    def get_next_entity(self) -> Dict[str, Any]:
        """
        Gibt die nächste Entität aus dem kombinierten Pool zurück (Round-Robin).

        Wird von feldtyp-agnostischen Anonymisierern genutzt (IBAN, BIC,
        Adresse, Kontakt), bei denen kein Personen/Firmen-Kontext bekannt ist.
        Pool = persons + companies in Konfigurationsreihenfolge.
        Fallback: Default-Entität.
        """
        persons   = self.data['dummy_data'].get('persons', [])
        companies = self.data['dummy_data'].get('companies', [])
        all_entities = persons + companies

        if not all_entities:
            logger.warning("Kombinierter Entity-Pool leer – verwende Default.")
            return self.get_default()

        entity = all_entities[self._entity_index % len(all_entities)]
        self._entity_index += 1
        return entity

    # -------------------------------------------------------------------------
    # Verwendungszweck-Pool
    # -------------------------------------------------------------------------

    def get_next_remittance(self) -> str:
        """
        Gibt den nächsten Verwendungszweck zurück (Round-Robin).

        Fallback: Default-Remittance.
        """
        texts = self.data['dummy_data'].get('remittance_texts', [])
        if not texts:
            logger.warning("Verwendungszweck-Pool leer – verwende Default.")
            return self.get_default()['remittance']
        text = texts[self._remittance_index % len(texts)]
        self._remittance_index += 1
        return text

    # -------------------------------------------------------------------------
    # Reset
    # -------------------------------------------------------------------------

    def reset_indices(self):
        """Setzt alle Indizes zurück (für neue Datei)."""
        self._person_index = 0
        self._company_index = 0
        self._entity_index = 0
        self._remittance_index = 0

    # -------------------------------------------------------------------------
    # Pfad-Konfiguration
    # -------------------------------------------------------------------------

    @property
    def input_path(self) -> str:
        return self.data['paths']['input_path']

    @property
    def output_path(self) -> str:
        return self.data['paths']['output_path']

    @property
    def log_path(self) -> str:
        return self.data['paths']['log_path']

    @property
    def prefix(self) -> str:
        return self.data['file_handling']['prefix']

    @property
    def suffix(self) -> str:
        return self.data['file_handling']['suffix']

    @property
    def file_extensions(self) -> List[str]:
        return self.data['file_handling']['file_extensions']
