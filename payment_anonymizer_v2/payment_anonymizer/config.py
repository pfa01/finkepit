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

Partei-weise Zuordnung
-----------------------
``get_or_assign_entity(name, is_company)`` stellt sicher, dass derselbe
Originalname innerhalb einer Datei immer dieselbe Entität erhält.
So werden Name, IBAN, BIC und Adresse einer Partei konsistent aus einem
einzigen Datensatz bezogen.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .iban_utils import IBANGenerator

logger = logging.getLogger(__name__)


class Config:
    """Konfigurationsmanager."""

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.data = self._load_config()
        self._validate_default()
        self._person_index = 0
        self._company_index = 0
        self._entity_index = 0
        self._remittance_index = 0
        # Name → Entität-Zuordnung (wird pro Datei zurückgesetzt)
        self._entity_assignments: Dict[str, Dict[str, Any]] = {}

    # -------------------------------------------------------------------------
    # Laden & Validierung
    # -------------------------------------------------------------------------

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config nicht gefunden: {self.config_path}")
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _validate_default(self):
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

    @property
    def grphdr_bic_enabled(self) -> bool:
        return self.data.get('header_modification', {}).get('modify_grphdr_bic',False)

    @property
    def grphdr_bic_replacements(self) -> list:
        """
        Gibt die BIC-Ersetzungen für den GrpHdr zurück. 
        Der from-Wert wird als 8-Zeichen-Präfix geprüft,
        damit werden BIC8 und BIC11 erfasst.
        """
        return self.data.get('header_modification',{}) \
                        .get('grphdr_bic', {}) \
                        .get('bic_replacements',[])

    @property
    def swift_mx_service_enabled(self) -> bool:
        return self.data.get('header_modification', {}) \
                        .get('modify_swift_mx_service',False)

    @property
    def swift_mx_service_prod(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement',{}) \
                        .get('swift_mx', {}) \
                        .get('prod_value','')

    @property
    def swift_mx_service_test(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement',{}) \
                        .get('swift_mx', {}) \
                        .get('test_value','')


    @property
    def sepa_service_enabled(self) -> bool:
        return self.data.get('header_modification', {}) \
                        .get('modify_sepa_service',False)


    @property
    def sepa_service_prod(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement',{}) \
                        .get('swift', {}) \
                        .get('prod_value','')


    @property
    def sepa_service_test(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement',{}) \
                        .get('swift', {}) \
                        .get('test_value','')


    
    # -------------------------------------------------------------------------
    # Default-Entität
    # -------------------------------------------------------------------------

    def get_default(self) -> Dict[str, Any]:
        """Gibt den Default-Datensatz zurück (immer verfügbar als Fallback)."""
        return self.data['dummy_data']['default']

    # -------------------------------------------------------------------------
    # Partei-weise Entitätszuordnung  ←  NEU
    # -------------------------------------------------------------------------

    def get_or_assign_entity(self, original_name: str,
                              is_company: bool) -> Dict[str, Any]:
        """
        Gibt die Entität zurück, die diesem Namen zugeordnet wurde.

        Neue Namen erhalten die nächste Entität aus dem passenden Pool
        (Round-Robin). Wird derselbe Name erneut aufgerufen, kommt immer
        dieselbe Entität zurück → Name, IBAN, BIC und Adresse einer Partei
        stammen garantiert aus demselben Datensatz.

        Parameters
        ----------
        original_name : str
            Originalname (Personen- oder Firmenname) vor der Anonymisierung.
        is_company : bool
            True → Firmen-Pool, False → Personen-Pool.
        """
        prefix = 'CO' if is_company else 'PE'
        key = f"{prefix}:{original_name}"
        if key not in self._entity_assignments:
            if is_company:
                self._entity_assignments[key] = self.get_next_company_entity()
            else:
                self._entity_assignments[key] = self.get_next_person_entity()
        return self._entity_assignments[key]

    # -------------------------------------------------------------------------
    # Personen-Pool
    # -------------------------------------------------------------------------

    def get_next_person_entity(self) -> Dict[str, Any]:
        persons = self.data['dummy_data'].get('persons', [])
        if not persons:
            logger.warning("Personen-Pool leer – verwende Default.")
            return self._person_entity_from_default()
        entity = persons[self._person_index % len(persons)]
        self._person_index += 1
        return entity

    def _person_entity_from_default(self) -> Dict[str, Any]:
        d = self.get_default()
        return {
            'first_name': d['first_name'], 'last_name': d['last_name'],
            'iban': d['iban'], 'bic': d['bic'], 'address': d['address'],
            'email': d['email'], 'phone': d['phone'], 'remittance': d['remittance'],
        }

    # -------------------------------------------------------------------------
    # Firmen-Pool
    # -------------------------------------------------------------------------

    def get_next_company_entity(self) -> Dict[str, Any]:
        companies = self.data['dummy_data'].get('companies', [])
        if not companies:
            logger.warning("Firmen-Pool leer – verwende Default.")
            return self._company_entity_from_default()
        entity = companies[self._company_index % len(companies)]
        self._company_index += 1
        return entity

    def _company_entity_from_default(self) -> Dict[str, Any]:
        d = self.get_default()
        return {
            'name': d['company_name'], 'iban': d['iban'], 'bic': d['bic'],
            'address': d['address'], 'email': d['email'], 'phone': d['phone'],
            'remittance': d['remittance'],
        }

    # -------------------------------------------------------------------------
    # Allgemeiner Entity-Pool (feldtyp-agnostisch)
    # -------------------------------------------------------------------------

    def get_next_entity(self) -> Dict[str, Any]:
        """Round-Robin über Persons + Companies (für Felder ohne Partei-Kontext)."""
        persons   = self.data['dummy_data'].get('persons', [])
        companies = self.data['dummy_data'].get('companies', [])
        all_entities = persons + companies
        if not all_entities:
            return self.get_default()
        entity = all_entities[self._entity_index % len(all_entities)]
        self._entity_index += 1
        return entity

    # -------------------------------------------------------------------------
    # Verwendungszweck-Pool
    # -------------------------------------------------------------------------

    def get_next_remittance(self) -> str:
        texts = self.data['dummy_data'].get('remittance_texts', [])
        if not texts:
            return self.get_default()['remittance']
        text = texts[self._remittance_index % len(texts)]
        self._remittance_index += 1
        return text

    # -------------------------------------------------------------------------
    # Reset
    # -------------------------------------------------------------------------

    def reset_indices(self):
        """Setzt alle Indizes und Zuordnungen zurück (für neue Datei)."""
        #self._person_index = 0
        #self._company_index = 0
        #self._entity_index = 0
        #self._remittance_index = 0
        self._entity_assignments = {}     # Partei-Zuordnungen ebenfalls löschen

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
