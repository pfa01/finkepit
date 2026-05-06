# -*- coding: utf-8 -*-
"""
config.py
=========
Konfigurationsmanager mit entitaetsbasierter, deterministischer Auswahl.
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
        self._person_index    = 0
        self._company_index   = 0
        self._entity_index    = 0
        self._remittance_index = 0
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
        default  = self.data.get('dummy_data', {}).get('default', {})
        missing  = required - set(default.keys())
        if missing:
            raise ValueError(
                f"Unvollstaendiger Default-Eintrag in config.json. "
                f"Fehlende Felder: {', '.join(sorted(missing))}"
            )
        addr_required = {'street', 'postal_code', 'city', 'country'}
        addr_missing  = addr_required - set(default.get('address', {}).keys())
        if addr_missing:
            raise ValueError(
                f"Unvollstaendige Default-Adresse. "
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
    def anonymize_mt_field_86(self) -> bool:
        """Steuert ob das :86:-Feld in MT940/942/950 anonymisiert wird."""
        return self.data.get('anonymization', {}).get('anonymize_mt_field_86', True)

    # -------------------------------------------------------------------------
    # Header-Modifikation
    # -------------------------------------------------------------------------

    @property
    def grphdr_bic_enabled(self) -> bool:
        return self.data.get('header_modification', {}) \
                        .get('modify_grphdr_bic', False)

    @property
    def grphdr_bic_replacements(self) -> list:
        """
        BIC-Ersetzungen fuer GrpHdr und SWIFT-Header-Bloecke.
        8-Zeichen-Praefix-Vergleich – BIC8, BIC11 und LT-Adresse (12 Zeichen)
        werden alle erfasst.
        """
        return self.data.get('header_modification', {}) \
                        .get('grphdr_bic', {}) \
                        .get('bic_replacements', [])

    @property
    def swift_mx_service_enabled(self) -> bool:
        return self.data.get('header_modification', {}) \
                        .get('modify_swift_mx_service', False)

    @property
    def swift_mx_service_prod(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement', {}) \
                        .get('swift_mx', {}) \
                        .get('prod_value', '')

    @property
    def swift_mx_service_test(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement', {}) \
                        .get('swift_mx', {}) \
                        .get('test_value', '')

    @property
    def sepa_service_enabled(self) -> bool:
        return self.data.get('header_modification', {}) \
                        .get('modify_sepa_service', False)

    @property
    def sepa_service_prod(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement', {}) \
                        .get('sepa', {}) \
                        .get('prod_value', '')

    @property
    def sepa_service_test(self) -> str:
        return self.data.get('header_modification', {}) \
                        .get('service_replacement', {}) \
                        .get('sepa', {}) \
                        .get('test_value', '')

    # -------------------------------------------------------------------------
    # Unterstuetzte Nachrichtentypen
    # -------------------------------------------------------------------------

    @property
    def supported_message_types(self) -> list:
        """
        Gibt alle unterstuetzten Nachrichtentypen als flache Liste zurueck.

        ISO 20022 und SWIFT MT werden aus den jeweiligen Unterabschnitten
        zusammengefuehrt. Fallback: leere Liste.
        """
        section  = self.data.get('supported_message_types', {})
        iso_list = section.get('iso20022', [])
        mt_list  = section.get('swift_mt', [])
        return iso_list + mt_list

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
    def not_supported_path(self) -> str:
        """Zielverzeichnis fuer nicht unterstuetzte Nachrichtentypen."""
        return self.data['paths'].get('not_supported_path', 'not_supported/')

    @property
    def archive_path(self) -> str:
        """Zielverzeichnis fuer archivierte Eingabedateien."""
        return self.data['paths'].get('archive_path', 'archive/')

    @property
    def error_path(self) -> str:
        """Zielverzeichnis fuer Dateien die einen Verarbeitungsfehler verursacht haben."""
        return self.data['paths'].get('error_path', 'error/')

    @property
    def prefix(self) -> str:
        return self.data['file_handling']['prefix']

    @property
    def suffix(self) -> str:
        return self.data['file_handling']['suffix']

    @property
    def file_extensions(self) -> List[str]:
        return self.data['file_handling']['file_extensions']

    @property
    def swift_mt_message_separator(self) -> str:
        """
        Trennzeichen zwischen mehreren MT-Nachrichten in einer Datei.
        Standard: '$' (ISO 15022 Multi-Message-Format).
        """
        return self.data.get('file_handling', {}).get(
            'swift_mt_message_separator', '$'
        )

    # -------------------------------------------------------------------------
    # Default-Entitaet
    # -------------------------------------------------------------------------

    def get_default(self) -> Dict[str, Any]:
        """Gibt den Default-Datensatz zurueck (immer verfuegbar als Fallback)."""
        return self.data['dummy_data']['default']

    # -------------------------------------------------------------------------
    # Partei-weise Entitaetszuordnung
    # -------------------------------------------------------------------------

    def get_or_assign_entity(self, original_name: str,
                              is_company: bool) -> Dict[str, Any]:
        """
        Gibt die Entitaet zurueck, die diesem Namen zugeordnet wurde.

        Neue Namen erhalten die naechste Entitaet aus dem passenden Pool
        (Round-Robin). Wird derselbe Name erneut aufgerufen, kommt immer
        dieselbe Entitaet zurueck.
        """
        prefix = 'CO' if is_company else 'PE'
        key    = f"{prefix}:{original_name}"
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
        """Round-Robin ueber Persons + Companies."""
        persons      = self.data['dummy_data'].get('persons', [])
        companies    = self.data['dummy_data'].get('companies', [])
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
        """
        Setzt den Zuordnungs-Cache fuer eine neue Datei zurueck.

        Die Round-Robin-Indizes laufen bewusst ueber alle Dateien durch –
        jede Datei bekommt so die naechste Entitaet aus dem Pool.
        """
        self._entity_assignments = {}
