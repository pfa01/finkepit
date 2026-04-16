# -*- coding: utf-8 -*-
"""
payment_anonymizer
==================
Anonymisiert ISO 20022 (camt.054/057, pacs.002/008/009/010) und
SWIFT MT (MT900/MT910) Nachrichten.

Autor: Peter Finken

Auswahllogik für Dummy-Daten
-----------------------------
Alle Ersetzungen nutzen einen gemeinsamen Round-Robin-Index.
Kein Hash, keine Zufallsauswahl. Gebündelte Entitäten (Person/Firma)
definieren Name, IBAN, BIC, Adresse und Kontakt in einem Block.
Ein expliziter Default greift, wenn kein Pool-Eintrag vorhanden ist.

Paketstruktur
-------------
payment_anonymizer/
├── models.py
├── iban_utils.py
├── config.py
├── result_logger.py
├── payment_anonymizer.py
├── field_anonymizers/
│   ├── base.py, name.py, iban.py, bic.py
│   ├── address.py, remittance.py, contact.py, private_id.py
└── anonymizers/
    ├── base.py, iso20022.py, swift_mt.py
"""

from .models             import AnonymizationResult, FieldMapping
from .config             import Config
from .result_logger      import ResultLogger
from .payment_anonymizer import PaymentAnonymizer
from .field_anonymizers  import (
    BaseFieldAnonymizer, NameFieldAnonymizer, IBANFieldAnonymizer,
    BICFieldAnonymizer, AddressFieldAnonymizer, RemittanceFieldAnonymizer,
    ContactFieldAnonymizer, PrivateIDFieldAnonymizer,
)
from .anonymizers import BaseAnonymizer, ISO20022Anonymizer, SwiftMTAnonymizer

__all__ = [
    "AnonymizationResult", "FieldMapping", "Config", "ResultLogger",
    "PaymentAnonymizer", "BaseFieldAnonymizer", "NameFieldAnonymizer",
    "IBANFieldAnonymizer", "BICFieldAnonymizer", "AddressFieldAnonymizer",
    "RemittanceFieldAnonymizer", "ContactFieldAnonymizer",
    "PrivateIDFieldAnonymizer", "BaseAnonymizer", "ISO20022Anonymizer",
    "SwiftMTAnonymizer",
]
