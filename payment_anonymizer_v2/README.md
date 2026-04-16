# Payment Message Anonymizer

Anonymisiert ISO 20022 (camt.054/057, pacs.002/008/009/010) und
SWIFT MT (MT900/MT910) Nachrichten.

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Verwendung

```bash
# Ganzes Verzeichnis verarbeiten (Standard-Config)
python main.py

# Eigene Konfigurationsdatei
python main.py -c meine_config.json

# Einzelne Datei
python main.py -f pfad/zur/nachricht.xml

# Ausführliche Ausgabe bei Fehlern
python main.py -v
```

---

## Auswahllogik für Dummy-Daten

### Prinzip

Alle Ersetzungen sind **deterministisch** und **nachvollziehbar**.
Es gibt keinerlei Zufall oder Hash-basierte Auswahl.

| Methode | Index | Beschreibung |
|---|---|---|
| `get_next_person_entity()` | `_person_index` | Round-Robin über `persons`-Pool |
| `get_next_company_entity()` | `_company_index` | Round-Robin über `companies`-Pool |
| `get_next_entity()` | `_entity_index` | Round-Robin über `persons + companies` (für IBAN, BIC, Adresse, Kontakt) |
| `get_next_remittance()` | `_remittance_index` | Round-Robin über `remittance_texts`-Pool |
| `get_default()` | – | Immer derselbe Fallback-Eintrag |

Für jede neue Original→Dummy-Zuordnung wird der Index um 1 erhöht.
Trifft derselbe Originalwert erneut auf, wird das bestehende Mapping
verwendet → **dokumentweite Konsistenz**.

### Default

Der `default`-Eintrag in `config.json` ist ein Pflichtfeld und wird
verwendet, wenn ein Pool leer ist. Er muss alle Felder vollständig
enthalten (first_name, last_name, company_name, iban, bic, address,
email, phone, remittance).

---

## config.json – Struktur

```json
{
  "dummy_data": {
    "default": {
      "first_name":   "Max",
      "last_name":    "Mustermann",
      "company_name": "Muster GmbH",
      "iban":         "DE89370400440532013000",
      "bic":          "COBADEFFXXX",
      "address": {
        "street": "Musterstraße 1", "postal_code": "10115",
        "city": "Berlin",          "country": "DE"
      },
      "email":      "default@example.com",
      "phone":      "+49 30 00000000",
      "remittance": "Musterreferenz 0000"
    },
    "persons": [
      {
        "first_name": "Anna",   "last_name": "Bauer",
        "iban":  "DE89...",     "bic": "COBADEFFXXX",
        "address": { "street": "...", "postal_code": "...", "city": "...", "country": "DE" },
        "email": "anna.bauer@example.com",
        "phone": "+49 30 12345001",
        "remittance": "Rechnung 2024-001"
      }
    ],
    "companies": [
      {
        "name": "Alpha Handels GmbH",
        "iban": "DE27...", "bic": "DEUTDEDBBER",
        "address": { ... },
        "email": "info@alpha.example.com",
        "phone": "+49 40 99880001",
        "remittance": "Lieferantenrechnung 2024-001"
      }
    ],
    "remittance_texts": [
      "Rechnung 2024-R01", "Monatliche Zahlung Januar 2024"
    ]
  }
}
```

**Wichtig:** Jede Person und jede Firma ist ein vollständig in sich
geschlossener Datensatz. Es gibt keine getrennten Pools für IBANs,
BICs oder Adressen.

---

## Paketstruktur

```
payment_anonymizer/
├── main.py
├── requirements.txt
├── config.json
├── README.md
└── payment_anonymizer/
    ├── __init__.py
    ├── models.py               – AnonymizationResult, FieldMapping
    ├── iban_utils.py           – IBANGenerator
    ├── config.py               – Config (entity-basiert, Round-Robin)
    ├── result_logger.py        – ResultLogger (CSV / JSON)
    ├── payment_anonymizer.py   – PaymentAnonymizer (Hauptprozessor)
    ├── field_anonymizers/
    │   ├── base.py             – BaseFieldAnonymizer (ABC)
    │   ├── name.py             – NameFieldAnonymizer
    │   ├── iban.py             – IBANFieldAnonymizer
    │   ├── bic.py              – BICFieldAnonymizer
    │   ├── address.py          – AddressFieldAnonymizer
    │   ├── remittance.py       – RemittanceFieldAnonymizer
    │   ├── contact.py          – ContactFieldAnonymizer
    │   └── private_id.py       – PrivateIDFieldAnonymizer
    └── anonymizers/
        ├── base.py             – BaseAnonymizer (ABC)
        ├── iso20022.py         – ISO20022Anonymizer
        └── swift_mt.py         – SwiftMTAnonymizer
```
