# -*- coding: utf-8 -*-
"""
anonymizers/iso20022.py
=======================
Anonymisierer für ISO 20022 XML-Nachrichten
(camt.054/057, pacs.002/008/009/010).
"""

import logging
import re
import sys
from typing import List, Optional, Tuple

from lxml import etree

from ..config import Config
from .base import BaseAnonymizer

logger = logging.getLogger(__name__)


class ISO20022Anonymizer(BaseAnonymizer):
    """Anonymisierer für ISO 20022 XML-Nachrichten."""

    NAMESPACES = {
        'camt054': 'urn:iso:std:iso:20022:tech:xsd:camt.054.001.08',
        'camt057': 'urn:iso:std:iso:20022:tech:xsd:camt.057.001.06',
        'pacs002': 'urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10',
        'pacs008': 'urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08',
        'pacs009': 'urn:iso:std:iso:20022:tech:xsd:pacs.009.001.08',
        'pacs010': 'urn:iso:std:iso:20022:tech:xsd:pacs.010.001.03',
    }

    FIELDS_TO_ANONYMIZE = {
        'name_fields': [
            './/Nm',
            './/CtctDtls/Nm',
        ],
        'address_fields': [
            './/StrtNm',
            './/BldgNb',
            './/PstCd',
            './/TwnNm',
            './/AdrLine',
            './/Ctry',
        ],
        'iban_fields': [
            './/IBAN',
        ],
        'bic_fields': [
            './/BIC',
            './/BICFI',
        ],
        'remittance_fields': [
            './/Ustrd',
            './/AddtlRmtInf',
            './/AddtlTxInf',
        ],
        'contact_fields': [
            './/EmailAdr',
            './/PhneNb',
            './/MobNb',
            './/FaxNb',
        ],
        'private_id_fields': [
            './/PrvtId/Othr/Id',
            './/PrvtId/DtAndPlcOfBirth/BirthDt',
            './/PrvtId/DtAndPlcOfBirth/CityOfBirth',
        ],
    }

    # XPath-Teilstring → id_type für PrivateIDFieldAnonymizer
    _PRIVATE_ID_TYPE_MAP = {
        'BirthDt':     'birth_date',
        'CityOfBirth': 'birth_city',
    }

    # XML-Tag → contact_type für ContactFieldAnonymizer
    _CONTACT_TYPE_MAP = {
        'EmailAdr': 'email',
        'PhneNb':   'phone',
        'MobNb':    'phone',
        'FaxNb':    'phone',
    }

    def __init__(self, config: Config):
        super().__init__(config)

    # -------------------------------------------------------------------------
    # Namespace- / Nachrichtentyp-Erkennung
    # -------------------------------------------------------------------------

    def _detect_namespace(self, root: etree._Element) -> Optional[str]:
        """Erkennt den Namespace der XML-Nachricht."""
        nsmap = root.nsmap

        if None in nsmap:
            ns = nsmap[None]
            if 'iso:std:iso:20022' in ns:
                return ns

        root_local = etree.QName(root.tag).localname
        if root_local == 'DataPDU':
            for elem in root.iter():
                local_name = etree.QName(elem.tag).localname
                if local_name == 'Document':
                    doc_ns = elem.nsmap.get(None)
                    if doc_ns and 'iso:std:iso:20022' in doc_ns:
                        return doc_ns
            for elem in root.iter():
                local_name = etree.QName(elem.tag).localname
                if local_name == 'AppHdr':
                    hdr_ns = elem.nsmap.get(None)
                    if hdr_ns and 'iso:std:iso:20022' in hdr_ns:
                        return hdr_ns

        for ns in nsmap.values():
            if 'iso:std:iso:20022' in ns:
                return ns

        return None

    def _detect_message_type(self, namespace: str) -> str:
        """Erkennt den Nachrichtentyp aus dem Namespace."""
        if not namespace:
            return "UNKNOWN"
        match = re.search(r'xsd:([a-z]+\.\d+)', namespace)
        if match:
            return match.group(1)
        return "UNKNOWN"

    # -------------------------------------------------------------------------
    # Anonymisierung
    # -------------------------------------------------------------------------

    def anonymize(self, content: str) -> Tuple[str, int]:
        """Anonymisiert eine ISO 20022 XML-Nachricht."""
        self.fields_anonymized = 0

        try:
            root = etree.fromstring(content.encode('utf-8'))
            namespace = self._detect_namespace(root)
            ns_map = {'ns': namespace} if namespace else {}

            def find_elements(xpath_expr: str):
                """Findet Elemente mit oder ohne Namespace."""
                if namespace:
                    if xpath_expr.startswith('.//'):
                        elem_path = xpath_expr[3:]
                        if '/' in elem_path:
                            parts = elem_path.split('/')
                            local_xpath = './/' + '/'.join(
                                [f"*[local-name()='{p}']" for p in parts]
                            )
                        else:
                            local_xpath = f".//*[local-name()='{elem_path}']"
                        return root.xpath(local_xpath)
                    else:
                        ns_xpath = xpath_expr.replace('.//', './/ns:')
                        return root.xpath(ns_xpath, namespaces=ns_map)
                return root.xpath(xpath_expr)

            # --- Namen ---
            if self.name_anonymizer.is_enabled:
                for xpath in self.FIELDS_TO_ANONYMIZE['name_fields']:
                    for elem in find_elements(xpath):
                        if elem.text:
                            elem.text = self.name_anonymizer.anonymize(elem.text)
                            self.fields_anonymized += 1

            # --- IBANs ---
            if self.iban_anonymizer.is_enabled:
                for xpath in self.FIELDS_TO_ANONYMIZE['iban_fields']:
                    for elem in find_elements(xpath):
                        if elem.text:
                            elem.text = self.iban_anonymizer.anonymize(elem.text)
                            self.fields_anonymized += 1

            # --- BICs ---
            if self.bic_anonymizer.is_enabled:
                for xpath in self.FIELDS_TO_ANONYMIZE['bic_fields']:
                    for elem in find_elements(xpath):
                        if elem.text:
                            elem.text = self.bic_anonymizer.anonymize(elem.text)
                            self.fields_anonymized += 1

            # --- Adressen ---
            if self.address_anonymizer.is_enabled:
                simple_address_fields = [
                    ('.//StrtNm', 'street'),
                    ('.//PstCd',  'postal'),
                    ('.//TwnNm',  'city'),
                    ('.//Ctry',   'country'),
                ]
                for xpath, field_type in simple_address_fields:
                    for elem in find_elements(xpath):
                        if elem.text:
                            elem.text = self.address_anonymizer.anonymize(
                                elem.text,
                                field_type=field_type,
                                counter=self.fields_anonymized
                            )
                            self.fields_anonymized += 1

                for elem in find_elements('.//AdrLine'):
                    if elem.text:
                        elem.text = self.address_anonymizer.anonymize_line(elem.text)
                        self.fields_anonymized += 1

            # --- Verwendungszweck ---
            if self.remittance_anonymizer.is_enabled:
                for xpath in self.FIELDS_TO_ANONYMIZE['remittance_fields']:
                    for elem in find_elements(xpath):
                        if elem.text:
                            elem.text = self.remittance_anonymizer.anonymize(elem.text)
                            self.fields_anonymized += 1

            # --- Kontaktdaten ---
            if self.contact_anonymizer.is_enabled:
                for xpath in self.FIELDS_TO_ANONYMIZE['contact_fields']:
                    tag_name = xpath.lstrip('./')
                    contact_type = self._CONTACT_TYPE_MAP.get(tag_name, 'generic')
                    for elem in find_elements(xpath):
                        if elem.text:
                            elem.text = self.contact_anonymizer.anonymize(
                                elem.text,
                                contact_type=contact_type,
                                counter=self.fields_anonymized
                            )
                            self.fields_anonymized += 1

            # --- Private IDs (immer anonymisieren) ---
            for xpath in self.FIELDS_TO_ANONYMIZE['private_id_fields']:
                id_type = next(
                    (v for k, v in self._PRIVATE_ID_TYPE_MAP.items() if k in xpath),
                    'generic'
                )
                for elem in find_elements(xpath):
                    if elem.text:
                        elem.text = self.private_id_anonymizer.anonymize(
                            elem.text,
                            id_type=id_type,
                            counter=self.fields_anonymized
                        )
                        self.fields_anonymized += 1

            xml_bytes = etree.tostring(
                root,
                encoding='UTF-8',
                pretty_print=True,
                xml_declaration=True
            )
            return xml_bytes.decode('utf-8'), self.fields_anonymized

        except etree.XMLSyntaxError as e:
            logger.error(f"XML Parse-Fehler: {e}")
            raise

    # -------------------------------------------------------------------------
    # Validierung
    # -------------------------------------------------------------------------

    # Pflichtfelder pro Nachrichtentyp für die strukturelle Fallback-Validierung.
    # Jeder Eintrag: (local-name des Root-Childs, [erforderliche Child-Tags])
    _REQUIRED_ELEMENTS = {
        'camt.054': ('BkToCstmrDbtCdtNtfctn', ['GrpHdr', 'Ntfctn']),
        'camt.057': ('NtfctnToRcv',            ['GrpHdr', 'Ntfctn']),
        'pacs.002': ('FIToFIPmtStsRpt',         ['GrpHdr', 'TxInfAndSts']),
        'pacs.008': ('FIToFICstmrCdtTrf',       ['GrpHdr', 'CdtTrfTxInf']),
        'pacs.009': ('FinInstnCdtTrf',           ['GrpHdr', 'CdtTrfTxInf']),
        'pacs.010': ('FinInstnDrctDbt',          ['GrpHdr', 'DrctDbtTxInf']),
    }

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validiert eine ISO 20022 Nachricht.

        Strategie
        ---------
        Python >= 3.10  Schema-Validierung via pyiso20022 / xsdata.
        Python <  3.10  Strukturelle Fallback-Validierung via lxml –
                        pyiso20022/xsdata werden auf diesen Versionen nicht
                        aufgerufen, da sie intern ``kw_only=True`` in
                        ``@dataclass`` verwenden (erst ab Python 3.10 gültig).

        Der ``kw_only``-TypeError landet in keinem Fall als Fehlermeldung
        in ``validation_errors``.  Tritt er trotzdem auf (z.B. durch eine
        inkompatible Bibliotheksversion), wird er als WARNING geloggt und
        die strukturelle Validierung übernimmt automatisch.
        """
        errors: List[str] = []

        try:
            root      = etree.fromstring(content.encode('utf-8'))
            namespace = self._detect_namespace(root)
            msg_type  = self._detect_message_type(namespace)

            # ── Schritt 1: Python-Version prüfen ─────────────────────────────
            if sys.version_info < (3, 10):
                logger.info(
                    "Python %d.%d erkannt – strukturelle ISO-20022-Validierung "
                    "(pyiso20022 erfordert Python 3.10+).",
                    *sys.version_info[:2]
                )
                errors.extend(self._validate_structural(root, namespace, msg_type))
                return len(errors) == 0, errors

            # ── Schritt 2: pyiso20022 / xsdata (Python >= 3.10) ──────────────
            try:
                from xsdata.formats.dataclass.parsers import XmlParser
                from xsdata.formats.dataclass.parsers.config import ParserConfig

                parser         = XmlParser(
                    config=ParserConfig(fail_on_unknown_properties=False)
                )
                document_class = self._get_document_class(msg_type)

                if document_class:
                    parser.from_string(content, document_class)
                    logger.info("Schema-Validierung erfolgreich für %s.", msg_type)
                else:
                    errors.append(
                        f"Kein pyiso20022-Schema für Nachrichtentyp "
                        f"'{msg_type}' verfügbar."
                    )

            except ImportError as e:
                # pyiso20022 / xsdata nicht installiert → struktureller Fallback
                logger.warning(
                    "pyiso20022/xsdata nicht installiert (%s) – "
                    "strukturelle Validierung als Fallback.",
                    e
                )
                errors.extend(self._validate_structural(root, namespace, msg_type))

            except TypeError as e:
                # Sicherheitsnetz: kw_only-Fehler trotz Python >= 3.10
                # (z.B. inkompatible xsdata-Version) → kein INVALID, kein
                # kw_only im Log → struktureller Fallback übernimmt.
                if 'kw_only' in str(e):
                    logger.warning(
                        "pyiso20022 nicht kompatibel (kw_only) – "
                        "strukturelle Validierung als Fallback."
                    )
                    errors.extend(
                        self._validate_structural(root, namespace, msg_type)
                    )
                else:
                    errors.append(f"TypeError bei Schema-Validierung: {e}")

            except Exception as e:
                errors.append(f"Schema-Validierungsfehler: {e}")

            return len(errors) == 0, errors

        except etree.XMLSyntaxError as e:
            errors.append(f"XML-Syntaxfehler: {str(e)}")
            return False, errors

    def _validate_structural(self, root: etree._Element,
                              namespace: Optional[str],
                              msg_type: str) -> List[str]:
        """
        Strukturelle Fallback-Validierung ohne externe Bibliotheken (Python 3.8+).

        Prüft:
        1. ISO 20022-Namespace vorhanden und erkannt
        2. Nachrichtentyp bekannt
        3. Pflicht-Child-Elemente des Document-Knotens vorhanden
        4. GrpHdr enthält MsgId und CreDtTm
        5. Mindestens eine IBAN oder BICFI vorhanden (Plausibilität)
        """
        errors: List[str] = []

        # 1. Namespace
        if not namespace:
            errors.append(
                "Kein ISO 20022-Namespace gefunden. "
                "Erwartet: urn:iso:std:iso:20022:tech:xsd:..."
            )
            return errors

        # 2. Bekannter Nachrichtentyp
        base_type = next(
            (k for k in self._REQUIRED_ELEMENTS if msg_type.startswith(k)),
            None
        )
        if not base_type:
            errors.append(
                f"Unbekannter Nachrichtentyp '{msg_type}'. "
                f"Unterstützt: {', '.join(self._REQUIRED_ELEMENTS)}"
            )
            return errors

        root_child_name, required_tags = self._REQUIRED_ELEMENTS[base_type]

        # 3. Pflicht-Child-Elemente
        def find_local(tag: str) -> List[etree._Element]:
            return root.xpath(f".//*[local-name()='{tag}']")

        missing_root = find_local(root_child_name)
        if not missing_root:
            errors.append(
                f"Fehlendes Root-Element <{root_child_name}> "
                f"für Nachrichtentyp {msg_type}."
            )

        for tag in required_tags:
            if not find_local(tag):
                errors.append(f"Fehlendes Pflicht-Element <{tag}>.")

        # 4. GrpHdr: MsgId und CreDtTm
        grp_hdr_elems = find_local('GrpHdr')
        if grp_hdr_elems:
            grp_hdr = grp_hdr_elems[0]
            for required in ('MsgId', 'CreDtTm'):
                if not grp_hdr.xpath(f".//*[local-name()='{required}']"):
                    errors.append(f"<GrpHdr> fehlt Pflichtfeld <{required}>.")
        else:
            # Bereits in Schritt 3 gemeldet – hier nicht doppelt
            pass

        # 5. Mindestens eine IBAN oder BICFI (Plausibilität)
        has_iban  = bool(find_local('IBAN'))
        has_bicfi = bool(find_local('BICFI') or find_local('BIC'))
        if not has_iban and not has_bicfi:
            errors.append(
                "Weder <IBAN> noch <BICFI>/<BIC> gefunden – "
                "Nachricht scheint unvollständig."
            )

        if not errors:
            logger.info(
                "Strukturelle Validierung erfolgreich für %s "
                "(Fallback, kein pyiso20022-Schema).",
                msg_type
            )

        return errors

    def _get_document_class(self, msg_type: str):
        """Gibt die passende Document-Klasse für den Nachrichtentyp zurück."""
        try:
            if msg_type.startswith('camt.054'):
                from pyiso20022.camt.camt_054_001_08 import Document
                return Document
            elif msg_type.startswith('camt.057'):
                from pyiso20022.camt.camt_057_001_06 import Document
                return Document
            elif msg_type.startswith('pacs.002'):
                from pyiso20022.pacs.pacs_002_001_10 import Document
                return Document
            elif msg_type.startswith('pacs.008'):
                from pyiso20022.pacs.pacs_008_001_08 import Document
                return Document
            elif msg_type.startswith('pacs.009'):
                from pyiso20022.pacs.pacs_009_001_08 import Document
                return Document
            elif msg_type.startswith('pacs.010'):
                from pyiso20022.pacs.pacs_010_001_03 import Document
                return Document
        except ImportError:
            pass
        return None

    def extract_message_id(self, content: str) -> str:
        """
        Extrahiert die MsgId aus dem GrpHdr-Element.

        Die MsgId ist der eindeutige technische Bezeichner einer ISO-20022-
        Nachricht und wird nicht anonymisiert.
        Enthält die Nachricht mehrere GrpHdr-Elemente (z.B. AppHdr + Document),
        wird der erste gefundene Wert zurückgegeben.
        """
        try:
            root  = etree.fromstring(content.encode('utf-8'))
            elems = root.xpath(
                ".//*[local-name()='GrpHdr']/*[local-name()='MsgId']"
            )
            if elems and elems[0].text:
                return elems[0].text.strip()
        except Exception as e:
            logger.debug("MsgId konnte nicht extrahiert werden: %s", e)
        return ""
