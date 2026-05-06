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
        'camt019': 'http://www.six-interbank-clearing.com/de/camt.019.001.07.ch.02',
        'camt052': 'urn:iso:std:iso:20022:tech:xsd:camt.052.001.08',
        'camt053': 'urn:iso:std:iso:20022:tech:xsd:camt.053.001.08',
        'camt054': 'urn:iso:std:iso:20022:tech:xsd:camt.054.001.08',
        'camt057': 'urn:iso:std:iso:20022:tech:xsd:camt.057.001.06',        
        'pain001': 'urn:iso:std:iso:20022:tech:xsd:pain.001.001.09',
        'pain009': 'urn:iso:std:iso:20022:tech:xsd:pain.009.001.07',
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

    _PRIVATE_ID_TYPE_MAP = {
        'BirthDt':     'birth_date',
        'CityOfBirth': 'birth_city',
    }

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
        """
        Erkennt den ISO-20022-Namespace anhand des <Document>-Tags.

        Strategie: direkt nach dem <Document>-Element suchen und dessen
        Namespace zurueckgeben. Das ist die zuverlaessigste Methode, da
        alle ISO-20022-Nachrichten den Nachrichtentyp-Namespace auf dem
        <Document>-Element deklarieren – unabhaengig von umgebenden
        Wrapper-Elementen (SAA DataPDU, BBkICF Bulk, AppHdr etc.).

        Fallback fuer Nachrichten ohne <Document>-Element:
        Alle Kind-Elemente werden nach einem Namespace durchsucht der
        einen bekannten Nachrichtentyp enthaelt (xsd: oder Swiss SIX).
        """
        # Direkt nach <Document>-Element suchen (max. 200 Elemente)
        # Deckt alle Strukturen ab:
        #   Standard:   <Document xmlns="...xsd:camt.053...">
        #   SAA:        <DataPDU><Body><Document xmlns="...xsd:camt.053...">
        #   BBkICF:     <BBkICF:BBkICFBlkCdtTrf>...<Document xmlns="...xsd:pacs.008...">
        for i, elem in enumerate(root.iter()):
            if i >= 200:
                break
            local = etree.QName(elem.tag).localname
            if local == 'Document':
                # Default-Namespace des Document-Elements zurueckgeben
                ns = elem.nsmap.get(None) or etree.QName(elem.tag).namespace
                if ns:
                    logger.debug(
                        "Namespace via <Document>-Element gefunden "
                        "(Element %d): %s", i, ns
                    )
                    return ns

        # Fallback: Nachrichten ohne <Document>-Wrapper
        # z.B. Swiss SIX camt.019 mit <GetCcltnStsReq> als Root
        # oder SEPA Bulk wo FIToFICstmrCdtTrf den Namespace traegt
        logger.debug(
            "Kein <Document>-Element gefunden – "
            "suche Namespace in Kind-Elementen (Fallback)."
        )
        for i, elem in enumerate(root.iter()):
            if i >= 200:
                break
            for ns in (elem.nsmap or {}).values():
                if not ns:
                    continue
                # Akzeptiere nur Nachrichten-Namespaces:
                # Standard/SEPA Bulk: muss xsd: enthalten (schließt head: aus)
                # Swiss SIX:          six-interbank-clearing.com
                if ('tech:xsd:' in ns or
                        'six-interbank-clearing.com' in ns):
                    logger.debug(
                        "Namespace via Fallback in Element %d gefunden: %s",
                        i, ns
                    )
                    return ns

        logger.warning(
            "ISO-20022-Namespace nicht gefunden. "
            "Root-Tag: %s, nsmap: %s",
            root.tag, root.nsmap
        )
        return None

    def _detect_message_type(self, namespace: str) -> str:
        """
        Erkennt den Nachrichtentyp aus dem Namespace.

        Unterstützte Namespace-Formate:
        Standard:  urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08
        SEPA Bulk: urn:iso:std:iso:20022:tech:xsd:sct:pacs.008.001.08
                                                   ^^^^
                   Optionales Infix (sct:, cbpr:, fi: etc.) wird übersprungen.
        """
        if not namespace:
            return "UNKNOWN"
        # Unterstuetzte Namespace-Formate:
        # Standard:   urn:iso:std:iso:20022:tech:xsd:camt.019.001.07
        # SEPA Bulk:  urn:iso:std:iso:20022:tech:xsd:sct:pacs.008.001.08
        # Swiss SIX:  http://www.six-interbank-clearing.com/de/camt.019.001.07.ch.02
        match = re.search(
            r'(?:xsd:|/de/)(?:[a-z]+:)?([a-z]+\.\d+)', namespace
        )
        if match:
            return match.group(1)
        return "UNKNOWN"

    # -------------------------------------------------------------------------
    # Anonymisierung
    # -------------------------------------------------------------------------

    PARTY_GROUPS = [
        ('Dbtr',       'DbtrAcct',       'DbtrAgt'),
        ('Cdtr',       'CdtrAcct',       'CdtrAgt'),
        ('InitgPty',   None,             None),
        ('UltmtDbtr',  None,             None),
        ('UltmtCdtr',  None,             None),
        ('IntrmyAgt1', 'IntrmyAgt1Acct', None),
        ('IntrmyAgt2', 'IntrmyAgt2Acct', None),
        ('IntrmyAgt3', 'IntrmyAgt3Acct', None),
        ('InstgAgt',   None,             None),
        ('InstdAgt',   None,             None),
    ]

    def _anonymize_party_group(self, party_elem: etree._Element,
                                account_elem: Optional[etree._Element],
                                agent_elem:   Optional[etree._Element],
                                processed_ids: set) -> None:
        """
        Anonymisiert alle Felder einer Partei mit einer einzigen Entitaet.
        """
        name_elems = party_elem.xpath(".//*[local-name()='Nm']")
        fin_names  = party_elem.xpath(
            ".//*[local-name()='FinInstnId']/*[local-name()='Nm']"
        )

        original_name = None
        if name_elems and name_elems[0].text and name_elems[0].text.strip():
            original_name = name_elems[0].text.strip()

        has_prvt_id = bool(party_elem.xpath(".//*[local-name()='PrvtId']"))
        has_org_id  = bool(party_elem.xpath(".//*[local-name()='OrgId']"))

        if has_prvt_id:
            is_company = False
        elif has_org_id or bool(fin_names):
            is_company = True
        else:
            is_company = (
                original_name is not None
                and self.name_anonymizer._is_company(original_name)
            )

        if original_name:
            entity = self.config.get_or_assign_entity(original_name, is_company)
        else:
            entity = self.config.get_next_entity()

        if self.name_anonymizer.is_enabled:
            for nm_elem in name_elems:
                if nm_elem.text and nm_elem.text.strip():
                    nm_elem.text = self.name_anonymizer.anonymize_with_entity(
                        nm_elem.text.strip(), entity, is_company
                    )
                    processed_ids.add(id(nm_elem))
                    self.fields_anonymized += 1

        if self.address_anonymizer.is_enabled:
            for tag, ft in [('StrtNm', 'street'), ('PstCd', 'postal'),
                             ('TwnNm', 'city'), ('Ctry', 'country')]:
                for elem in party_elem.xpath(f".//*[local-name()='{tag}']"):
                    if elem.text:
                        elem.text = self.address_anonymizer.anonymize_with_entity(
                            elem.text, entity, field_type=ft
                        )
                        processed_ids.add(id(elem))
                        self.fields_anonymized += 1
            for elem in party_elem.xpath(".//*[local-name()='AdrLine']"):
                if elem.text:
                    elem.text = self.address_anonymizer.anonymize_line_with_entity(
                        elem.text, entity
                    )
                    processed_ids.add(id(elem))
                    self.fields_anonymized += 1

        if self.contact_anonymizer.is_enabled:
            for tag, ct in self._CONTACT_TYPE_MAP.items():
                for elem in party_elem.xpath(f".//*[local-name()='{tag}']"):
                    if elem.text:
                        elem.text = self.contact_anonymizer.anonymize_with_entity(
                            elem.text, entity, contact_type=ct
                        )
                        processed_ids.add(id(elem))
                        self.fields_anonymized += 1

        if account_elem is not None and self.iban_anonymizer.is_enabled:
            for elem in account_elem.xpath(".//*[local-name()='IBAN']"):
                if elem.text:
                    elem.text = self.iban_anonymizer.anonymize_with_entity(
                        elem.text, entity
                    )
                    processed_ids.add(id(elem))
                    self.fields_anonymized += 1

        if agent_elem is not None and self.bic_anonymizer.is_enabled:
            for bic_tag in ('BICFI', 'BIC'):
                for elem in agent_elem.xpath(f".//*[local-name()='{bic_tag}']"):
                    if elem.text:
                        elem.text = self.bic_anonymizer.anonymize_with_entity(
                            elem.text, entity
                        )
                        processed_ids.add(id(elem))
                        self.fields_anonymized += 1

    def anonymize(self, content: str) -> Tuple[str, int]:
        """
        Anonymisiert eine ISO 20022 XML-Nachricht.

        Verarbeitungsreihenfolge
        -----------------------
        Schritt 1 - Partei-weise: Jede Partei wird komplett verarbeitet.
        Schritt 2 - Dokument-weise: Restfelder ohne Partei-Kontext.
        Schritt 3 - Header-Modifikationen: BIC-Replacements, SAA-Sender,
                    Service-Bezeichner.
        """
        self.fields_anonymized = 0
        processed_ids: set = set()

        try:
            root = etree.fromstring(content.encode('utf-8'))

            def by_local_name(tag: str):
                return root.xpath(f".//*[local-name()='{tag}']")

            # Schritt 1: Partei-weise
            for party_tag, account_tag, agent_tag in self.PARTY_GROUPS:
                for party_elem in by_local_name(party_tag):
                    parent = party_elem.getparent()
                    account_elem = None
                    agent_elem   = None

                    if account_tag and parent is not None:
                        res = parent.xpath(f"*[local-name()='{account_tag}']")
                        account_elem = res[0] if res else None

                    if agent_tag and parent is not None:
                        res = parent.xpath(f"*[local-name()='{agent_tag}']")
                        agent_elem = res[0] if res else None

                    self._anonymize_party_group(
                        party_elem, account_elem, agent_elem, processed_ids
                    )

            # Schritt 2: Dokument-weite Restfelder

            if self.iban_anonymizer.is_enabled:
                for elem in by_local_name('IBAN'):
                    if id(elem) not in processed_ids and elem.text:
                        elem.text = self.iban_anonymizer.anonymize(elem.text)
                        self.fields_anonymized += 1

            if self.bic_anonymizer.is_enabled:
                for bic_tag in ('BIC', 'BICFI'):
                    for elem in by_local_name(bic_tag):
                        if id(elem) not in processed_ids and elem.text:
                            elem.text = self.bic_anonymizer.anonymize(elem.text)
                            self.fields_anonymized += 1

            if self.name_anonymizer.is_enabled:
                for elem in by_local_name('Nm'):
                    if id(elem) not in processed_ids and elem.text:
                        elem.text = self.name_anonymizer.anonymize(elem.text)
                        self.fields_anonymized += 1

            if self.remittance_anonymizer.is_enabled:
                for tag in ('Ustrd', 'AddtlRmtInf', 'AddtlTxInf'):
                    for elem in by_local_name(tag):
                        if elem.text:
                            elem.text = self.remittance_anonymizer.anonymize(elem.text)
                            self.fields_anonymized += 1

            if self.contact_anonymizer.is_enabled:
                for tag, ct in self._CONTACT_TYPE_MAP.items():
                    for elem in by_local_name(tag):
                        if id(elem) not in processed_ids and elem.text:
                            elem.text = self.contact_anonymizer.anonymize(
                                elem.text, contact_type=ct,
                                counter=self.fields_anonymized
                            )
                            self.fields_anonymized += 1

            for elem in by_local_name('BirthDt'):
                if elem.text:
                    elem.text = self.private_id_anonymizer.anonymize(
                        elem.text, id_type='birth_date',
                        counter=self.fields_anonymized
                    )
                    self.fields_anonymized += 1

            for elem in by_local_name('CityOfBirth'):
                if elem.text:
                    elem.text = self.private_id_anonymizer.anonymize(
                        elem.text, id_type='birth_city',
                        counter=self.fields_anonymized
                    )
                    self.fields_anonymized += 1

            for elem in root.xpath(
                ".//*[local-name()='PrvtId']"
                "/*[local-name()='Othr']"
                "/*[local-name()='Id']"
            ):
                if elem.text:
                    elem.text = self.private_id_anonymizer.anonymize(
                        elem.text, id_type='generic',
                        counter=self.fields_anonymized
                    )
                    self.fields_anonymized += 1

            # Schritt 3: Header-Modifikationen
            self.fields_anonymized += self._replace_grphdr_bic(root, processed_ids)
            self.fields_anonymized += self._replace_saa_sender(root, processed_ids)
            self._replace_service_indicators(root)

            xml_str = etree.tostring(root, encoding='unicode', pretty_print=True)
            result  = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str
            return result, self.fields_anonymized

        except etree.XMLSyntaxError as e:
            logger.error(f"XML Parse-Fehler: {e}")
            raise

    # -------------------------------------------------------------------------
    # Header-Modifikationen
    # -------------------------------------------------------------------------

    def _replace_grphdr_bic(self, root: etree._Element,
                             processed_ids: set) -> int:
        """
        Ersetzt BICFI/BIC-Werte im gesamten Dokument anhand der
        bic_replacements-Liste.

        Erfasst alle Elemente mit local-name BICFI oder BIC - unabhaengig
        vom uebergeordneten Element (GrpHdr, AppHdr, InstgAgt, DbtrAgt, ...).
        Bereits in Schritt 1 verarbeitete Elemente werden ueberspungen
        (processed_ids-Pruefung).

        Der from-Wert wird als 8-Zeichen-Praefix geprueft, damit BIC8 und
        BIC11 gleichermassen erfasst werden. Der Branch-Code (Pos. 9-11)
        bleibt bei BIC11 erhalten.
        """
        if not self.config.grphdr_bic_enabled:
            return 0

        replacements = self.config.grphdr_bic_replacements
        if not replacements:
            logger.warning(
                "grphdr_bic aktiviert aber keine bic_replacements konfiguriert."
            )
            return 0

        def apply_specific_replacements(bic_value: str) -> Optional[str]:
            bic_upper = bic_value.strip().upper()
            for mapping in replacements:
                from_bic = mapping.get('from', '').upper()
                to_bic   = mapping.get('to', '')
                if not from_bic or not to_bic:
                    continue
                if bic_upper[:8] == from_bic[:8]:
                    branch = bic_upper[8:] if len(bic_upper) > 8 else ''
                    return to_bic[:8] + branch
            return None

        count = 0

        # Alle BICFI / BIC Elemente im gesamten Dokument
        for bic_tag in ('BICFI', 'BIC'):
            for elem in root.xpath(f".//*[local-name()='{bic_tag}']"):
                if not elem.text or not elem.text.strip():
                    continue
                original = elem.text.strip()
                new_bic  = apply_specific_replacements(original)
                if new_bic is not None:
                    logger.debug(
                        "[BIC_REPLACEMENT] alt wert=%s   neuer wert=%s",
                        original, new_bic
                    )
                    elem.text = new_bic
                    processed_ids.add(id(elem))
                    count += 1

        # BBkICF:SndgInst (SEPA Bulk Header)
        for sndg_inst in root.xpath(".//*[local-name()='SndgInst']"):
            ns = etree.QName(sndg_inst.tag).namespace or ''
            if 'BBkICF' not in ns and 'bulkpayment' not in ns.lower():
                continue
            if not sndg_inst.text or not sndg_inst.text.strip():
                continue
            original = sndg_inst.text.strip()
            new_bic  = apply_specific_replacements(original)
            if new_bic is not None:
                logger.debug(
                    "[BBKICF_SNDGINST] alt wert=%s   neuer wert=%s",
                    original, new_bic
                )
                sndg_inst.text = new_bic
                processed_ids.add(id(sndg_inst))
                count += 1

        return count

    def _replace_saa_sender(self, root: etree._Element,
                             processed_ids: set) -> int:
        """
        Ersetzt BIC-Werte im SAA-Sender-Block.

        Verarbeitet zwei Felder innerhalb von <Saa:Sender>:

        <Saa:X1>BANKLULLXXX</Saa:X1>
            Enthaelt den BIC direkt - wird ueber bic_replacements ersetzt.

        <Saa:DN>ou=xxx,o=banklull,o=swift</Saa:DN>
            Enthaelt den BIC als Teil eines DN-Strings (kleingeschrieben).
            Ersetzung als Teilstring: o=banklull -> o=banklul0.
        """
        if not self.config.grphdr_bic_enabled:
            return 0

        replacements = self.config.grphdr_bic_replacements
        if not replacements:
            return 0

        count = 0

        for sender in root.xpath(".//*[local-name()='Sender']"):

            # Saa:X1 - direkter BIC-Wert
            for x1 in sender.xpath(".//*[local-name()='X1']"):
                if id(x1) in processed_ids:
                    continue
                if not x1.text or not x1.text.strip():
                    continue
                original  = x1.text.strip()
                bic_upper = original.upper()
                for mapping in replacements:
                    from_bic = mapping.get('from', '').upper()
                    to_bic   = mapping.get('to', '')
                    if not from_bic or not to_bic:
                        continue
                    if bic_upper[:8] == from_bic[:8]:
                        branch  = bic_upper[8:] if len(bic_upper) > 8 else ''
                        new_bic = to_bic[:8] + branch
                        logger.debug(
                            "[SAA_X1] alt wert=%s   neuer wert=%s",
                            original, new_bic
                        )
                        x1.text = new_bic
                        processed_ids.add(id(x1))
                        count += 1
                        break

            # Saa:DN - BIC als Teilstring im Distinguished Name
            # Format: ou=xxx,o=banklull,o=swift
            for dn in sender.xpath(".//*[local-name()='DN']"):
                if id(dn) in processed_ids:
                    continue
                if not dn.text or not dn.text.strip():
                    continue
                original = dn.text
                modified = original
                for mapping in replacements:
                    from_bic    = mapping.get('from', '').lower()
                    to_bic      = mapping.get('to', '').lower()
                    if not from_bic or not to_bic:
                        continue
                    from_prefix = from_bic[:8]
                    to_prefix   = to_bic[:8]
                    pattern = re.compile(
                        rf'(o=){re.escape(from_prefix)}', re.IGNORECASE
                    )
                    if pattern.search(modified):
                        modified = pattern.sub(
                            lambda m: m.group(1) + to_prefix, modified
                        )
                        logger.debug(
                            "[SAA_DN] alt wert=%s   neuer wert=%s",
                            original.strip(), modified.strip()
                        )

                if modified != original:
                    dn.text = modified
                    processed_ids.add(id(dn))
                    count += 1

        return count

    def _replace_service_indicators(self, root: etree._Element) -> int:
        """
        Ersetzt Service-Bezeichner fuer Test-Umgebungen.

        SWIFT MX: <Saa:Service> im DataPDU-Envelope
            prod_value -> test_value
        SEPA: <Svc> im AppHdr
            prod_value -> test_value
        """
        count = 0

        if self.config.swift_mx_service_enabled:
            prod = self.config.swift_mx_service_prod
            test = self.config.swift_mx_service_test
            if not prod:
                logger.warning(
                    "swift_mx service_replacement aktiviert aber prod_value leer."
                )
            else:
                # Saa:Service - local-name() gibt 'Service' zurueck
                # (Saa: ist Namespace-Praefix, kein Teil des Tag-Namens)
                for elem in root.xpath(".//*[local-name()='Service']"):
                    if elem.text and prod in elem.text:
                        logger.debug(
                            "[SERVICE_MX] alt wert=%s   neuer wert=%s",
                            elem.text.strip(),
                            elem.text.replace(prod, test).strip()
                        )
                        elem.text = elem.text.replace(prod, test)
                        count += 1

        if self.config.sepa_service_enabled:
            prod = self.config.sepa_service_prod
            test = self.config.sepa_service_test
            if not prod:
                logger.warning(
                    "sepa service_replacement aktiviert aber prod_value leer."
                )
            else:
                for apphdr in root.xpath(".//*[local-name()='AppHdr']"):
                    for svc in apphdr.xpath(".//*[local-name()='Svc']"):
                        if svc.text and prod in svc.text:
                            logger.debug(
                                "[SERVICE_SEPA] alt wert=%s   neuer wert=%s",
                                svc.text.strip(),
                                svc.text.replace(prod, test).strip()
                            )
                            svc.text = svc.text.replace(prod, test)
                            count += 1

        return count

    # -------------------------------------------------------------------------
    # Validierung
    # -------------------------------------------------------------------------

    _REQUIRED_ELEMENTS = {
        'camt.019': ('GetCcltnStsReq',            ['Assgnmt', 'Undrlyg']),
        'camt.052': ('BkToCstmrAcctRpt',          ['GrpHdr', 'Rpt']),
        'camt.053': ('BkToCstmrStmt',             ['GrpHdr', 'Stmt']),
        'camt.054': ('BkToCstmrDbtCdtNtfctn',    ['GrpHdr', 'Ntfctn']),
        'camt.057': ('NtfctnToRcv',               ['GrpHdr', 'Ntfctn']),
        'pain.001': ('CstmrCdtTrfInitn',           ['GrpHdr', 'PmtInf']),
        'pain.009': ('MndtInitnReq',               ['GrpHdr', 'Mndt']),
        'pacs.002': ('FIToFIPmtStsRpt',            ['GrpHdr', 'TxInfAndSts']),
        'pacs.008': ('FIToFICstmrCdtTrf',          ['GrpHdr', 'CdtTrfTxInf']),
        'pacs.009': ('FinInstnCdtTrf',              ['GrpHdr', 'CdtTrfTxInf']),
        'pacs.010': ('FinInstnDrctDbt',             ['GrpHdr', 'DrctDbtTxInf']),
    }

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validiert eine ISO 20022 Nachricht.

        Python >= 3.10: Schema-Validierung via pyiso20022 / xsdata.
        Python <  3.10: Strukturelle Fallback-Validierung via lxml.
        """
        errors: List[str] = []

        try:
            root      = etree.fromstring(content.encode('utf-8'))
            namespace = self._detect_namespace(root)
            msg_type  = self._detect_message_type(namespace)

            if sys.version_info < (3, 10):
                logger.info(
                    "Python %d.%d erkannt - strukturelle ISO-20022-Validierung "
                    "(pyiso20022 erfordert Python 3.10+).",
                    *sys.version_info[:2]
                )
                errors.extend(self._validate_structural(root, namespace, msg_type))
                return len(errors) == 0, errors

            try:
                from xsdata.formats.dataclass.parsers import XmlParser
                from xsdata.formats.dataclass.parsers.config import ParserConfig

                parser         = XmlParser(
                    config=ParserConfig(fail_on_unknown_properties=False)
                )
                document_class = self._get_document_class(msg_type)

                if document_class:
                    parser.from_string(content, document_class)
                    logger.info("Schema-Validierung erfolgreich fuer %s.", msg_type)
                else:
                    errors.append(
                        f"Kein pyiso20022-Schema fuer Nachrichtentyp "
                        f"'{msg_type}' verfuegbar."
                    )

            except ImportError as e:
                logger.warning(
                    "pyiso20022/xsdata nicht installiert (%s) - "
                    "strukturelle Validierung als Fallback.",
                    e
                )
                errors.extend(self._validate_structural(root, namespace, msg_type))

            except TypeError as e:
                if 'kw_only' in str(e):
                    logger.warning(
                        "pyiso20022 nicht kompatibel (kw_only) - "
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
        """Strukturelle Fallback-Validierung ohne externe Bibliotheken (Python 3.8+)."""
        errors: List[str] = []

        if not namespace:
            errors.append(
                "Kein ISO 20022-Namespace gefunden. "
                "Erwartet: urn:iso:std:iso:20022:tech:xsd:..."
            )
            return errors

        base_type = next(
            (k for k in self._REQUIRED_ELEMENTS if msg_type.startswith(k)),
            None
        )
        if not base_type:
            errors.append(
                f"Unbekannter Nachrichtentyp '{msg_type}'. "
                f"Unterstuetzt: {', '.join(self._REQUIRED_ELEMENTS)}"
            )
            return errors

        root_child_name, required_tags = self._REQUIRED_ELEMENTS[base_type]

        def find_local(tag: str) -> List[etree._Element]:
            return root.xpath(f".//*[local-name()='{tag}']")

        if not find_local(root_child_name):
            errors.append(
                f"Fehlendes Root-Element <{root_child_name}> "
                f"fuer Nachrichtentyp {msg_type}."
            )

        for tag in required_tags:
            if not find_local(tag):
                errors.append(f"Fehlendes Pflicht-Element <{tag}>.")

        grp_hdr_elems = find_local('GrpHdr')
        if grp_hdr_elems:
            grp_hdr = grp_hdr_elems[0]
            for required in ('MsgId', 'CreDtTm'):
                if not grp_hdr.xpath(f".//*[local-name()='{required}']"):
                    errors.append(f"<GrpHdr> fehlt Pflichtfeld <{required}>.")

        has_iban  = bool(find_local('IBAN'))
        has_bicfi = bool(find_local('BICFI') or find_local('BIC'))
        if not has_iban and not has_bicfi:
            errors.append(
                "Weder <IBAN> noch <BICFI>/<BIC> gefunden - "
                "Nachricht scheint unvollstaendig."
            )

        if not errors:
            logger.info(
                "Strukturelle Validierung erfolgreich fuer %s "
                "(Fallback, kein pyiso20022-Schema).",
                msg_type
            )

        return errors

    def _get_document_class(self, msg_type: str):
        """Gibt die passende Document-Klasse fuer den Nachrichtentyp zurueck."""
        try:
            if msg_type.startswith('camt.019'):
                # Swiss SIX-spezifisch – kein Standard-pyiso20022-Schema verfuegbar
                logger.debug("camt.019 (Swiss): strukturelle Validierung aktiv.")
                return None
            elif msg_type.startswith('camt.052'):
                from pyiso20022.camt.camt_052_001_08 import Document
                return Document
            elif msg_type.startswith('camt.053'):
                from pyiso20022.camt.camt_053_001_08 import Document
                return Document
            elif msg_type.startswith('camt.054'):
                from pyiso20022.camt.camt_054_001_08 import Document
                return Document
            elif msg_type.startswith('camt.057'):
                from pyiso20022.camt.camt_057_001_06 import Document
                return Document
            elif msg_type.startswith('pain.001'):
                from pyiso20022.pain.pain_001_001_09 import Document
                return Document
            elif msg_type.startswith('pain.009'):
                from pyiso20022.pain.pain_009_001_07 import Document
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
