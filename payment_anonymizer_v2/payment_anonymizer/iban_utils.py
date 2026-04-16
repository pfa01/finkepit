# -*- coding: utf-8 -*-
"""
iban_utils.py
=============
Hilfsfunktionen zur Generierung und Validierung von IBANs.
"""

import hashlib


class IBANGenerator:
    """Generiert und validiert IBANs mit korrekter Prüfsumme."""

    COUNTRY_LENGTHS = {
        'DE': 22, 'AT': 20, 'CH': 21, 'LU': 20, 'FR': 27,
        'NL': 18, 'BE': 16, 'IT': 27, 'ES': 24
    }

    @staticmethod
    def calculate_checksum(country_code: str, bban: str) -> str:
        """Berechnet die IBAN-Prüfsumme."""
        temp_iban = bban + country_code + "00"
        numeric_str = ""
        for char in temp_iban:
            if char.isalpha():
                numeric_str += str(ord(char.upper()) - 55)
            else:
                numeric_str += char
        remainder = int(numeric_str) % 97
        checksum = 98 - remainder
        return f"{checksum:02d}"

    @staticmethod
    def validate_iban(iban: str) -> bool:
        """Validiert eine IBAN."""
        iban = iban.replace(" ", "").upper()
        if len(iban) < 4:
            return False
        rearranged = iban[4:] + iban[:4]
        numeric_str = ""
        for char in rearranged:
            if char.isalpha():
                numeric_str += str(ord(char) - 55)
            else:
                numeric_str += char
        return int(numeric_str) % 97 == 1

    @staticmethod
    def generate_valid_iban(country_code: str, seed: str) -> str:
        """Generiert eine gültige IBAN basierend auf einem Seed."""
        country_code = country_code.upper()
        length = IBANGenerator.COUNTRY_LENGTHS.get(country_code, 22)
        bban_length = length - 4
        hash_val = hashlib.md5(seed.encode()).hexdigest()
        bban = ''.join(c for c in hash_val if c.isdigit())[:bban_length]
        bban = bban.ljust(bban_length, '0')
        checksum = IBANGenerator.calculate_checksum(country_code, bban)
        return f"{country_code}{checksum}{bban}"
