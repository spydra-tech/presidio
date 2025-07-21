import re
import pyffx
import base64
import logging
logging.basicConfig(
    filename="app.log",
    level=logging.ERROR,
    force=True,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
class FPEAnonymizer:
    def __init__(self):
        self.name = "fpe"

    def __call__(self, text: str, params: dict = None,reverse: bool = False) -> str:
        logging.info("Logging to start")
        entity_type = params.get("entity_type", "").upper()
        logging.info("Logging to %s",entity_type)
        key = params.get("key")
        alphabet = params.get("alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        logging.debug("This is a DEBUG message-------")
        if not key:
            raise ValueError("FPE requires a 'key' parameter.")
        logging.info("entity_type %s",entity_type)
        key_bytes = base64.b64decode(key.encode())
        logging.info("entity_type %s",entity_type)
        # Route entity types to appropriate methods
        if entity_type == "EMAIL_ADDRESS":
            return self._fpe_email(text, key_bytes, alphabet,reverse)
        elif entity_type == "CREDIT_CARD":
            return self._fpe_credit_card(text, key_bytes, alphabet,reverse)
        elif entity_type == "PHONE_NUMBER":
            logging.info("PHONE_NUMBER====")
            return self._fpe_phone(text, key_bytes, alphabet,reverse)
        elif entity_type in ["PERSON", "LOCATION"]:
            return self._fpe_tokens(text, key_bytes, alphabet,reverse)
        else:
            return self._fpe(text, key_bytes, alphabet)

    def operate(self, text: str, params: dict = None) -> str:
        return self.__call__(text, params)

    def deanonymize(self, text: str, params: dict = None) -> str:
        logging.info("Logging todeanonymize")
        return self.__call__(text, params, reverse=True)

    def validate(self, params: dict = None):
        if not params or "key" not in params:
            raise ValueError("Missing 'key' parameter for FPE anonymizer.")
        if not isinstance(params.get("key"), str):
            raise ValueError("'key' must be a base64-encoded string.")

    def operator_name(self):
        return self.name

    # --- Core FPE Helpers ---

    def _fpe(self, token, key_bytes, alphabet,reverse=False):
        cipher = pyffx.String(key_bytes, alphabet=alphabet, length=len(token))
        return cipher.decrypt(token) if reverse else cipher.encrypt(token)

    def _fpe_tokens(self, text, key_bytes, alphabet,reverse=False):
        return ' '.join([self._fpe(token, key_bytes, alphabet,reverse) for token in text.split()])

    def _fpe_email(self, email, key_bytes, alphabet,reverse=False):
        if '@' not in email:
            return self._fpe(email, key_bytes, alphabet,reverse)
        logging.info("Logging to %s",email)
        local, domain = email.split('@', 1)
        domain_name, dot, domain_tld = domain.partition('.')
        encrypted_local = self._fpe(local, key_bytes, alphabet,reverse)
        encrypted_domain = self._fpe(domain_name, key_bytes, alphabet,reverse)
        encrypted_tld = self._fpe(domain_tld, key_bytes, alphabet) if domain_tld else ''
        return f"{encrypted_local}@{encrypted_domain}.{encrypted_tld}".rstrip('.')

    def _fpe_credit_card(self, text, key_bytes, alphabet,reverse=False):
       digits = ''.join(filter(str.isdigit, text))
       cipher = pyffx.String(key_bytes, alphabet="0123456789", length=len(digits))
       encrypted = cipher.decrypt(digits) if reverse else cipher.encrypt(digits)

       # Replace original digits in the text with encrypted ones
       result = []
       idx = 0
       for c in text:
        if c.isdigit():
            result.append(encrypted[idx])
            idx += 1
        else:
            result.append(c)
       return ''.join(result)

    def _fpe_phone(self, text, key_bytes, alphabeti,reverse=False):
     """
     Encrypt only the digits of a phone number using FPE,
     preserving formatting (spaces, dashes, plus, etc).
     """
     # Extract digits from the text
     digits = ''.join(filter(str.isdigit, text))
     logging.info("This is a DEBUG message")
     print("==============")
     if not digits:
        return text

     # Encrypt all digits as one block
     cipher = pyffx.String(key_bytes, alphabet="0123456789", length=len(digits))
     encrypted_digits = cipher.decrypt(digits) if reverse else cipher.encrypt(digits)
     # Replace original digits one-by-one with encrypted ones
     result = []
     digit_index = 0
     for char in text:
        if char.isdigit():
            result.append(encrypted_digits[digit_index])
            digit_index += 1
        else:
            result.append(char)

     return ''.join(result)