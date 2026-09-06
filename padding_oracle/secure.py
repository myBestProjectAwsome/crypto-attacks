"""Version corrigée : Encrypt-then-MAC.

Le padding oracle existe parce que le service accepte de déchiffrer un
ciphertext qu'il n'a pas produit, puis révèle un état interne (padding
valide/invalide). La bonne correction n'est PAS de masquer l'erreur de
padding — c'est de refuser tout ciphertext non authentifié.

On attache un HMAC au ciphertext et on le vérifie en temps constant AVANT
tout déchiffrement. Un ciphertext trafiqué échoue au MAC : la routine de
padding n'est jamais atteinte, l'oracle n'existe plus.
"""

import hmac
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16


class SecureChannel:
    def __init__(self, secret: bytes):
        self._enc_key = get_random_bytes(16)
        self._mac_key = get_random_bytes(32)
        self._iv = get_random_bytes(16)
        self._secret = secret

    def encrypt(self) -> bytes:
        """Renvoie IV || ciphertext || tag."""
        cipher = AES.new(self._enc_key, AES.MODE_CBC, self._iv)
        body = self._iv + cipher.encrypt(pad(self._secret, BLOCK_SIZE))
        tag = hmac.new(self._mac_key, body, sha256).digest()
        return body + tag

    def decrypt(self, data: bytes) -> bytes:
        body, tag = data[:-32], data[-32:]
        expected = hmac.new(self._mac_key, body, sha256).digest()
        # Comparaison en temps constant : ne fuit pas où le tag diffère.
        if not hmac.compare_digest(tag, expected):
            raise ValueError("authentification échouée")
        iv, ct = body[:BLOCK_SIZE], body[BLOCK_SIZE:]
        cipher = AES.new(self._enc_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), BLOCK_SIZE)
