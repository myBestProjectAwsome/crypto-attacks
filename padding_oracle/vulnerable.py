"""Cible vulnérable : un oracle de padding CBC.

Le service déchiffre un ciphertext et révèle une seule information : le
padding PKCS#7 du clair est-il valide ? C'est le pattern qu'on retrouve
dans un cookie de session chiffré, un token applicatif, ou un message
d'erreur distinguable ("padding invalide" vs "erreur applicative").

Cette fuite d'un seul bit suffit à récupérer tout le clair sans jamais
connaître la clé (Vaudenay, 2002).
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16


class PaddingOracle:
    """Détient une clé secrète et un secret. N'expose que le chiffrement du
    secret et l'oracle de padding."""

    def __init__(self, secret: bytes):
        self._key = get_random_bytes(16)
        self._iv = get_random_bytes(16)
        self._secret = secret

    def encrypt(self) -> bytes:
        """Chiffre le secret et renvoie IV || ciphertext."""
        cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        ct = cipher.encrypt(pad(self._secret, BLOCK_SIZE))
        return self._iv + ct

    def has_valid_padding(self, data: bytes) -> bool:
        """L'ORACLE. data = IV || ciphertext.

        Renvoie True si et seulement si le padding PKCS#7 du clair déchiffré
        est valide. C'est l'unique information qui fuit — et c'est déjà trop.
        """
        iv, ct = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, BLOCK_SIZE)
            return True
        except ValueError:
            return False
