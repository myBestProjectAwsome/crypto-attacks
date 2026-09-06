import pytest

from padding_oracle.attack import attack
from padding_oracle.secure import SecureChannel
from padding_oracle.vulnerable import PaddingOracle


@pytest.mark.parametrize(
    "secret",
    [
        b"A",                                   # 1 octet -> padding sur 1 bloc
        b"exactement seize",                    # 16 octets -> bloc de padding plein
        b"un secret plus long que trente-deux octets ici",
        bytes(range(32)),                       # octets non imprimables
    ],
)
def test_attack_recovers_plaintext(secret):
    oracle = PaddingOracle(secret)
    ciphertext = oracle.encrypt()
    recovered = attack(oracle.has_valid_padding, ciphertext)
    assert recovered == secret


def test_secure_channel_roundtrip():
    channel = SecureChannel(b"message authentifie")
    assert channel.decrypt(channel.encrypt()) == b"message authentifie"


def test_secure_channel_rejects_tampering():
    channel = SecureChannel(b"message authentifie")
    data = bytearray(channel.encrypt())
    data[16] ^= 0x01  # on trafique un octet du ciphertext
    with pytest.raises(ValueError):
        channel.decrypt(bytes(data))
