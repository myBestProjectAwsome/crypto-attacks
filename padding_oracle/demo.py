"""Démonstration de bout en bout.

    python -m padding_oracle.demo

Monte un oracle sur un secret, lance l'attaque en n'utilisant QUE l'oracle
de padding (jamais la clé), et affiche le clair récupéré.
"""

from padding_oracle.attack import attack
from padding_oracle.vulnerable import PaddingOracle


def main() -> None:
    secret = b"le drapeau: FCSC{padding_oracle_demo}"
    oracle = PaddingOracle(secret)

    ciphertext = oracle.encrypt()
    print(f"[*] ciphertext ({len(ciphertext)} octets) : {ciphertext.hex()}")
    print(f"[*] longueur secret : {len(secret)} octets")

    recovered = attack(oracle.has_valid_padding, ciphertext)

    print(f"[+] clair récupéré  : {recovered!r}")
    assert recovered == secret, "échec : clair récupéré incorrect"
    print("[+] OK — récupéré sans jamais utiliser la clé")


if __name__ == "__main__":
    main()
