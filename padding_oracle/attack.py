"""Exploitation de l'oracle de padding CBC.

Rappel CBC : P_i = D_k(C_i) XOR C_{i-1}, où D_k est le déchiffrement bloc
du chiffre. On note « intermédiaire » la valeur I_i = D_k(C_i), inconnue
mais indépendante de C_{i-1}.

Idée : on forge un bloc précédent C' de notre choix et on soumet C' || C_i
à l'oracle. Le clair vu par l'oracle est alors I_i XOR C'. En jouant sur C'
pour obtenir un padding valide, on apprend I_i octet par octet — puis on
retrouve le vrai clair par P_i = I_i XOR C_{i-1} (le vrai bloc précédent).
Le tout SANS jamais connaître la clé.
"""

from typing import Callable

from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16

# Un oracle est n'importe quelle fonction bytes -> bool qui répond
# « padding valide ? » sur une entrée IV || ciphertext.
Oracle = Callable[[bytes], bool]


def recover_intermediate(oracle: Oracle, target: bytes) -> bytes:
    """Récupère les 16 octets intermédiaires I = D_k(target).

    `target` est le bloc chiffré à attaquer. On lui préfixe un bloc forgé
    et on soumet forged || target à l'oracle.
    """
    inter = bytearray(BLOCK_SIZE)

    # On remonte du dernier octet (pos 15) au premier (pos 0). À l'étape
    # `pad_val`, on cible un padding valide de valeur pad_val sur pad_val
    # octets.
    for pad_val in range(1, BLOCK_SIZE + 1):
        pos = BLOCK_SIZE - pad_val
        forged = bytearray(BLOCK_SIZE)

        # Les octets déjà connus (à droite de pos) sont fixés pour que le
        # clair correspondant vaille pad_val : C'[k] = I[k] XOR pad_val.
        for k in range(pos + 1, BLOCK_SIZE):
            forged[k] = inter[k] ^ pad_val

        # Brute force de l'octet courant : 256 possibilités.
        for guess in range(256):
            forged[pos] = guess
            if not oracle(bytes(forged) + target):
                continue

            # Faux positif possible au tout premier octet trouvé (pad_val==1) :
            # le clair réel pouvait déjà contenir un padding plus long valide.
            # On perturbe l'octet précédent : si le padding reste valide, c'est
            # bien 0x01 ; sinon c'était un faux positif, on continue.
            if pad_val == 1:
                probe = bytearray(forged)
                probe[pos - 1] ^= 0xFF
                if not oracle(bytes(probe) + target):
                    continue

            inter[pos] = guess ^ pad_val
            break
        else:
            raise RuntimeError(f"aucun octet valide trouvé à la position {pos}")

    return bytes(inter)


def attack(oracle: Oracle, data: bytes, verify_padding: bool = True) -> bytes:
    """Récupère le clair complet à partir de IV || ciphertext.

    Le premier bloc de `data` est l'IV et sert de C_0.
    """
    blocks = [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    plaintext = bytearray()

    for i in range(1, len(blocks)):
        inter = recover_intermediate(oracle, blocks[i])
        prev = blocks[i - 1]  # le vrai bloc précédent (IV pour i == 1)
        plaintext += bytes(a ^ b for a, b in zip(inter, prev))

    return unpad(bytes(plaintext), BLOCK_SIZE) if verify_padding else bytes(plaintext)
