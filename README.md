# crypto-attacks

Implémentations pédagogiques d'attaques cryptographiques classiques. Chaque
attaque est un module autonome contenant la cible vulnérable, la version
corrigée, le code de l'exploitation, une démo reproductible et un write-up.

L'objectif n'est pas de fournir des outils prêts à l'emploi, mais de montrer
*pourquoi* ces constructions cassent — la faille, la mathématique de
l'exploitation, et la correction.

## Attaques

| Module | Attaque | Statut |
|---|---|---|
| [`padding_oracle/`](padding_oracle/) | Récupération de clair via oracle de padding CBC (Vaudenay 2002) | ✅ |

## Installation

```bash
git clone https://github.com/<user>/crypto-attacks.git
cd crypto-attacks
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest
```

## Avertissement

Code à but pédagogique, sur des cibles fournies dans ce dépôt. À n'utiliser
que sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez
une autorisation explicite.
