# Padding oracle sur AES-CBC

Récupération du clair complet à partir d'un chiffré AES-CBC, en n'utilisant
qu'un oracle qui répond à une seule question : le padding du message
déchiffré est-il valide ? Attaque décrite par Serge Vaudenay en 2002.

## Contexte

Un oracle de padding apparaît dès qu'un service déchiffre un ciphertext
fourni par l'extérieur et laisse observer, d'une manière ou d'une autre, si
le padding du clair obtenu est correct. Le canal d'observation n'a pas besoin
d'être explicite : un message d'erreur distinguable (« padding invalide » vs
« requête mal formée »), un code HTTP différent, un temps de réponse plus
long, ou une entrée de log suffisent. On retrouve ce motif dans des cookies
de session chiffrés, des tokens applicatifs, ou tout endpoint qui accepte un
blob chiffré et se comporte différemment selon la validité du padding.

Le point contre-intuitif : le chiffrement sous-jacent est correct. AES est
solide, la clé est aléatoire et jamais exposée. La faille n'est pas
cryptographique mais protocolaire — le service accepte de déchiffrer un
contenu qu'il n'a pas produit, et en révèle un état interne.

## Rappel CBC

En CBC, le déchiffrement d'un bloc suit la relation :

    P_i = D_k(C_i) XOR C_{i-1}

où `P_i` est le bloc de clair, `C_i` le bloc chiffré, `D_k` le déchiffrement
bloc d'AES, et `C_{i-1}` le bloc chiffré précédent (l'IV pour le premier
bloc). On note `I_i = D_k(C_i)` la valeur « intermédiaire ».

Deux observations rendent l'attaque possible. `I_i` dépend uniquement de la
clé et de `C_i` : inconnue sans la clé, mais fixe tant que `C_i` ne change
pas. `C_{i-1}`, en revanche, n'est que de la donnée transmise — l'attaquant
la contrôle entièrement. Dans `P_i = I_i XOR C_{i-1}`, un terme est figé et
l'autre est choisi librement : modifier un octet de `C_{i-1}` modifie de
façon prévisible l'octet correspondant de `P_i`, sans jamais connaître `I_i`.

## Padding PKCS#7

AES-CBC ne chiffre que des messages multiples de 16 octets, donc on complète
le clair. En PKCS#7, chaque octet ajouté vaut le nombre d'octets ajoutés : il
manque 3 octets → `03 03 03` ; il manque 1 octet → `01` ; le message est déjà
un multiple de 16 → un bloc entier de `10` (16 en hexa). Au déchiffrement, on
vérifie cette structure et on la retire. Un padding mal formé est rejeté —
c'est ce rejet, observable, qui constitue l'oracle.

## La faille

L'oracle ne rend ni le clair, ni la clé — juste un booléen « padding valide ».
Cela paraît anodin. Ça ne l'est pas : une fuite d'un seul bit, mais
interrogeable à volonté, suffit à reconstruire tout le clair.

## L'exploitation

On récupère la valeur intermédiaire `I_i` octet par octet, en partant du
dernier.

On forge un faux bloc précédent `C'` et on soumet `C' || C_i` à l'oracle. Le
clair vu en interne vaut alors `I_i XOR C'`. On fait varier le dernier octet
de `C'` sur ses 256 valeurs jusqu'à ce que l'oracle réponde « valide » : le
dernier octet du clair interne vaut alors `0x01`, le plus court padding
valide. On en déduit :

    dernier octet de I_i = 0x01 XOR (dernier octet de C')

Un octet de `I_i` est récupéré sans la clé. Le vrai clair suit par
`P_i = I_i XOR C_{i-1}`, avec le vrai bloc précédent.

Pour l'avant-dernier octet, on fixe le dernier pour qu'il vaille `0x02`
(via `C'[15] = I_i[15] XOR 0x02`), puis on cherche l'octet qui produit un
padding `02 02`. On remonte ainsi tout le bloc, puis on passe au suivant.

### Le piège du faux positif

Au tout premier octet cherché (padding visé `0x01`), l'oracle peut répondre
« valide » pour une mauvaise raison : si le clair interne se termine déjà par
un padding plus long valide (par exemple `... 02 02`), c'est un faux positif.
On lève l'ambiguïté en perturbant l'avant-dernier octet du bloc forgé et en
redemandant. Si le padding tient, il ne dépendait que du dernier octet :
c'était bien `0x01`. S'il tombe, l'avant-dernier octet faisait partie du
padding : faux positif, on continue la recherche. Aux étapes suivantes le
problème disparaît, les octets de droite étant fixés par nos soins.

### Coût

Au pire 256 requêtes par octet, soit de l'ordre de `256 * N` pour un secret
de N octets — quelques milliers de requêtes, négligeable. C'est
l'illustration du principe : en cryptographie, une fuite minuscule mais
interrogeable suffit à tout casser.

## La correction

Masquer le message d'erreur ne corrige rien. La différence de temps de
traitement entre padding valide et invalide reste observable (timing oracle),
et surtout on traite le symptôme, pas la cause : tant que le service
déchiffre du contenu non authentifié, un canal observable subsistera.

La correction robuste est d'authentifier le ciphertext : Encrypt-then-MAC. On
attache un HMAC calculé sur le chiffré (IV compris), et on le vérifie **avant
tout déchiffrement**. Un ciphertext trafiqué échoue au MAC — que l'attaquant
ne peut pas recalculer sans la clé MAC — et est rejeté avant d'atteindre la
routine de padding. L'oracle cesse d'exister.

Deux points de mise en œuvre dans [`secure.py`](secure.py) :

- Deux clés distinctes, une pour le chiffrement, une pour le MAC — on ne
  réutilise jamais une clé pour deux usages.
- La comparaison du MAC se fait en temps constant (`hmac.compare_digest`) et
  non avec `==`, qui s'arrête au premier octet différent et rouvrirait, au
  niveau du MAC, exactement le type de fuite temporelle qu'on cherche à
  éliminer.

L'ordre encrypt-then-MAC (MAC sur le chiffré, pas sur le clair) est celui
prouvé sûr, par opposition à MAC-then-Encrypt, à l'origine d'attaques comme
Lucky 13 sur TLS.

## Reproduire

```bash
pip install -e ".[dev]"
python -m padding_oracle.demo   # monte l'oracle, lance l'attaque, affiche le clair
pytest -v                       # vérifie attaque et canal authentifié
```

## Fichiers

- `vulnerable.py` — l'oracle de padding CBC (la cible)
- `attack.py` — récupération du clair via l'oracle seul
- `secure.py` — version corrigée en Encrypt-then-MAC
- `demo.py` — démonstration de bout en bout

## Références

- S. Vaudenay, *Security Flaws Induced by CBC Padding* (Eurocrypt 2002)
- N. AlFardan, K. Paterson, *Lucky Thirteen* (2013)
