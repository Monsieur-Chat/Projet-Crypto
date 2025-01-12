# Projet-Crypto  
Vote electronique
  
L'EC ElGamal (Elliptic Curve ElGamal) est effectivement un schéma de chiffrement homomorphique additif. Cela signifie que vous pouvez effectuer des opérations d'addition sur des données chiffrées sans avoir besoin de les déchiffrer. Voici pourquoi :

### Explication de l'homomorphisme additif dans EC ElGamal

1. **Chiffrement EC ElGamal** :

   - Soit $` G `$ un groupe elliptique avec un générateur $` P `$.
   - La clé publique est $` Q = dP `$, où $` d `$ est la clé privée.
   - Pour chiffrer un message $` m `$, on choisit un entier aléatoire $` k `$ et on calcule le chiffré $` (C_1, C_2) `$ comme suit :

     $`
     C_1 = kP
     `$

     $`
     C_2 = m + kQ
     `$

2. **Propriété homomorphique additive** :

   - Supposons que vous avez deux messages $` m_1 `$ et $` m_2 `$ chiffrés respectivement en $` (C_{1,1}, C_{2,1}) `$ et $` (C_{1,2}, C_{2,2}) `$.
   - Les chiffrés sont :

     $`
     C_{1,1} = k_1P, \quad C_{2,1} = m_1 + k_1Q
     `$

     $`
     C_{1,2} = k_2P, \quad C_{2,2} = m_2 + k_2Q
     `$

   - Pour additionner les messages chiffrés, vous additionnez simplement les composantes $` C_2 `$ :

     $`
     C_{2,1} + C_{2,2} = (m_1 + k_1Q) + (m_2 + k_2Q) = (m_1 + m_2) + (k_1 + k_2)Q
     `$

   - La nouvelle composante $` C_1 `$ sera :

     $`
     C_{1,1} + C_{1,2} = k_1P + k_2P = (k_1 + k_2)P
     `$

   - Ainsi, le chiffré de la somme des messages $` m_1 + m_2 `$ est

     $`
     (C_{1,1} + C_{1,2}, C_{2,1} + C_{2,2}) = ((k_1 + k_2)P, (m_1 + m_2) + (k_1 + k_2)Q)
     `$

3. **Conclusion** :
   - Cette propriété montre que l'addition des chiffrés $` (C_{1,1}, C_{2,1}) `$ et $` (C_{1,2}, C_{2,2}) `$ résulte en un chiffré qui correspond à la somme des messages originaux $` m_1 + m_2 `$.
   - Cela démontre que l'EC ElGamal est homomorphique additif, permettant des opérations d'addition sur des données chiffrées sans nécessiter de déchiffrement.

En résumé, l'EC ElGamal permet d'additionner des messages chiffrés directement dans le domaine chiffré, ce qui en fait un schéma de chiffrement homomorphique additif.
---

## Implémentation dans un système de vote

### Partie Serveur

Dans un premier temps, le serveur (script **`server.py`**) :

1. **Génère** un couple de **clé privée** et **clé publique** (EC ElGamal).  
   - Cette clé publique est mise à disposition de tous les clients.  
   - La clé privée est **conservée secrète** pour le dépouillement final.

2. **Crée** l’urne, qui va stocker les votes chiffrés pour chaque candidat.  
   - Cette urne est souvent initialisée à \((1, 0)\) (ou tout autre point neutre selon l’implémentation) pour **chaque candidat**.  
   - L’algorithme de chiffrement utilisé est **EC ElGamal**, donc l’urne est stockée sous forme de paires \((r, c)\) pour chacun.

3. **Reçoit** les votes des clients.  
   - Chaque vote consiste en un **bulletin chiffré** (les paires \((C_1, C_2)\) pour chaque candidat), **signé** via ECDSA.  
   - Le serveur exécute une **vérification** de la signature ECDSA (avec la **clé publique** du votant). Si la signature est valide, le vote est considéré comme **authentique**.

4. **Additionne** chaque vote dans l’urne grâce à la **propriété homomorphique** de EC ElGamal.  
   - Concrètement, on additionne composante \((r)\) de l’urne et composante \((c)\) de l’urne avec celles du vote.

5. **Dépouille** les votes une fois le scrutin terminé :  
   - Le serveur **déchiffre** la case associée à chaque candidat en utilisant **la clé privée** ElGamal.  
   - Il **retrouve** ainsi le nombre de votes pour chaque candidat.  
   - Il **détermine** le gagnant ou les gagnants (en cas d’égalité).

---

### Partie Client

Dans la partie client (script **`client.py`**), chaque votant :

1. **Génère** (ou possède déjà) une **clé ECDSA** (privée/publique) pour **signer** les votes.  
2. **Récupère** la **clé publique EC ElGamal** du serveur pour **chiffrer** son bulletin de vote.  
3. **Crée** un vecteur de vote (par exemple `[0, 1, 0, 0]` pour sélectionner un seul candidat).  
4. **Chiffre** chaque entrée du vecteur (soit `0`, soit `1`) avec la clé publique ElGamal.  
   - Chaque entrée devient un couple \((C_1, C_2)\).  
5. **Signe** chaque élément chiffré (ou le bulletin complet) avec **la clé privée** ECDSA pour prouver l’origine et l’intégrité du vote.  
6. **Envoie** l’ensemble (bulletin chiffré + signatures) au **serveur**.

#### Modifications / Points clés dans `client.py` :

- Nous avons **introduit** la fonction `generate_secure_private_key()` pour s’assurer d’utiliser un **générateur de nombres aléatoires cryptographiquement sûr** (`secrets` au lieu de `random`).  
- La fonction `castVote(voteList, userPrivKey, pubKey)` permet de **chiffrer** le vecteur de vote et de **signer** chaque composante.  
- Avant l’envoi, on peut **afficher** des **informations de débogage** (la clé privée ECDSA, la forme du bulletin chiffré, etc.) pour s’assurer du bon fonctionnement.

---

## Conclusion

Grâce à **EC ElGamal** pour le chiffrement (avec sa **propriété homomorphique additive**) et à **ECDSA** pour la signature des bulletins :

- **Le serveur** peut collecter et additionner **directement** les votes **chiffrés**.  
- **Chaque votant** reste **anonyme** (le serveur ne voit jamais le vote en clair).  
- **La validité** de chaque vote est **garantie** via la signature ECDSA, empêchant les votes falsifiés ou répétés.  
- Au **dépouillement**, on ne procède au déchiffrement **qu’après** la clôture du scrutin pour récupérer le total de votes de chaque candidat.

C’est donc un **prototype** de vote électronique **sécurisé** et respectueux de **l’intégrité** et de **la confidentialité** des électeurs.
