# Projet-Crypto

gote electronique

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

   - Supposons que vous avez deux messages $` m*1 `$ et $` m_2 `$ chiffrés respectivement en $` (C*{1,1}, C*{2,1}) `$ et $` (C*{1,2}, C\_{2,2}) `$.
   - Les chiffrés sont :
     $`
     C*{1,1} = k_1P, \quad C*{2,1} = m*1 + k_1Q
     `$
     $`
     C*{1,2} = k*2P, \quad C*{2,2} = m_2 + k_2Q
     `$
   - Pour additionner les messages chiffrés, vous additionnez simplement les composantes $` C*2 `$ :
     $`
     C*{2,1} + C\_{2,2} = (m_1 + k_1Q) + (m_2 + k_2Q) = (m_1 + m_2) + (k_1 + k_2)Q
     `$
   - La nouvelle composante $` C*1 `$ sera :
     $`
     C*{1,1} + C\_{1,2} = k_1P + k_2P = (k_1 + k_2)P
     `$
   - Ainsi, le chiffré de la somme des messages $` m*1 + m_2 `$ est :
     $`
     (C*{1,1} + C*{1,2}, C*{2,1} + C\_{2,2}) = ((k_1 + k_2)P, (m_1 + m_2) + (k_1 + k_2)Q)
     `$

3. **Conclusion** :
   - Cette propriété montre que l'addition des chiffrés $` (C*{1,1}, C*{2,1}) `$ et $` (C*{1,2}, C*{2,2}) `$ résulte en un chiffré qui correspond à la somme des messages originaux $` m_1 + m_2 `$.
   - Cela démontre que l'EC ElGamal est homomorphique additif, permettant des opérations d'addition sur des données chiffrées sans nécessiter de déchiffrement.

En résumé, l'EC ElGamal permet d'additionner des messages chiffrés directement dans le domaine chiffré, ce qui en fait un schéma de chiffrement homomorphique additif.
