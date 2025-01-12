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


# Implémentation dans un système de vote
## Partie Serveur

- Dans un premier temps, le serveur initialise un couple de clé privée et publique, puis l'urne qui serviras à stocker les votes pour chaque candidat, l'algorythme utilisé étant ECElgamal, elle est composée de matrice  (1,0) pour le nombre de candidat à l'éléction.
- Lorsqu'un vote (chiffré avec la clé publique) est reçu, le serveur vérifie d'abord sa validité en comparant les signatures reçus pour chaque vote avec la clé publique du votant émetteur, l'algorythme utilisé est ECDSA.
- Dès lors que la validité du vote est vérifiée, chaque chiffré est additionné en utilisant la propriété homomorphique de ECElgamal.
  On rappel que chaque vote est composé d'une matrice de 0 et d'un 1, tous chiffrés, pour le candidat visé par ce vote.
- Une fois les votes reçus, l'urne passe au dépouillement : chaque case mémoire associé à un candidat est déchiffré en utilisant la clé privée et les votes sont comparés et le (ou les gagnants en cas d'égalité) gagnant est déterminé

















