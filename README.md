# Projet-Crypto  
Vote électronique

L'EC ElGamal (Elliptic Curve ElGamal) est un schéma de chiffrement homomorphique additif. Cela signifie que l'on peut effectuer des opérations d'addition sur des données **chiffrées** sans avoir besoin de les déchiffrer. Voici pourquoi :

### Explication de l'homomorphisme additif dans EC ElGamal

1. **Chiffrement EC ElGamal** :

   - Soit \( G \) un groupe elliptique avec un générateur \( P \).
   - La clé publique est \( Q = dP \), où \( d \) est la clé privée.
   - Pour chiffrer un message \( m \), on choisit un entier aléatoire \( k \) et on calcule le chiffré \( (C_1, C_2) \) comme suit :

     \[
     C_1 = kP
     \]

     \[
     C_2 = m + kQ
     \]

2. **Propriété homomorphique additive** :

   - Supposons que vous avez deux messages \( m_1 \) et \( m_2 \) chiffrés respectivement en \( (C_{1,1}, C_{2,1}) \) et \( (C_{1,2}, C_{2,2}) \).
   - Les chiffrés sont :

     \[
     C_{1,1} = k_1P, \quad C_{2,1} = m_1 + k_1Q
     \]

     \[
     C_{1,2} = k_2P, \quad C_{2,2} = m_2 + k_2Q
     \]

   - Pour additionner les messages chiffrés, vous additionnez simplement les composantes \( C_2 \) :

     \[
     C_{2,1} + C_{2,2} = (m_1 + k_1Q) + (m_2 + k_2Q) = (m_1 + m_2) + (k_1 + k_2)Q
     \]

   - La nouvelle composante \( C_1 \) sera :

     \[
     C_{1,1} + C_{1,2} = k_1P + k_2P = (k_1 + k_2)P
     \]

   - Ainsi, le chiffré de la somme des messages \( m_1 + m_2 \) est

     \[
     (C_{1,1} + C_{1,2},\; C_{2,1} + C_{2,2}) = ((k_1 + k_2)P,\; (m_1 + m_2) + (k_1 + k_2)Q)
     \]

3. **Conclusion** :
   - Cette propriété montre que l'addition des chiffrés \( (C_{1,1}, C_{2,1}) \) et \( (C_{1,2}, C_{2,2}) \) résulte en un chiffré qui correspond à la somme des messages originaux \( m_1 + m_2 \).
   - Cela démontre que l'EC ElGamal est homomorphique additif, permettant des opérations d'addition sur des données **chiffrées** sans nécessiter de déchiffrement.

---

## Implémentation dans un système de vote

Les scripts Python du serveur et du client implémentent un système de vote électronique sécurisé, permettant de choisir dynamiquement l'algorithme de signature (**DSA** ou **ECDSA**) et l'algorithme de chiffrement (**ElGamal** ou **EC-ElGamal**). Voici un commentaire détaillé du fonctionnement global de ces deux scripts, en français.

### Serveur (`serveur.py`)

1. **Initialisation et Sélection des Algorithmes**  
   - Le serveur démarre et demande à l'opérateur de choisir un algorithme de signature (**DSA** ou **ECDSA**) et un algorithme de chiffrement (**ElGamal** ou **EC-ElGamal**).
   - On suppose que la clé cryptographique nécessaire à la vérification de l'authenticité est transmise par un moyen sécurisé (par exemple, par la poste) pour garantir son intégrité. Pour l'illustration, on considère que c'est le client qui génère une clé éphémère et l'envoie au serveur, bien que dans un vrai scénario, la distribution des clés se ferait autrement pour vérifier l'authenticité.

2. **Configuration du Serveur**  
   - Le serveur initialise une "urne" électronique (`ballot_box_r` et `ballot_box_c`) pour accumuler les votes chiffrés.
   - Une structure de configuration (`config`) est préparée, contenant les paramètres sélectionnés, les clés, et un verrou pour la synchronisation des threads.

3. **Gestion des Connexions Clients**  
   - Le serveur écoute les connexions entrantes et lance un thread pour chaque client via la fonction `client_handler`.
   - Avant de traiter une nouvelle connexion, le serveur vérifie s'il a déjà atteint le nombre maximal d'électeurs et si le vote est terminé (via un flag `tallied`). Si le vote est terminé, il refuse la nouvelle connexion.

4. **Interaction avec le Client dans `client_handler`**  
   - **Envoi des Informations Initiales** : Le serveur envoie au client la clé publique, le nombre de candidats, et les algorithmes de signature et de chiffrement sélectionnés.
   - **Réception du Vote** : Le serveur reçoit le vote chiffré et les signatures du client, avec un buffer étendu pour gérer de gros messages JSON.
   - **Vérification du Vote** : Le serveur utilise l'algorithme de signature choisi pour vérifier l'authenticité du vote reçu.
   - **Agrégation des Votes** : Si la vérification réussit, le serveur ajoute le vote à l'urne électronique.
   - **Tally Final** : Lorsqu’il atteint le nombre maximal de votes, le serveur effectue un décompte final des votes, affiche les résultats, et marque le processus comme terminé pour refuser les connexions futures.

### Client (`client.py`)

1. **Connexion Initiale**  
   - Le client se connecte au serveur et reçoit les informations initiales : clé publique, nombre de candidats, et algorithmes sélectionnés.
   - En fonction de l'algorithme de signature choisi (**DSA** ou **ECDSA**), le client génère une paire de clés éphémères.

2. **Saisie du Vote**  
   - Le client invite l’utilisateur à choisir un candidat.
   - Il prépare un vecteur de votes où un seul élément est "1" (pour le candidat sélectionné) et le reste "0".

3. **Chiffrement et Signature du Vote**  
   - Pour chaque candidat, le client chiffre son vote en utilisant l'algorithme de chiffrement sélectionné :
     - **ElGamal (Additif)** : Utilise `EGA_encrypt` pour chiffrer le vote de manière additive. Cela signifie que le vote est transformé en un couple de valeurs chiffrées dont la combinaison homomorphique permettra d'obtenir la somme des votes.
     - **EC-ElGamal** : Utilise `ECEG_encrypt` pour chiffrer le vote avec une courbe elliptique.
   - Ensuite, le client signe chaque vote chiffré selon l'algorithme de signature choisi (**DSA** ou **ECDSA**).

4. **Envoi du Vote**  
   - Le client sérialise les votes chiffrés, les signatures, et sa clé publique dans un message JSON.
   - Il envoie ce message au serveur et ferme la connexion.

---

## Conclusion

Grâce à **EC-ElGamal** (ou ElGamal) pour le chiffrement, avec leur **propriété homomorphique additive**, et à des algorithmes de signature comme **DSA** ou **ECDSA** :

- Le serveur peut collecter et additionner directement les votes chiffrés.
- Chaque votant reste anonyme puisque le serveur ne voit jamais le vote en clair.
- La validité de chaque vote est garantie via la signature (DSA/ECDSA), empêchant les votes falsifiés ou répétés.
- Au dépouillement, le déchiffrement ne se fait qu'après la clôture du scrutin pour récupérer le total des votes par candidat.

Ce prototype de vote électronique est conçu pour respecter l'intégrité et la confidentialité des électeurs, tout en permettant l'addition sécurisée de votes chiffrés dans un environnement multi-threadé.
