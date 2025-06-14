# client.py

import socket
import sys
import json
import secrets
import json

from ecelgamal import ECEG_encrypt
from elgamal import EGM_encrypt, EGA_encrypt
from dsa import DSA_generate_keys, DSA_sign, DSA_verify
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify

def areVotesValid(voteList, signatures, userPubKey, signature_algo, encryption_algo):
    # Cette fonction n'est pas utilisée côté client, mais pourrait servir pour une vérification locale.
    for i in range(len(voteList)):
        if encryption_algo == 'ElGamal':
            message = f"{voteList[i][0]}_{voteList[i][1]}"
        elif encryption_algo == 'ECElGamal':
            message = json.dumps(voteList[i])
        else:
            print(f"Algorithme de chiffrement non supporté : {encryption_algo}")
            return False

        message_bytes = message.encode('utf-8')
        r, s = signatures[i]
        if signature_algo == 'DSA':
            valid = DSA_verify(message, r, s, userPubKey)
        elif signature_algo == 'ECDSA':
            valid = ECDSA_verify(userPubKey, message_bytes, r, s)
        else:
            print(f"Algorithme de signature non supporté : {signature_algo}")
            return False
        if not valid:
            return False
    return True

def castVote(voteList, userPrivKey, candidatePubKeys, encryption_algo, signature_algo):
    encryptedVotes = []
    # Chiffrement des votes pour chaque candidat
    for i, vote in enumerate(voteList):
        pubKey = candidatePubKeys[i]
        if encryption_algo == 'ElGamal':
            enc = EGA_encrypt(vote, pubKey)  # Utilisation du chiffrement additif pour ElGamal
        elif encryption_algo == 'ECElGamal':
            enc = ECEG_encrypt(vote, pubKey)
        else:
            raise ValueError(f"Algorithme de chiffrement non supporté : {encryption_algo}")
        encryptedVotes.append(enc)
    
    signatures = []
    # Signature de chaque vote chiffré
    for enc in encryptedVotes:
        if encryption_algo == 'ElGamal':
            message = f"{enc[0]}_{enc[1]}"
            message_bytes = message.encode('utf-8')
        elif encryption_algo == 'ECElGamal':
            message = json.dumps(enc)
            message_bytes = message.encode('utf-8')
        else:
            raise ValueError(f"Algorithme de chiffrement non supporté : {encryption_algo}")
        
        if signature_algo == 'DSA':
            r, s = DSA_sign(message, userPrivKey)
        elif signature_algo == 'ECDSA':
            r, s = ECDSA_sign(userPrivKey, message_bytes)
        else:
            raise ValueError(f"Algorithme de signature non supporté : {signature_algo}")
        signatures.append((r, s))
    return encryptedVotes, signatures

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <HOST> <PORT>")
        sys.exit(1)

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

    # Connexion au serveur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Réception des informations initiales du serveur
        data = s.recv(8192)
        msg_in = json.loads(data.decode('utf-8'))

        sharedPubKey = msg_in["pubKey"]
        num_candidates = msg_in["num_candidates"]
        signature_algo = msg_in["signature_algo"]
        encryption_algo = msg_in["encryption_algo"]

        print("[Client] Nombre de candidats :", num_candidates)
        print("[Client] Algorithme de signature :", signature_algo)
        print("[Client] Algorithme de chiffrement :", encryption_algo)

        # Génération de la clé éphémère du client
        if signature_algo == 'DSA':
            userPrivKey, userPubKey = DSA_generate_keys()
        elif signature_algo == 'ECDSA':
            userPrivKey, userPubKey = ECDSA_generate_keys()
        else:
            print(f"Algorithme de signature non supporté : {signature_algo}")
            sys.exit(1)

        # Choix du candidat
        try:
            chosen = int(input(f"Choisissez un candidat [1..{num_candidates}] : ")) - 1
            if chosen < 0 or chosen >= num_candidates:
                print("Numéro de candidat invalide !")
                return
        except ValueError:
            print("Entrée invalide. Veuillez entrer un nombre.")
            return

        voteList = [0] * num_candidates
        voteList[chosen] = 1  # Vote pour le candidat choisi

        # Préparation des clés publiques pour chaque candidat
        if encryption_algo == 'ElGamal':
            candidatePubKeys = [sharedPubKey for _ in range(num_candidates)]
        elif encryption_algo == 'ECElGamal':
            candidatePubKeys = [tuple(sharedPubKey) for _ in range(num_candidates)]
        else:
            print(f"Algorithme de chiffrement non supporté : {encryption_algo}")
            sys.exit(1)

        # Chiffrement et signature du vote
        encryptedVotes, signatures = castVote(voteList, userPrivKey, candidatePubKeys, encryption_algo, signature_algo)

        # Préparation des données à envoyer au serveur
        if encryption_algo == 'ElGamal':
            to_send_encrypted = [[enc[0], enc[1]] for enc in encryptedVotes]
            if signature_algo == 'ECDSA':
                userPubKey_send = list(userPubKey)
            else:
                userPubKey_send = [userPubKey]
        elif encryption_algo == 'ECElGamal':
            to_send_encrypted = [[list(enc[0]), list(enc[1])] for enc in encryptedVotes]
            if signature_algo == 'ECDSA':
                userPubKey_send = list(userPubKey)
            else:
                userPubKey_send = [userPubKey]
        else:
            print(f"Algorithme de chiffrement non supporté : {encryption_algo}")
            sys.exit(1)

        msg_out = {
            "encryptedVotes": to_send_encrypted,
            "signatures": signatures,
            "userPubKey": userPubKey_send
        }
        s.sendall(json.dumps(msg_out).encode('utf-8'))

        print("[Client] Vote envoyé. Fermeture de la connexion.")

if __name__ == "__main__":
    main()
