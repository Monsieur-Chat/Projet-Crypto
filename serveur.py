# serveur.py

import socket
import threading
import json
import sys
import secrets

# Importation des fonctions cryptographiques pour EC-ElGamal et ElGamal,
# ainsi que pour DSA et ECDSA.
from ecelgamal import (
    p as ECELG_P, ECEG_generate_keys, ECEG_decrypt, ECEG_add, bruteECLog, ECEG_encrypt
)
from elgamal import (
    PARAM_P as ELG_P, PARAM_Q as ELG_Q, PARAM_G as ELG_G,
    EG_generate_keys, EGA_encrypt, EG_decrypt, bruteLog
)
from dsa import DSA_generate_keys, DSA_sign, DSA_verify
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
import json

# Compteur global de votes reçus
votes_received = 0

# Fonction pour vérifier la validité des votes en utilisant l'algorithme de signature choisi
def areVotesValid(voteList, signatures, userPubKey, signature_algo, encryption_algo):
    for i in range(len(voteList)):
        # Pour ElGamal, reconstruction du message signé
        if encryption_algo == 'ElGamal':
            message = f"{voteList[i][0]}_{voteList[i][1]}"
        elif encryption_algo == 'ECElGamal':
            message = json.dumps(voteList[i])
        else:
            message = str(voteList[i])
        message_bytes = message.encode('utf-8')
        r, s = signatures[i]
        # Vérification selon l'algorithme de signature
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

# Fonction pour chiffrer les votes et les signer
def castVote(voteList, userPrivKey, candidatePubKeys, encryption_algo, signature_algo):
    encryptedVotes = []
    # Chiffrement pour chaque candidat
    for i, vote in enumerate(voteList):
        pubKey = candidatePubKeys[i]
        if encryption_algo == 'ElGamal':
            # Utilisation du chiffrement additif pour ElGamal
            enc = EGA_encrypt(vote, pubKey)
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

# Fonction pour effectuer le décompte final et afficher les résultats
def tally_and_print(ballot_box_r, ballot_box_c, sharedPrivKey, encryption_algo, num_candidates):
    print("\n=== Décompte Final ===")
    results = []
    for i in range(num_candidates):
        r_sum = ballot_box_r[i]
        c_sum = ballot_box_c[i]
        # Décryptage et calcul du nombre de votes par candidat
        if encryption_algo == 'ECElGamal':
            decrypted_sum = ECEG_decrypt(r_sum, c_sum, sharedPrivKey)
            vote_count = bruteECLog(decrypted_sum[0], decrypted_sum[1], ECELG_P)
        elif encryption_algo == 'ElGamal':
            decrypted_sum = EG_decrypt(r_sum, c_sum, sharedPrivKey)
            vote_count = bruteLog(decrypted_sum, ELG_G, ELG_P)
        else:
            raise ValueError(f"Algorithme de chiffrement non supporté : {encryption_algo}")
        print(f"Candidat #{i+1} : {vote_count} votes")
        results.append(vote_count)
    
    # Détermination du gagnant ou des ex-aequo
    winner = 0
    otherWinners = []
    for i, count in enumerate(results):
        if count > results[winner]:
            winner = i
            otherWinners = []
        elif i != winner and count == results[winner]:
            otherWinners.append(i)
    if not otherWinners:
        print(f"\nGagnant : Candidat #{winner+1} avec {results[winner]} votes !")
    else:
        tie_candidates = [winner] + otherWinners
        tie_str = ", ".join([f"#{c+1}" for c in tie_candidates])
        print(f"\nEx-aequo entre les candidats {tie_str} avec {results[winner]} votes chacun !")

# Fonction de gestion de chaque client connecté
def client_handler(conn, addr, config):
    global votes_received

    # Refuser les nouvelles votes si le décompte est terminé
    if config.get('tallied', False):
        try:
            refusal_msg = json.dumps({"error": "Période de vote terminée."})
            conn.sendall(refusal_msg.encode('utf-8'))
        except Exception as e:
            print(f"Erreur lors de l'envoi du message de refus : {e}")
        finally:
            conn.close()
        return

    signature_algo = config['signature_algo']
    encryption_algo = config['encryption_algo']
    sharedPubKey = config['sharedPubKey']
    num_candidates = config['num_candidates']
    ballot_box_r = config['ballot_box_r']
    ballot_box_c = config['ballot_box_c']
    sharedPrivKey = config['sharedPrivKey']
    max_voters = config['max_voters']
    lock = config['lock']

    try:
        # Envoi des informations initiales au client
        msg_out = {
            "pubKey": sharedPubKey,
            "num_candidates": num_candidates,
            "signature_algo": signature_algo,
            "encryption_algo": encryption_algo
        }
        conn.sendall(json.dumps(msg_out).encode('utf-8'))

        # Réception des données du client avec un buffer plus grand
        data = conn.recv(65536)
        if not data:
            conn.close()
            return

        msg_in = json.loads(data.decode('utf-8'))
        encryptedVotes = msg_in["encryptedVotes"]
        signatures = msg_in["signatures"]
        userPubKey_list = msg_in["userPubKey"]

        # Conversion de la clé publique reçue en fonction de l'algorithme de signature
        if signature_algo == 'DSA':
            if isinstance(userPubKey_list, list):
                userPubKey_value = int(userPubKey_list[0])
            else:
                userPubKey_value = int(userPubKey_list)
        elif signature_algo == 'ECDSA':
            userPubKey_value = tuple(userPubKey_list)
        else:
            print(f"Algorithme de signature non supporté : {signature_algo}")
            conn.close()
            return

        # Reconstruction des votes chiffrés
        if encryption_algo == 'ECElGamal':
            encryptedVotes_tuples = [tuple(vote) for vote in encryptedVotes]
        elif encryption_algo == 'ElGamal':
            encryptedVotes_tuples = [tuple(vote) for vote in encryptedVotes]
        else:
            print(f"Algorithme de chiffrement non supporté : {encryption_algo}")
            conn.close()
            return

        # Vérification des votes reçus
        if not areVotesValid(encryptedVotes_tuples, signatures, userPubKey_value, signature_algo, encryption_algo):
            print(f"[Erreur] Vérification échouée du client {addr}. Vote rejeté.")
            conn.close()
            return

        with lock:
            # Agrégation des votes selon l'algorithme de chiffrement
            if encryption_algo == 'ECElGamal':
                ECEG_add(ballot_box_r, ballot_box_c, encryptedVotes_tuples)
            elif encryption_algo == 'ElGamal':
                for i in range(len(encryptedVotes_tuples)):
                    r, c = encryptedVotes_tuples[i]
                    ballot_box_r[i] = (ballot_box_r[i] * r) % ELG_P
                    ballot_box_c[i] = (ballot_box_c[i] * c) % ELG_P
            else:
                raise ValueError(f"Algorithme de chiffrement non supporté : {encryption_algo}")

            votes_received += 1
            print(f"[Debug] Vote #{votes_received} reçu de {addr}.")

            # Effectuer le décompte final une seule fois
            if votes_received >= max_voters and not config.get('tallied', False):
                config['tallied'] = True
                tally_and_print(ballot_box_r, ballot_box_c, sharedPrivKey, encryption_algo, num_candidates)
                print("[Serveur] Nombre maximum de votants atteint, fermeture du serveur.")
    finally:
        conn.close()

def main():
    global votes_received
    votes_received = 0

    if len(sys.argv) != 5:
        print(f"Usage: python {sys.argv[0]} <HOST> <PORT> <MAX_VOTERS> <NUM_CANDIDATES>")
        sys.exit(1)

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    MAX_VOTERS = int(sys.argv[3])
    NUM_CANDIDATES = int(sys.argv[4])

    # Sélection des algorithmes par l'opérateur
    print("Sélectionnez l'algorithme de signature :")
    print("1. DSA")
    print("2. ECDSA")
    sig_choice = input("Entrez le numéro de votre choix (1 ou 2) : ").strip()
    if sig_choice == '1':
        signature_algo = 'DSA'
    elif sig_choice == '2':
        signature_algo = 'ECDSA'
    else:
        print("Choix invalide pour l'algorithme de signature.")
        sys.exit(1)

    print("\nSélectionnez l'algorithme de chiffrement :")
    print("1. ElGamal")
    print("2. EC-ElGamal")
    enc_choice = input("Entrez le numéro de votre choix (1 ou 2) : ").strip()
    if enc_choice == '1':
        encryption_algo = 'ElGamal'
    elif enc_choice == '2':
        encryption_algo = 'ECElGamal'
    else:
        print("Choix invalide pour l'algorithme de chiffrement.")
        sys.exit(1)

    print(f"\nAlgorithme de signature sélectionné : {signature_algo}")
    print(f"Algorithme de chiffrement sélectionné : {encryption_algo}\n")

    # Génération des clés partagées selon l'algorithme de chiffrement
    if encryption_algo == 'ElGamal':
        sharedPrivKey, sharedPubKey = EG_generate_keys()
    elif encryption_algo == 'ECElGamal':
        sharedPrivKey, sharedPubKey = ECEG_generate_keys()
    else:
        print(f"Algorithme de chiffrement non supporté : {encryption_algo}")
        sys.exit(1)


    # Initialisation de l'urne en fonction de l'algorithme choisi
    if encryption_algo == 'ElGamal':
        ballot_box_r = [1] * NUM_CANDIDATES
        ballot_box_c = [1] * NUM_CANDIDATES
    elif encryption_algo == 'ECElGamal':
        ballot_box_r = [(1, 0)] * NUM_CANDIDATES
        ballot_box_c = [(1, 0)] * NUM_CANDIDATES
    else:
        raise ValueError(f"Algorithme de chiffrement non supporté : {encryption_algo}")

    lock = threading.Lock()

    config = {
        'signature_algo': signature_algo,
        'encryption_algo': encryption_algo,
        'sharedPrivKey': sharedPrivKey,
        'sharedPubKey': sharedPubKey,
        'num_candidates': NUM_CANDIDATES,
        'max_voters': MAX_VOTERS,
        'ballot_box_r': ballot_box_r,
        'ballot_box_c': ballot_box_c,
        'lock': lock,
        'tallied': False  # Flag pour indiquer si le décompte a été effectué
    }

    print(f"[Serveur] Démarrage du serveur sur {HOST}:{PORT}, en attente de {MAX_VOTERS} votes pour {NUM_CANDIDATES} candidats...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        while True:
            conn, addr = s.accept()
            print(f"[Serveur] Connexion de {addr}")
            threading.Thread(target=client_handler, args=(conn, addr, config)).start()

            with lock:
                if votes_received >= MAX_VOTERS:
                    break

    print("[Serveur] Terminé. Extinction.")

if __name__ == "__main__":
    main()
