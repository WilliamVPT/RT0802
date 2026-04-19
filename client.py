#!/usr/bin/env python3
"""
client.py — Client boutique en ligne
══════════════════════════════════════
Terminal 2 :  python client.py
              python client.py --name "Alice" --article "Casque audio" --qty 2 --prix 79.99

Le client :
  1. Attend que ca_cert.json soit disponible (créé par le serveur)
  2. S'enregistre auprès de la CA (CSR → certificat)
  3. Se connecte au serveur (handshake DH → clé AES-128)
  4. Envoie sa commande :
       D  = { client_name, article, quantite, prix_unitaire,
              adresse_livraison, carte_masquee, timestamp }
       D' = { AES128(D), iv, SHA1(D) signé RSA, certificat }
  5. Reçoit et vérifie le reçu chiffré du serveur
"""

import os, sys, json, time, argparse
sys.path.insert(0, os.path.dirname(__file__))

from shared import (
    rsa_generate, pub_to_dict, pub_from_dict,
    rsa_sign_sha1, rsa_verify_sha1,
    cert_create, cert_verify,
    dh_generate_private, dh_public, dh_shared, dh_to_aes_key,
    aes_encrypt, aes_decrypt, sha1,
    chan_send, chan_recv,
    CA_CERT_FILE, log
)


def wait_for_ca(timeout: float = 60.0) -> dict:
    """Attend que le serveur ait déposé ca_cert.json."""
    log("CLIENT", "Connexion à shop.example.com...")
    log("CLIENT", "Attente du certificat CA...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(CA_CERT_FILE):
            try:
                ca = json.load(open(CA_CERT_FILE))
                log("CLIENT", f"CA trouvée : {ca['subject']}")
                return ca
            except Exception:
                pass
        time.sleep(0.2)
    raise TimeoutError("Impossible de joindre le serveur (ca_cert.json absent).")


def register(ca_cert: dict) -> tuple[dict, object]:
    """S'enregistre auprès de la CA, reçoit un certificat."""
    log("CLIENT", "Obtention du certificat client...")
    priv, pub = rsa_generate()
    chan_send("CLIENT", "CA", "CSR",
              {"subject": "client@shop.example.com", "public_key": pub_to_dict(pub)})

    env  = chan_recv("CA", "CLIENT", mtype="CERTIFICATE", timeout=20.0)
    cert = env["payload"]["certificate"]

    ca_pub = pub_from_dict(ca_cert["public_key"])
    if not cert_verify(cert, ca_pub):
        raise ValueError("Certificat reçu : signature CA invalide !")

    log("CLIENT", f"Identité certifiée par la CA ✓  serial={cert['serial']}")
    return cert, priv


def handshake(my_cert: dict) -> bytes:
    """
    → HELLO  (cert client + g^x mod p)
    ← HELLO_ACK (cert serveur + g^y mod p)
    → dérivation clé AES-128
    """
    log("CLIENT", "Établissement du canal sécurisé (DH)...")

    x  = dh_generate_private()
    gx = dh_public(x)

    chan_send("CLIENT", "SERVER", "HELLO",
              {"certificate": my_cert, "dh_public": gx})

    env = chan_recv("SERVER", "CLIENT", mtype="HELLO_ACK", timeout=20.0)
    ack = env["payload"]

    server_cert = ack["certificate"]
    gy          = ack["dh_public"]

    # Vérifie le certificat du serveur
    ca_cert = json.load(open(CA_CERT_FILE))
    ca_pub  = pub_from_dict(ca_cert["public_key"])
    if not cert_verify(server_cert, ca_pub):
        raise ValueError("Certificat serveur non reconnu — connexion abandonnée.")

    log("CLIENT", f"Serveur authentifié : {server_cert['subject']} ✓")

    shared  = dh_shared(gy, x)
    aes_key = dh_to_aes_key(shared)
    log("CLIENT", f"Canal chiffré AES-128 établi  clé={aes_key.hex()}")

    return aes_key


def send_order(aes_key: bytes, my_cert: dict, my_priv,
               client_name: str, article: str,
               quantite: int, prix: float,
               adresse: str, carte: str):
    """
    Construit la commande, la chiffre et l'envoie.
    D' = AES128(D) | SHA1(D) signé | certificat
    """
    order = {
        "client_name":       client_name,
        "article":           article,
        "quantite":          quantite,
        "prix_unitaire":     prix,
        "adresse_livraison": adresse,
        "carte_masquee":     carte,
        "timestamp":         int(time.time()),
    }
    raw       = json.dumps(order, sort_keys=True).encode()
    empreinte = sha1(raw)
    signature = rsa_sign_sha1(my_priv, empreinte)
    iv, ct    = aes_encrypt(aes_key, raw)

    chan_send("CLIENT", "SERVER", "ORDER", {
        "encrypted":   ct.hex(),
        "iv":          iv.hex(),
        "signature":   signature.hex(),
        "certificate": my_cert,
    })

    print()
    log("CLIENT", "╔══ COMMANDE ENVOYÉE " + "═"*33)
    log("CLIENT", f"║  Article   : {article}  ×{quantite}")
    log("CLIENT", f"║  Total     : {quantite * prix:.2f} €")
    log("CLIENT", f"║  Adresse   : {adresse}")
    log("CLIENT", f"║  Carte     : {carte}")
    log("CLIENT", f"║  ─────────────────────────────────────────────")
    log("CLIENT", f"║  Chiffré   : {ct.hex()[:32]}...")
    log("CLIENT", f"║  SHA1(D)   : {empreinte.hex()}")
    log("CLIENT", f"║  Signature : {signature.hex()[:32]}...")
    log("CLIENT", "╚" + "═"*52)


def receive_receipt(aes_key: bytes):
    """Reçoit, déchiffre et vérifie le reçu du serveur."""
    log("CLIENT", "En attente du reçu...")
    env = chan_recv("SERVER", "CLIENT", mtype="RECEIPT", timeout=20.0)
    msg = env["payload"]

    raw     = aes_decrypt(aes_key,
                           bytes.fromhex(msg["iv"]),
                           bytes.fromhex(msg["encrypted"]))
    receipt = json.loads(raw.decode())

    # Vérifie la signature du serveur
    ca_cert    = json.load(open(CA_CERT_FILE))
    ca_pub     = pub_from_dict(ca_cert["public_key"])
    server_pub = pub_from_dict(msg["certificate"]["public_key"])
    cert_ok    = cert_verify(msg["certificate"], ca_pub)
    sig_ok     = rsa_verify_sha1(server_pub, sha1(raw),
                                  bytes.fromhex(msg["signature"]))

    print()
    log("CLIENT", "╔══ REÇU DE COMMANDE " + "═"*33)
    log("CLIENT", f"║  Statut    : {receipt.get('statut')}")
    log("CLIENT", f"║  N° cmd    : {receipt.get('numero_commande')}")
    log("CLIENT", f"║  Article   : {receipt.get('article')}  ×{receipt.get('quantite')}")
    log("CLIENT", f"║  Total     : {receipt.get('total')}")
    log("CLIENT", f"║  Livraison : {receipt.get('livraison')}")
    log("CLIENT", f"║  Message   : {receipt.get('message')}")
    log("CLIENT", f"║  ─────────────────────────────────────────────")
    log("CLIENT", f"║  Cert CA   : {'✅ authentique' if cert_ok else '❌ INVALIDE'}")
    log("CLIENT", f"║  Signature : {'✅ intègre'     if sig_ok  else '❌ INVALIDE'}")
    log("CLIENT", "╚" + "═"*52)
    print()


def main():
    ap = argparse.ArgumentParser(description="Client boutique — RT802")
    ap.add_argument("--name",    default="Alice Dupont",
                    help="Nom du client")
    ap.add_argument("--article", default="Clavier mécanique",
                    help="Article à commander")
    ap.add_argument("--qty",     type=int,   default=1)
    ap.add_argument("--prix",    type=float, default=89.90)
    ap.add_argument("--adresse", default="12 rue de la Paix, 75001 Paris")
    ap.add_argument("--carte",   default="**** **** **** 4242",
                    help="Numéro de carte masqué")
    args = ap.parse_args()

    print()
    log("CLIENT", "═"*52)
    log("CLIENT", "  shop.example.com — Boutique en ligne")
    log("CLIENT", "═"*52)

    ca_cert      = wait_for_ca()
    my_cert, priv = register(ca_cert)
    aes_key       = handshake(my_cert)

    send_order(aes_key, my_cert, priv,
               client_name = args.name,
               article     = args.article,
               quantite    = args.qty,
               prix        = args.prix,
               adresse     = args.adresse,
               carte       = args.carte)

    receive_receipt(aes_key)

    log("CLIENT", "Merci et à bientôt !")


if __name__ == "__main__":
    main()
