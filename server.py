#!/usr/bin/env python3
"""
server.py — Serveur boutique en ligne
═══════════════════════════════════════
Terminal 1 :  python server.py

Le serveur fait deux choses :
  1. Il démarre la CA en interne (thread de fond) — c'est lui qui gère
     l'infrastructure PKI, comme un vrai site qui possède son autorité.
  2. Il s'enregistre lui-même auprès de cette CA, attend le client,
     fait le handshake DH, puis reçoit et vérifie les commandes.

Flux :
  [CA interne]
      ├── émet cert SERVEUR (auto-enregistrement)
      └── émet cert CLIENT  (quand le client se connecte)

  CLIENT ──HELLO──► SERVER   (cert client + g^x)
  SERVER ──HELLO_ACK──► CLIENT (cert serveur + g^y)
  CLIENT ──ORDER──► SERVER   (AES128(commande) | SHA1 signé | cert)
  SERVER ──RECEIPT──► CLIENT  (AES128(reçu)    | SHA1 signé | cert)
"""

import os, sys, json, time, threading
sys.path.insert(0, os.path.dirname(__file__))

from shared import (
    rsa_generate, pub_to_dict, pub_from_dict,
    rsa_sign_sha1, rsa_verify_sha1,
    cert_create, cert_verify,
    dh_generate_private, dh_public, dh_shared, dh_to_aes_key,
    aes_encrypt, aes_decrypt, sha1,
    chan_send, chan_recv, chan_init,
    CA_CERT_FILE, log
)


# ══════════════════════════════════════════════════════════════
#  CA interne  (tourne dans un thread du serveur)
# ══════════════════════════════════════════════════════════════

class InternalCA:
    """
    Autorité de Certification embarquée dans le serveur.
    Génère ca_cert.json au démarrage, puis traite les CSR entrants.
    """

    def __init__(self):
        self.priv, pub = rsa_generate()
        self.pub_dict  = pub_to_dict(pub)

        self.cert = cert_create(
            subject     = "ShopCA",
            pub_dict    = self.pub_dict,
            issuer      = "ShopCA",
            issuer_priv = self.priv,
        )
        with open(CA_CERT_FILE, "w") as f:
            json.dump(self.cert, f, indent=2)

        log("CA", "Certificat auto-signé généré → ca_cert.json")
        log("CA", f"  └─ RSA-2048, sha1WithRSAEncryption, validité 365 j")

    def run(self, nb_csr: int = 2):
        """Boucle de traitement des CSR (dans son propre thread)."""
        log("CA", f"En écoute — attend {nb_csr} CSR(s)...")
        issued = 0
        while issued < nb_csr:
            try:
                env = chan_recv("*", "CA", mtype="CSR", timeout=120.0)
            except TimeoutError:
                break
            csr  = env["payload"]
            src  = env["src"]
            cert = cert_create(
                subject     = csr["subject"],
                pub_dict    = csr["public_key"],
                issuer      = "ShopCA",
                issuer_priv = self.priv,
            )
            chan_send("CA", src, "CERTIFICATE", {"certificate": cert})
            issued += 1
            log("CA", f"Certificat émis pour '{csr['subject']}'  "
                       f"serial={cert['serial']}")
        log("CA", "CA terminée.")


# ══════════════════════════════════════════════════════════════
#  Serveur boutique
# ══════════════════════════════════════════════════════════════

def register() -> tuple[dict, object]:
    """Le serveur s'enregistre auprès de sa propre CA."""
    priv, pub = rsa_generate()
    chan_send("SERVER", "CA", "CSR",
              {"subject": "shop.example.com", "public_key": pub_to_dict(pub)})
    env  = chan_recv("CA", "SERVER", mtype="CERTIFICATE", timeout=15.0)
    cert = env["payload"]["certificate"]
    ca_cert = json.load(open(CA_CERT_FILE))
    assert cert_verify(cert, pub_from_dict(ca_cert["public_key"]))
    log("SERVER", f"Certificat serveur obtenu  serial={cert['serial']}")
    return cert, priv


def handshake(my_cert: dict) -> tuple[bytes, dict]:
    """
    ← HELLO  (cert client + g^x)
    → HELLO_ACK (cert serveur + g^y)
    → clé AES-128 partagée
    Retourne (aes_key, client_cert)
    """
    log("SERVER", "En attente de la connexion client...")
    env   = chan_recv("CLIENT", "SERVER", mtype="HELLO", timeout=120.0)
    hello = env["payload"]

    client_cert = hello["certificate"]
    gx          = hello["dh_public"]

    # Vérifie le certificat du client via la CA
    ca_pub = pub_from_dict(json.load(open(CA_CERT_FILE))["public_key"])
    if not cert_verify(client_cert, ca_pub):
        raise ValueError("Certificat client invalide !")

    log("SERVER", f"Client connecté : {client_cert['subject']}")
    log("SERVER", f"  Certificat client vérifié par la CA ✓")

    # DH : calcule g^y, répond, dérive la clé
    y  = dh_generate_private()
    gy = dh_public(y)
    chan_send("SERVER", "CLIENT", "HELLO_ACK",
              {"certificate": my_cert, "dh_public": gy})

    shared  = dh_shared(gx, y)
    aes_key = dh_to_aes_key(shared)
    log("SERVER", f"Handshake DH terminé  →  clé AES-128 = {aes_key.hex()}")

    return aes_key, client_cert


def receive_order(aes_key: bytes, client_cert: dict,
                  my_cert: dict, my_priv) -> dict | None:
    """
    Reçoit une commande chiffrée du client.
    Déchiffre → vérifie cert CA → vérifie signature SHA1.
    Retourne les données de commande ou None si invalide.
    """
    log("SERVER", "En attente d'une commande...")
    env = chan_recv("CLIENT", "SERVER", mtype="ORDER", timeout=60.0)
    msg = env["payload"]

    # Déchiffrement AES-128-CBC
    raw = aes_decrypt(aes_key,
                      bytes.fromhex(msg["iv"]),
                      bytes.fromhex(msg["encrypted"]))
    order = json.loads(raw.decode())

    # Vérifications
    ca_pub     = pub_from_dict(json.load(open(CA_CERT_FILE))["public_key"])
    cert_ok    = cert_verify(msg["certificate"], ca_pub)
    client_pub = pub_from_dict(msg["certificate"]["public_key"])
    sig_ok     = rsa_verify_sha1(client_pub, sha1(raw),
                                  bytes.fromhex(msg["signature"]))

    print()
    log("SERVER", "╔══ COMMANDE REÇUE " + "═"*34)
    log("SERVER", f"║  Client    : {order.get('client_name')}")
    log("SERVER", f"║  Article   : {order.get('article')}  ×{order.get('quantite')}")
    log("SERVER", f"║  Prix unit : {order.get('prix_unitaire')} €")
    log("SERVER", f"║  Total     : {order.get('quantite', 0) * order.get('prix_unitaire', 0):.2f} €")
    log("SERVER", f"║  Adresse   : {order.get('adresse_livraison')}")
    log("SERVER", f"║  Carte     : {order.get('carte_masquee')}")
    log("SERVER", f"║  ─────────────────────────────────────────────")
    log("SERVER", f"║  Cert CA   : {'✅ valide' if cert_ok else '❌ INVALIDE'}")
    log("SERVER", f"║  Signature : {'✅ valide' if sig_ok else '❌ INVALIDE'}")
    log("SERVER", "╚" + "═"*52)

    if not (cert_ok and sig_ok):
        log("SERVER", "Commande REJETÉE ❌")
        return None

    return order


def send_receipt(aes_key: bytes, my_cert: dict, my_priv, order: dict):
    """Envoie un reçu chiffré + signé au client."""
    receipt = {
        "statut":          "CONFIRMÉE",
        "numero_commande": f"CMD-{int(time.time())}",
        "article":         order["article"],
        "quantite":        order["quantite"],
        "total":           f"{order['quantite'] * order['prix_unitaire']:.2f} €",
        "livraison":       order["adresse_livraison"],
        "message":         "Merci pour votre achat ! Livraison sous 48h.",
        "timestamp":       int(time.time()),
    }
    raw       = json.dumps(receipt, sort_keys=True).encode()
    empreinte = sha1(raw)
    signature = rsa_sign_sha1(my_priv, empreinte)
    iv, ct    = aes_encrypt(aes_key, raw)

    chan_send("SERVER", "CLIENT", "RECEIPT", {
        "encrypted":   ct.hex(),
        "iv":          iv.hex(),
        "signature":   signature.hex(),
        "certificate": my_cert,
    })
    log("SERVER", f"Reçu envoyé au client  (n° {receipt['numero_commande']})")


def main():
    print()
    log("SERVER", "═"*52)
    log("SERVER", "  shop.example.com — Serveur boutique")
    log("SERVER", "═"*52)

    chan_init()

    # Démarre la CA dans un thread de fond
    ca = InternalCA()
    ca_thread = threading.Thread(target=ca.run, args=(2,), daemon=True, name="CA")
    ca_thread.start()

    # Le serveur s'enregistre lui-même
    my_cert, my_priv = register()

    # Handshake avec le client
    aes_key, client_cert = handshake(my_cert)

    # Commande
    order = receive_order(aes_key, client_cert, my_cert, my_priv)

    if order:
        send_receipt(aes_key, my_cert, my_priv, order)

    log("SERVER", "Session terminée.")


if __name__ == "__main__":
    main()
