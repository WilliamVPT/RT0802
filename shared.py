"""
shared.py — Utilitaires communs (crypto + transport fichier JSON)
═══════════════════════════════════════════════════════════════════

Primitives crypto utilisées (selon le sujet RT802) :
  • RSA-2048 + PKCS1v15/SHA-1   : signature des certificats et des empreintes
  • SHA-1                        : empreinte des données
  • Diffie-Hellman (RFC 3526)    : échange de clé → AES-128
  • AES-128-CBC + PKCS7          : chiffrement des messages

Transport : fichiers JSON dans un dossier partagé (channel/).
"""

import os, json, time, glob, hashlib, struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ─── Chemins ────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CHANNEL_DIR = os.path.join(BASE_DIR, "channel")
CA_CERT_FILE = os.path.join(BASE_DIR, "ca_cert.json")   # partagé entre tous


# ═══ CRYPTO ═════════════════════════════════════════════════════════════════

# ─── RSA ────────────────────────────────────────────────────────────────────

def rsa_generate():
    """Génère une paire RSA-2048."""
    priv = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return priv, priv.public_key()


def rsa_sign_sha1(priv, data: bytes) -> bytes:
    """Signature RSA-PKCS1v15 avec SHA-1 (requis par le sujet)."""
    return priv.sign(data, padding.PKCS1v15(), hashes.SHA1())


def rsa_verify_sha1(pub, data: bytes, sig: bytes) -> bool:
    """Vérifie une signature RSA-PKCS1v15/SHA-1."""
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False


def pub_to_dict(pub) -> dict:
    n = pub.public_numbers()
    return {"n": n.n, "e": n.e}


def pub_from_dict(d: dict):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    return RSAPublicNumbers(d["e"], d["n"]).public_key(default_backend())


# ─── Certificat X.509 simplifié ─────────────────────────────────────────────

def cert_create(subject: str, pub_dict: dict, issuer: str, issuer_priv) -> dict:
    """
    Crée un certificat X.509 simplifié signé par l'issuer.
    Signature = RSA(SHA1(TBS)).
    """
    body = {
        "version":   "X509v3",
        "serial":    int.from_bytes(os.urandom(8), "big"),
        "subject":   subject,
        "issuer":    issuer,
        "not_before": int(time.time()),
        "not_after":  int(time.time()) + 365 * 86400,
        "public_key": pub_dict,
        "sig_algo":   "sha1WithRSAEncryption",
    }
    tbs  = json.dumps(body, sort_keys=True).encode()
    sig  = rsa_sign_sha1(issuer_priv, hashlib.sha1(tbs).digest())
    return {**body, "signature": sig.hex()}


def cert_verify(cert: dict, issuer_pub) -> bool:
    """Vérifie la signature d'un certificat avec la clé publique de l'émetteur."""
    body = {k: v for k, v in cert.items() if k != "signature"}
    tbs  = json.dumps(body, sort_keys=True).encode()
    return rsa_verify_sha1(issuer_pub, hashlib.sha1(tbs).digest(),
                            bytes.fromhex(cert["signature"]))


# ─── SHA-1 ──────────────────────────────────────────────────────────────────

def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


# ─── Diffie-Hellman (groupe RFC 3526 — 2048 bits) ───────────────────────────

DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_G = 2


def dh_generate_private() -> int:
    """Génère une valeur privée DH aléatoire."""
    return int.from_bytes(os.urandom(32), "big") % (DH_P - 2) + 2


def dh_public(x: int) -> int:
    """Calcule g^x mod p."""
    return pow(DH_G, x, DH_P)


def dh_shared(their_pub: int, my_priv: int) -> int:
    """Calcule le secret partagé (their_pub)^my_priv mod p."""
    return pow(their_pub, my_priv, DH_P)


def dh_to_aes_key(shared_secret: int) -> bytes:
    """Dérive une clé AES-128 depuis le secret DH : SHA1(secret)[:16]."""
    return sha1(shared_secret.to_bytes(256, "big"))[:16]


# ─── AES-128-CBC ────────────────────────────────────────────────────────────

def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """AES-128-CBC avec padding PKCS7. Retourne (iv, ciphertext)."""
    iv      = os.urandom(16)
    pad_len = 16 - len(plaintext) % 16
    padded  = plaintext + bytes([pad_len] * pad_len)
    enc     = Cipher(algorithms.AES(key), modes.CBC(iv),
                     backend=default_backend()).encryptor()
    return iv, enc.update(padded) + enc.finalize()


def aes_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    """Déchiffre AES-128-CBC et retire le padding PKCS7."""
    dec    = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    return padded[: -padded[-1]]


# ═══ TRANSPORT (fichiers JSON) ═══════════════════════════════════════════════

def chan_init():
    """Remet le canal à zéro (à appeler au démarrage du serveur)."""
    os.makedirs(CHANNEL_DIR, exist_ok=True)
    for f in glob.glob(os.path.join(CHANNEL_DIR, "*.json")):
        os.remove(f)
    for f in glob.glob(os.path.join(CHANNEL_DIR, ".read_*")):
        os.remove(f)


def chan_send(src: str, dst: str, mtype: str, payload: dict):
    """Dépose un message JSON dans le canal."""
    os.makedirs(CHANNEL_DIR, exist_ok=True)
    seq  = len(glob.glob(os.path.join(CHANNEL_DIR, f"{src}_{dst}_*.json")))
    path = os.path.join(CHANNEL_DIR, f"{src}_{dst}_{seq:04d}_{mtype}.json")
    with open(path, "w") as f:
        json.dump({"src": src, "dst": dst, "type": mtype,
                   "ts": int(time.time() * 1000), "payload": payload}, f, indent=2)


def chan_recv(src: str, dst: str, mtype: str = None, timeout: float = 30.0) -> dict:
    """
    Attend le prochain message src→dst (ou *→dst si src="*").
    Retourne l'enveloppe complète.
    """
    pattern  = os.path.join(CHANNEL_DIR,
                f"{'*' if src == '*' else src}_{dst}_*.json")
    log_path = os.path.join(CHANNEL_DIR, f".read_{'ALL' if src == '*' else src}_{dst}")

    seen = set()
    if os.path.exists(log_path):
        seen = set(open(log_path).read().splitlines())

    deadline = time.time() + timeout
    while time.time() < deadline:
        for fp in sorted(glob.glob(pattern)):
            fname = os.path.basename(fp)
            if fname in seen:
                continue
            try:
                env = json.load(open(fp))
            except Exception:
                time.sleep(0.05)
                continue
            seen.add(fname)
            open(log_path, "a").write(fname + "\n")
            if mtype and env["type"] != mtype:
                continue   # mauvais type, on cherche le suivant
            return env
        time.sleep(0.1)
    raise TimeoutError(f"Timeout ({timeout}s) : pas de {src}→{dst} [{mtype}]")


# ═══ LOGGER ══════════════════════════════════════════════════════════════════

_COLORS = {
    "CA":     "\033[93m",   # jaune
    "SERVER": "\033[92m",   # vert
    "CLIENT": "\033[94m",   # bleu
    "CRYPTO": "\033[95m",   # magenta
    "OK":     "\033[92m",
    "ERR":    "\033[91m",
}
_RST = "\033[0m"

def log(who: str, msg: str):
    c = _COLORS.get(who, "")
    print(f"{c}[{time.strftime('%H:%M:%S')}][{who}] {msg}{_RST}", flush=True)
