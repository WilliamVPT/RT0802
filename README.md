# RT0802 - Boutique securisee (Client/Serveur)

Ce projet simule une boutique en ligne securisee en Python, avec :

- une CA interne (Autorite de Certification) lancee par le serveur,
- une authentification par certificats simplifies,
- un echange de cle via Diffie-Hellman,
- un canal chiffre en AES-128-CBC,
- des signatures RSA/SHA-1 pour verifier l'integrite des messages.

Le transport reseau est simule par depots de fichiers JSON dans un dossier partage `channel/`.

## Objectif pedagogique

Le projet illustre de bout en bout un schema type TLS simplifie :

1. Distribution de confiance (certificat CA)
2. Emission de certificats client/serveur
3. Handshake DH pour etablir une cle symetrique
4. Echange de donnees chiffrees et signees

## Structure du projet

- `server.py` : serveur boutique + CA interne (thread)
- `client.py` : client qui passe une commande puis recoit un recu
- `shared.py` : primitives crypto + transport par fichiers JSON
- `ca_cert.json` : certificat CA genere au demarrage du serveur
- `channel/` : messages JSON echanges entre composants

## Prerequis

- Python 3.10+
- Package Python : `cryptography`

Installation :

```powershell
pip install cryptography
```

## Lancement rapide

Ouvrir 2 terminaux dans le dossier du projet.

### Terminal 1 : serveur

```powershell
python server.py
```

Le serveur :

- initialise le canal (`channel/`),
- demarre la CA interne,
- s'enregistre aupres de la CA pour obtenir son certificat,
- attend le client,
- verifie la commande et renvoie un recu chiffre et signe.

### Terminal 2 : client

```powershell
python client.py
```

Le client :

- attend `ca_cert.json`,
- demande son certificat a la CA,
- effectue le handshake DH avec le serveur,
- envoie une commande chiffree et signee,
- recoit puis verifie le recu.

## Exemple avec arguments

```powershell
python client.py --name "Alice" --article "Casque audio" --qty 2 --prix 79.99 --adresse "12 rue de la Paix, 75001 Paris" --carte "**** **** **** 4242"
```

Options disponibles cote client :

- `--name` : nom du client
- `--article` : article commande
- `--qty` : quantite
- `--prix` : prix unitaire
- `--adresse` : adresse de livraison
- `--carte` : carte masquee (texte)

## Deroulement du protocole

1. **CA interne (serveur)**
	- Genere un certificat auto-signe `ShopCA` (`ca_cert.json`)
2. **Enregistrement serveur**
	- `SERVER -> CA : CSR`
	- `CA -> SERVER : CERTIFICATE`
3. **Enregistrement client**
	- `CLIENT -> CA : CSR`
	- `CA -> CLIENT : CERTIFICATE`
4. **Handshake**
	- `CLIENT -> SERVER : HELLO` (certificat client + `g^x`)
	- `SERVER -> CLIENT : HELLO_ACK` (certificat serveur + `g^y`)
	- Derivation de la cle AES-128 partagee
5. **Commande**
	- `CLIENT -> SERVER : ORDER` = `AES128(D)` + `SHA1(D)` signe RSA + certificat client
6. **Recu**
	- `SERVER -> CLIENT : RECEIPT` = `AES128(R)` + `SHA1(R)` signe RSA + certificat serveur

## Notes techniques

- RSA : 2048 bits, PKCS#1 v1.5
- Empreinte : SHA-1 (choix impose par le sujet)
- DH : groupe RFC 3526 (2048 bits)
- Chiffrement symetrique : AES-128-CBC + padding PKCS7

## Limites (normales pour un mini-projet)

- Le transport par fichiers JSON n'est pas un vrai reseau socket.
- Les certificats sont des structures simplifiees (pas des X.509 complets).
- SHA-1 est utilise pour correspondre au cahier pedagogique, pas pour un usage moderne en production.

## Depannage

- Si le client reste bloque sur la CA : lancer d'abord `server.py`.
- Si des messages precedents perturbent l'execution : relancer le serveur (il nettoie `channel/`).
- Si `cryptography` manque : reexecuter `pip install cryptography`.