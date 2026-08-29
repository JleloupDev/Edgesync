<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0011 — Persistance via port `IStorage`, chiffrement au repos délégué à l'app

**Statut** : Accepté

## Contexte

Rien ne survivait à un redémarrage (identité, keyring, peerstore, contenu — tout en
mémoire) : un pair revenait avec une **nouvelle identité** et **sans accès au passé**.
Mais EdgeSync est un *protocole de communication* : le **chiffrement au repos n'est
pas son rôle**, c'est une décision applicative. Subtilité : le contenu *ne transite*
jamais en clair, mais *existe* en clair en RAM (déchiffré pour être édité) — donc le
persister **matérialisé** le ferait fuir sur disque.

## Décision

- **Port `IStorage`** (`get`/`set`/`delete` octets par clé). Le protocole persiste à
  travers lui et **ne sait rien** du chiffrement au repos.
- **Namespaces de sensibilité** : `secret/…` (identité, keyring — un adaptateur prod
  **doit** chiffrer) ; `open/…` (clés publiques ; ciphertext produit par le protocole).
- **Contenu persisté en ciphertext** (réutilise `K_doc`) → jamais en clair au repos,
  **même** sous un adaptateur en clair. Seuls les secrets racines (clé privée
  d'identité, keyring) — qui *ne transitent jamais* et ne peuvent pas être protégés
  par le keyring lui-même — exigent la protection de l'app.
- **Adaptateurs POC** : `InMemoryStorage`, `FileSystemStorage` (en clair). En prod,
  l'app injecte un adaptateur chiffrant pour `secret/`.
- **`Session.persist()`** expose l'action ; le *quand* (debounce, sur dispose…) est
  au choix de l'app, pas câblé dans le cœur.

## Conséquences

- Découplage net : le protocole ne porte aucun Argon2id / passphrase.
- Identité **stable** + lecture du passé après redémarrage ; contenu survit offline.
- Le contenu au repos hérite de la confidentialité du protocole (clé `K_doc`).
- Reste à l'app : adaptateur chiffrant pour `secret/` + politique de *quand* persister.
- Validé par `persistence.test` (in-memory + filesystem ; contenu vérifié ciphertext).
