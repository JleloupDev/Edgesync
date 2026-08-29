<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0003 — Identité = deux paires de clés

**Statut** : Accepté

## Contexte

Signer et chiffrer-vers-une-clé-publique sont deux opérations distinctes. Ed25519
signe mais ne chiffre rien ; le wrap exige une ECDH (X25519). On pouvait dériver
X25519 depuis Ed25519, mais la conversion est une source classique de bugs.

## Décision

Une identité = **deux paires explicites** : Ed25519 (signe) + X25519 (wrap). Pas de
conversion. Les clés privées sont 32 octets aléatoires (seed Ed25519 / scalaire
X25519 clampé), ce qui évite toute dépendance à une API `randomPrivateKey`.

## Conséquences

- `PeerIdentity = { signPub, boxPub }` ; `OwnIdentity` détient les privées.
- Forme d'identité figée tôt (foreclôt) : la changer = re-migrer toutes les PK.
- `sign`/`verify` (Ed25519) et `seal`/`unseal` (hybride X25519) sont séparés.
