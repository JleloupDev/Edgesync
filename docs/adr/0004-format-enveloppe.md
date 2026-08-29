<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0004 — Format d'enveloppe des ops

**Statut** : Accepté

## Contexte

Chaque op CRDT doit voyager chiffrée, signée, et porter de quoi choisir la clé de
déchiffrement. Le format est un contrat de fil : le changer plus tard = migration.

## Décision

Enveloppe binaire figée :

```
[ epoch:4 ][ nonce:24 ][ ciphertext:N ][ sig:64 ][ signerPub:32 ]
```

- **epoch** (uint32 BE) en **clair** : indice de déchiffrement, auto-validé par
  l'AEAD (un mauvais tag fait échouer le déchiffrement → aucune confiance requise).
- **ciphertext** : XChaCha20-Poly1305 (nonce 24 o, pas de compteur).
- **sig** : Ed25519 sur `epoch‖nonce‖ciphertext` (lie l'époque au chiffré).
- **signerPub** : clé publique de signature de l'auteur.

## Conséquences

- Le relais (même aveugle) peut lire l'époque pour rejeter une poussée périmée
  ([ADR-0005](0005-encrypt-a-lenvoi-revocation-forward-only.md)).
- Chiffrement ⊥ signature : l'AEAD authentifie le groupe, la signature l'individu.
- Le wrap de clés vers un pair utilise une sealed-box séparée (ephPub‖nonce‖ct).
