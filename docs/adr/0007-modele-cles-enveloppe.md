<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0007 — Modèle de clés en enveloppe `K_vault→K_doc`

**Statut** : Accepté (décision Q1)

## Contexte

Deux options pour la v0 : une clé de contenu unique par ressource, ou la hiérarchie
en enveloppe (un `K_vault` qui emballe des `K_doc` par note).

## Décision

**Enveloppe `K_vault → K_doc` dès la v0.** `K_vault` (par époque) emballe une
`K_doc` aléatoire par note ; les ops sont chiffrées sous `K_doc` ; le wrap
`Enc(K_vault, K_doc)` voyage avec la donnée. **Pas de dérivation.**

## Conséquences

- `K_vault` est un **passe-partout** : partager un vault = un seul `wrap(PK, K_vault)`,
  pas N clés.
- `K_doc` reste **indépendamment scellable** vers un pair externe → partage d'une
  note sans donner le vault (test `keyring` « partage de note »).
- v0 : époques vault et doc avancées **ensemble** ; rotation indépendante par note
  différée (la structure la permet déjà).
- Plus de code qu'une clé unique, mais fidèle au modèle cible.
