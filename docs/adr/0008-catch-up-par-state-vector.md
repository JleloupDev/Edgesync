<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0008 — Catch-up par state-vector

**Statut** : Accepté (décision Q4)

## Contexte

En P2P pur, un pair se déconnecte et revient souvent : il doit rattraper ce qu'il a
manqué. Sans mécanisme de catch-up, deux pairs reconnectés ne se resynchronisent pas.

## Décision

Inclure les messages **`SYNC_REQ` / `SYNC_RESP`** dès la v0. Au handshake (et après
chaque import de clé), un pair envoie son **state-vector** ; l'autre répond avec le
**diff** manquant, chiffré sous l'époque courante (encrypt-à-l'envoi).

## Conséquences

- Convergence après coupure, rotation, ou arrivée tardive (tests c, e).
- `SYNC_RESP` est exempté du rejet « époque périmée » (il porte légitimement de
  l'état historique).
- Réutilise `stateVector` / `diffSince` du port `ICrdt` (natifs côté Yjs).
- Surface un peu plus large que le strict minimum, justifiée par le P2P.
