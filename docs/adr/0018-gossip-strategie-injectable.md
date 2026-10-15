<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0018 — Gossip : relais à l'identique, stratégie injectable

**Statut** : Accepté

## Contexte

Aucun message ne dépassait les voisins directs. Un `Op` n'était jamais
retransmis, une `AclRequest` n'atteignait pas un arbitre non voisin, une époque
adoptée n'était pas relayée. Hors maillage complet, tout reposait sur le
rattrapage : plus lent, et re-signé par celui qui répond, donc sans l'auteur
d'origine. Un réseau pair-à-pair dans cet état est inutilisable.

La stratégie de diffusion évoluera (Plumtree, vue partielle HyParView,
bibliothèque externe). Elle doit pouvoir changer vite, sans toucher au cœur.

## Décision

- **Port `IBroadcast`** : `seen(bytes)` et `spread(bytes, from?)`. Injecté dans
  `Session` (`SessionOpts.broadcast`). La session décide **quoi** diffuser, la
  stratégie décide **où**.
- **Premier adaptateur : `FloodBroadcast`.** Chaque message part vers tous les
  voisins sauf celui d'où il vient, une seule fois. Mémoire bornée des messages
  vus (empreinte SHA-256, 10 000 par défaut, le plus ancien oublié d'abord).
- **Messages relayés** : `Op`, `AclRequest`, `EpochPush`. `Key`, `Hello` et le
  rattrapage (`SyncReq`, `SyncResp`, `StatePush`, `ChainReq`, `ChainResp`)
  restent point à point.
- **Relais à l'identique**, octet pour octet. Un `Op` relayé garde la signature
  de son auteur : le canal de logs (section K de la description du protocole)
  reste juste.
- **On ne relaie que ce qu'on a vérifié** :
  - `Op` : signature, et droit `write` de l'auteur à sa position. Pas besoin de la
    clé de contenu : un pair `pull` relaie sans lire.
  - `AclRequest` : signature, et l'op s'appliquerait sur notre tête de chaîne.
  - `EpochPush` : seulement une fois adoptée, donc validée.
- **Un message invalide n'est pas mémorisé.** Seul `spread` mémorise. Un message
  qu'on ne peut pas encore valider (pair en retard) garde sa chance si une copie
  revient plus tard.

## Conséquences

- Une modification, une demande ou une époque traverse n'importe quelle
  topologie connexe. Testé en ligne A–B–C et en triangle (`test/gossip.test.ts`).
- Un inondeur ne fait pas travailler le réseau : un message invalide meurt au
  premier saut.
- Coût de l'inondation : un message par lien et par message. Correct pour
  quelques centaines de pairs ; au-delà, un autre adaptateur derrière le même
  port.
- Le bus de test accepte une topologie (`new Bus(links)`) et journalise qui envoie
  quoi à qui (`bus.frames`).
- **Non traité ici** :
  - relayer aux non-membres : aujourd'hui, on envoie à tous les voisins ;
  - la perte de trames, qui relève de l'anti-entropie ;
  - le rejeu des demandes de droits, que le gossip rend plus facile.
