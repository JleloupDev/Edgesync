<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0014 — Chaîne d'époques : l'ordre faisant autorité

**Statut** : Accepté — remplace le report acté par [ADR-0010](0010-ordre-faisant-autorite-differe.md)

## Contexte

L'ACL n'existait pas dans le protocole : `Session` recevait un prédicat
`isAuthorized(signPub) → boolean` injecté par l'application, qui répondait
« maintenant » au lieu de « à la position causale de l'op ». Deux pairs qui
apprennent une révocation à dix minutes d'écart divergeaient donc définitivement
sur le contenu du document.

Un vault maintient deux états qui changent ensemble mais ne se comportent pas
pareil. **Deux listes de membres fusionnent toujours** — on met les lignes bout à
bout. **Deux clés ne fusionnent jamais**, et l'entropie fraîche est indispensable
à la révocation, sans quoi le révoqué recalculerait la nouvelle clé. Deux
administrateurs qui révoquent en concurrence produisaient donc deux clés pour la
même époque, et le vault se scindait en deux moitiés sourdes l'une à l'autre sans
que personne ne s'en aperçoive.

## Décision

Une **structure unique** : une chaîne d'époques, chaînée par hash, qui porte à la
fois le journal d'ACL et les engagements de clé.

```
Époque { prev, height, round, ops[], keyCommit?, sigs[] }
```

- **Une op hors époque n'a aucun effet.** Elle circule, c'est tout. La distinction
  en-attente / committé devient structurelle au lieu d'être un statut à gérer.
- L'époque N se valide contre l'ensemble d'arbitres défini par l'époque N−1, et
  ainsi de suite jusqu'à la racine — personne ne peut invalider rétroactivement
  l'historique en changeant les arbitres.
- Le consensus linéarise, donc **une chaîne suffit** : ni DAG, ni journal séparé,
  ni point de finalité distinct.
- `keyCommit` est un **engagement** — `sha256(K_vault)` — jamais la clé. La chaîne
  est publique ; la clé voyage scellée par destinataire dans un message `KEY`, et
  l'engagement permet au destinataire de vérifier qu'on lui a remis la bonne.
- L'`epochId` d'une enveloppe désigne une **position**, pas une clé : l'autorisation
  lit l'état à cette position, le déchiffrement remonte au dernier changement de clé.

## Conséquences

- `isAuthorized` disparaît au profit de `resolveAccess(signPub, epochId) → Access`.
- La synchronisation devient un **intervalle linéaire** (« donne-moi les époques
  après celle-ci »), au lieu d'une réconciliation de graphe.
- L'élagage redevient possible : garder les en-têtes, jeter les ops.
- La règle stricte « l'op doit être à l'époque courante » disparaît — l'autorisation
  à la position la rend redondante, ce qui rend à un relais `pull` la capacité de
  resservir du contenu stocké après une rotation.
- La genèse ne peut pas être certifiée (aucun ensemble d'arbitres antérieur) : elle
  est acceptée en confiance au premier usage. C'est exactement là que viendra
  s'attacher l'identifiant de vault auto-certifiant.
