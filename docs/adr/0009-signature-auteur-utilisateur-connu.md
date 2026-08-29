<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0009 — Signature d'auteur : autorisation par utilisateur connu (B1)

**Statut** : Accepté

## Contexte

L'enveloppe signe déjà chaque op par son producteur (`signerPub`) — donc, pour les
ops directes, *l'auteur*. Mais `onOp` ne se servait pas de cette signature pour
décider : elle était vérifiée *valide*, jamais confrontée à un ensemble d'identités.
Deux portées possibles : **B1** (la signature de l'utilisateur, sans droits, que
l'ACL remplacera) ou **B2** (signature d'auteur *durable* sur l'op CRDT, fondation
sans migration). B2 impose un journal de changements signés (les blobs Yjs mergés ne
portent pas l'auteur). Choix : **B1**, migration vers B2 assumée plus tard.

## Décision

- L'**auteur** d'une op est `signerPub` (déjà dans l'enveloppe).
- `onOp` n'accepte que les ops dont `signerPub` est un **utilisateur épinglé**
  (`PeerStore.knowsSigner`, TOFU au `HELLO`). **Aucun droit** n'est évalué.
- L'ACL remplacera plus tard cette porte « utilisateur connu » par « **membre
  autorisé à la position** » — sans changer le champ `signerPub`.
- On n'ajoute **pas** la signature interne durable (plaintext-bound) : c'est B2.

## Conséquences

- **Bloque** l'injection par une identité jamais rencontrée (clé de doc fuitée mais
  pas de handshake). Test `session.inproc` (b1).
- **Ne bloque pas** un révoqué *épinglé* (c'est le rejet d'époque, [ADR-0005](0005-encrypt-a-lenvoi-revocation-forward-only.md)),
  ni le **blanchiment** (niveau enveloppe).
- **Non durable** : sur les chemins `SYNC_RESP` / snapshot, `signerPub` est le
  **relayeur**, pas l'auteur d'origine. L'attribution par-op durable et la fermeture
  du blanchiment exigent **B2** (journal de changements signés) — migration attendue.
- Coût quasi nul (le format ne change pas) ; vrai gain : la signature *sert* enfin.
