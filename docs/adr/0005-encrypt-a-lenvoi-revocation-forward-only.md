<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0005 — Chiffrement-à-l'envoi & révocation forward-only

**Statut** : Accepté

## Contexte

Comment révoquer l'écriture, pas seulement la lecture ? Filtrer « les ops d'une
époque antérieure » casserait le membre honnête resté hors-ligne, indistinguable du
révoqué par la seule époque.

## Décision

- **Chiffrement-à-l'envoi** : un pair ne pousse jamais de vieux chiffré ; à la
  reconnexion il reçoit la clé courante et chiffre sa delta sous l'**époque
  courante**. La frontière de poussée est donc toujours à l'époque courante.
- **Révocation forward-only** : la rotation révoque la **lecture**. La **révocation
  d'écriture** se confond alors avec « détenir la clé courante = droit d'écrire » :
  le révoqué n'obtient pas la nouvelle clé → ses poussées sont en époque périmée →
  **rejetées à l'ingestion** (le tag d'époque en clair permet ce rejet même à un
  pair/serveur aveugle).
- **Course honnête** (pair en ligne pas encore au courant d'une rotation) → son op
  vieux-époque est rejetée par les pairs déjà rotés, puis re-livrée sous l'époque
  courante quand il reçoit la nouvelle clé (`onKey` re-pousse l'état) ; Yjs
  dédoublonne, donc rien n'est perdu ni dupliqué.
- **Rejet sur tous les chemins.** Le rejet d'époque périmée s'applique *aussi* au
  `SYNC_RESP` : grâce au chiffrement-à-l'envoi, un `SYNC_RESP` honnête est toujours à
  l'époque courante, donc aucune exemption n'est nécessaire. Exempter le `SYNC_RESP`
  était une faille (un révoqué pouvait y faire passer une op vieux-époque).

## Conséquences

- En **P2P pur** : best-effort (pas de tiers always-on pour refuser ; security
  §1.7.2).
- L'historique de clés sert à *lire* le passé, pas à *accepter* du vieux-époque.
- **Limite résiduelle — blanchiment.** Un pair honnête *en retard* (pas encore roté)
  accepte l'op vieux-époque du révoqué, puis la re-pousse sous l'époque courante,
  signée de lui : le contenu du révoqué entre alors « légitimement ». Le rejet
  d'époque ne l'attrape pas, car il porte sur le *chiffreur*, jamais sur l'*auteur*
  de l'op CRDT. Fermeture durable = **signer l'op CRDT par son auteur + ACL**
  (op-log, phase 7) ; en P2P, résidu réglé par arbitrage owner (revoke-wins).
- Variante zéro-confiance/audit (op-log + position) différée en phase 7.
- Validé par `session.inproc` (c), (d) et (d2 : contournement `SYNC_RESP` fermé).
