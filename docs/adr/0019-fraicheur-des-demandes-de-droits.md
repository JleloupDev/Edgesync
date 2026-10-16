<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0019 — Fraîcheur des demandes de droits : base, historique, backlink

**Statut** : Accepté

## Contexte

Une `AclOp` ne portait que `{group, changes, issuer, sig}`. Signée hors du temps,
elle restait valable pour toujours. EdgeSync-bench l'a montré (`rejeu-acl`) :
rejouer une ancienne admission après une révocation remettait le révoqué dans le
vault. Les époques ne protégeaient rien, car l'op n'en citait aucune : l'arbitre
pouvait la remettre dans une nouvelle époque.

Deux autres défauts du même ordre :

- **Le désordre d'un même émetteur.** Un admin signe « B lecteur » puis « B
  admin ». Le réseau, gossip compris, ne garantit pas l'ordre. L'arbitre peut
  appliquer le second en premier, et le résultat est l'inverse de l'intention.
- **Les décisions concurrentes sur un même membre**, prises par deux admins sans
  s'être vus. L'ordre de l'arbitre tranche seul, sans que personne le sache.

Les autres systèmes ancrent tous leurs opérations : identifiant par hash
(Matrix, any-sync, Keyhive), position ou prédécesseurs cités (`PrevId`
d'any-sync, `prev_events` de Matrix, `after_revocations` de Keyhive, `previous`
de p2panda), numéro de séquence par auteur (`seq_num` et `backlink` de p2panda).

## Décision

Trois règles, toutes jugées sur la chaîne seule, donc identiques chez tous les
pairs.

1. **Base.** L'op signe l'époque en tête quand son émetteur l'a créée. Elle ne
   s'applique que si **aucune rotation de clé** n'a eu lieu entre sa base et la
   tête. Une rotation signifie que quelqu'un a perdu le droit de lire : toute
   décision antérieure doit être reprise en connaissance de cause. La règle stricte
   d'any-sync (base = tête exacte) est écartée : elle fait se gêner tous les admins
   actifs en même temps, intenable à plusieurs milliers de pairs.
2. **Historique.** L'état de la chaîne retient les identifiants (hash) des ops
   appliquées depuis la dernière rotation. Une op déjà appliquée ne s'applique pas
   deux fois. L'historique se vide à chaque rotation. Il est tenu par **tous** les
   pairs : les arbitres pour décider, les autres pour vérifier (D39).
3. **Backlink.** `prev` désigne l'op précédente **du même émetteur** (par clé
   d'appareil), pas celle d'un autre. L'arbitre ne committe une op que si `prev`
   est la dernière op appliquée de cet émetteur ; sinon il la met en attente
   (bornée, vidée à chaque rotation). La chaîne de backlinks repart à zéro à chaque
   rotation.

Une op qui échoue ces règles est **inerte**, comme une op non autorisée : elle
peut figurer dans une époque sans effet. Même un arbitre fautif ne la fait pas
passer.

| Verdict | Sens |
| --- | --- |
| `ok` | s'applique |
| `wait` | sa précédente n'est pas encore appliquée |
| `stale` | pas de base, base inconnue, ou rotation depuis la base |
| `replay` | déjà appliquée dans cette époque de clé |
| `fork` | deux ops derrière la même précédente, ou deux « premières » : équivocation signée |
| `unauthorised` | l'émetteur n'a pas le droit |

**Détection des conflits.** Une op qui touche un membre modifié par un autre
émetteur **après sa base** est signalée (`onAclConflict`). Elle s'applique quand
même : qui a raison n'est pas l'affaire du protocole (D21, D34). Le gel reste la
cible.

**Côté émetteur.** La session ancre chaque demande sur sa tête et la chaîne à sa
dernière demande encore en vol, ou à sa dernière demande appliquée. Une demande
qui ne peut pas s'appliquer sur sa propre tête n'est pas retenue comme maillon :
sinon toutes les suivantes attendraient une précédente qui ne s'applique jamais.

**Rotation (D11) corrigée au passage.** La clé tourne quand quelqu'un **perd le
droit de lire**, jugé sur l'état résolu : retrait, mais aussi rétrogradation sous
`read`, ou groupe qui passe sous `read`. Avant, seul `remove` faisait tourner la
clé : un membre passé en `pull` continuait de lire tout le futur. À l'inverse,
retirer un relais qui n'avait que `pull` ne fait plus tourner la clé.

**Format.** `AclOp` gagne `base` (32 octets) et `prev` (32 octets), optionnels,
signés : `body = … [issuer:32][flags:1]([base:32])([prev:32])`. Seules les ops de
la genèse n'ont pas de base.

## Conséquences

- Le rejeu du bench est fermé, même après un redémarrage de l'arbitre (sa mémoire
  de gossip perdue). Scénarios `rejeu-acl`, `demande-perimee`,
  `desordre-emetteur`, `fourche-emetteur`, `admins-concurrents`,
  `retrogradation-sous-lecture`, `rotations-massives`.
- Une demande en vol au moment d'une rotation est perdue : l'émetteur doit la
  resigner. Aucun message ne le lui dit encore.
- Chaque op pèse 65 octets de plus. Mesuré : environ 385 octets par époque au lieu
  de 321.
- **Limites connues** :
  - une précédente refusée **plus tard** par l'arbitre, alors qu'elle passait chez
    l'émetteur, bloque les suivantes jusqu'à la prochaine rotation ;
  - les conflits ne sont visibles que de l'arbitre ;
  - un vault qui ne retire jamais personne voit son historique grossir sans fin.
    Une rotation périodique ou une fenêtre bornerait cela.
- **À venir** : racine de Merkle de l'historique dans chaque époque (preuves
  d'inclusion pour un pair élagué, détection d'équivocation), limite de demandes
  par émetteur et par époque de clé (A9), `Reject` explicite pour une demande
  périmée.
