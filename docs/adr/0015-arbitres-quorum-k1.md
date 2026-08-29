<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0015 — Arbitres : ordre seul, quorum impair, k=1 en v1

**Statut** : Accepté

## Contexte

Le problème de l'ACL est, au fond, un problème **d'ordonnancement** et de
**sous-réseaux divergents**. Sans point de référence, deux moitiés d'un réseau
coupé prennent chacune des décisions d'autorité et il faut ensuite fusionner deux
histoires contradictoires.

## Décision

Un ensemble d'**arbitres** connus de tous, qui s'accordent entre eux sur l'ordre —
et sur rien d'autre.

- **Ils ordonnent, ils n'autorisent pas.** Chaque op reste signée par son
  initiateur, et cette signature est vérifiée par **tous les pairs**, pas seulement
  par les arbitres. Un quorum ne peut donc ni usurper une identité, ni exercer un
  droit qui n'est pas le sien. Il peut censurer et réordonner — rien de plus.
- **Tout nœud émet, seuls les arbitres committent.** Une demande circule par gossip
  et n'a aucun effet tant qu'elle n'est pas dans une époque.
- **k est toujours impair** ; avec un k pair, une partition 50/50 gèle les deux
  moitiés. Si le nombre de candidats est pair, on écarte le moins gradé.
- **L'ensemble ne dépend jamais de la présence** — la présence est précisément ce
  qui diffère de part et d'autre d'une partition ; deux moitiés qui tirent chacune
  ses arbitres atteindraient chacune un quorum et avanceraient.
- **Il y a toujours au moins un arbitre** : par défaut le plus gradé, calculé depuis
  l'ACL. Pas de seuil d'activation, pas de bascule, un seul mode.
- **Un arbitre ne signe jamais deux candidats différents à la même paire
  `(hauteur, round)`.** Deux quorums d'un ensemble impair s'intersectent
  nécessairement, donc forker exige une **majorité corrompue**, pas un seul
  arbitre déviant.
- **En v1, arbitre = admin, et k=1** : l'arbitre signe seul, il n'y a aucun
  algorithme de consensus à écrire.

## Conséquences

- Plus de duels, plus de bulles de concurrence, plus de fork d'époque en
  fonctionnement normal.
- Lors d'une partition, au plus une moitié détient le quorum : elle continue,
  l'autre gèle son ACL mais **continue d'éditer ses documents**. À la réparation,
  la moitié gelée n'a rien produit à fusionner.
- Sans quorum : plus de promotion, plus de nouvelle époque. Mais le contenu
  continue de circuler et la clé continue d'être redonnée. **L'arbitrage n'est
  jamais une condition de progression, seulement un accélérateur de décision.**
- **Dette assumée** : dès que k ≥ 3 sera réellement utilisé, il faudra un
  algorithme éprouvé — pas un consensus maison. La forme de la chaîne ne changera
  pas ; seul le mécanisme qui produit le certificat changera. Le champ `round`
  existe déjà pour ça.
- À k=1, un arbitre compromis ne peut pas committer son propre retrait. Le recours
  est la voie de secours des owners, limitée aux seuls retraits d'arbitres.
