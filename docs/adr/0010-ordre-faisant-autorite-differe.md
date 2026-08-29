<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0010 — Ordre faisant autorité différé (mono-owner v0)

**Statut** : Accepté

## Contexte

Le **contenu** est un CRDT : il converge sans ordre total. Seul le **plan de
contrôle** (attribution des époques, plus tard l'appartenance/ACL) a besoin d'un
ordre. Or l'époque est un **entier local** (`currentEpoch + 1`) : deux rotateurs
concurrents minent chacun « époque N » avec des clés différentes → `import` garde le
premier arrivé → **split-brain**. Latent : en **mono-owner**, un seul pair rote,
donc jamais de rotation concurrente.

## Décision

- **Rester mono-owner en v0** (un seul détenteur de clés `granting` rote).
- Le vrai correctif de #2 est un **journal de contrôle chaîné, signé, ordonné par
  l'autorité** (« assignation centralisée + vérification décentralisée », §1.7.1 ;
  *consensus node* any-sync, §6.3) — c'est **le même substrat que l'op-log** (B2 /
  ACL). On ne le fait donc **pas isolément** : il arrivera **avec** l'op-log.
- Pas d'« époque-chaîne » intermédiaire maintenant : sous mono-owner elle n'a pas de
  fork à gérer → investissement sans bénéfice immédiat.

## Conséquences

- **Hors v0** : multi-admin, owner dynamique / passation, P2P sans autorité.
- **Invariant à respecter** : pas de rotation concurrente (un seul rotateur).
- Quand l'op-log arrivera, l'**époque dérivera de la position** dans la chaîne, ce
  qui supprime la collision par construction.
- Documenté aussi comme limite dans le [README du POC](../../poc/edgesync-protocol/README.md).
