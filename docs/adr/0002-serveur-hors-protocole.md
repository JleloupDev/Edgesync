<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0002 — Le serveur est hors du protocole

**Statut** : Accepté

## Contexte

Un serveur apporte du confort (haute dispo, découverte, provider de clés/identité)
mais ne doit jamais devenir une racine de confiance ni un point de couplage.

## Décision

Le serveur **n'est pas une brique du protocole**. Il n'intervient que comme
**assistant externe** :
- soit un *peer headless always-on* (il tourne la même lib, sans privilège) ;
- soit un *provider* de clés/identité.

Aucun code du cœur ne contient de `if (server)`. La distinction des rôles
*owner-réseau* (ordre/relais/HA, hébergeable) vs *owner-du-vault* (clés/admission,
jamais le serveur en E2E) est maintenue (security-channel-model.md §1.7.4).

## Conséquences

- Le front ne change pas selon qu'un serveur assiste ou non.
- En S3/S4 le serveur reste aveugle ; en S2 il peut tenir les clés (custodial).
- Le POC se construit et se teste **sans serveur**.
- Limite assumée : pas de refus actif temps-réel en P2P pur (security §1.7.2).
