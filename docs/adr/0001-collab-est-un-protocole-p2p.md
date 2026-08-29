<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0001 — La collaboration est un protocole P2P

**Statut** : Accepté

## Contexte

La collaboration pouvait être conçue autour du serveur (relais SignalR + hubs)
avec un fork de code client/serveur. On vise au contraire un socle dont les usages
(serveur, P2P, hybride) ne sont qu'une configuration.

## Décision

La couche de collaboration est **un protocole pair-à-pair réutilisable**. Chaque
participant est un `Peer` qui tourne la même lib. Le protocole de base est identique
dans tous les scénarios ; rien dans le cœur ne suppose un serveur.

## Conséquences

- Pas de fork client/serveur : un seul code de collaboration.
- Le serveur, s'il existe, devient un *peer headless* ou un *provider* (voir
  [ADR-0002](0002-serveur-hors-protocole.md)).
- Référence d'implémentation : any-sync (MIT).
- Coût : concevoir un vrai protocole (handshake, livraison de clé, catch-up) plutôt
  que de s'appuyer sur un relais central.
