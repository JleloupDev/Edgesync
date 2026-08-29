<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0006 — Ports `ICrdt` / `ITransport` (hexagonal)

**Statut** : Accepté

## Contexte

Le protocole doit rester réutilisable : ni cloué à Yjs, ni à un réseau précis. On
veut aussi pouvoir tester en isolation et faire tourner un pair dans un process.

## Décision

Architecture **hexagonale**. Le cœur (`Identity`, `Envelope`, `Keyring`) et
l'orchestrateur (`Session`) dépendent de **ports** :

- `ICrdt` — `onLocalUpdate` / `applyRemote` / `snapshot` / `stateVector` /
  `diffSince`. Adaptateur : `YjsCrdt`.
- `ITransport` — `send` / `onMessage` / `onPeerUp` / `onPeerDown` / `peers`.
  Adaptateurs : `InProcessTransport` (tests) et `WebSocketTransport` (process
  séparés).

Le cœur n'importe **jamais** `yjs` ni `ws`.

## Conséquences

- Swappable : autre CRDT, autre transport (WebRTC/libp2p) = nouvel adaptateur.
- Testable : le même `Session` se teste in-process *et* sur un vrai socket.
- Inversion de dépendances respectée (D de SOLID).
