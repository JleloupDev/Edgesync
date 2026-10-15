<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# EdgeSync

Protocole de collaboration **pair-à-pair**, chiffré de bout en bout et signé.
Fonctionne sans serveur ; sait en utiliser un comme super-pair quand il en existe.

Un *vault* regroupe des documents partagés par un groupe de personnes — quelques
centaines au plus, qui se connaissent.

## L'asymétrie qui a tout dicté

Un vault maintient deux états qui changent ensemble mais ne se comportent pas
pareil : **qui est membre**, et **quelle est la clé**.

> Deux listes de membres fusionnent toujours : on met les lignes bout à bout.
>
> Deux clés ne fusionnent jamais. Et l'entropie fraîche est indispensable à la
> révocation — sans quoi le révoqué recalculerait la nouvelle clé lui-même.

Deux administrateurs qui révoquent en même temps produisent donc deux clés
différentes : le vault se scinde en deux moitiés sourdes l'une à l'autre, sans que
personne ne s'en aperçoive. C'est ce problème qui a dicté l'architecture.

## Deux plans, une seule liaison

```
PLAN D'AUTORITÉ
    nœud A      nœud B      nœud C
       \           |           /
        \      demande       /
         +----------------+
         |    ARBITRES    |   accord interne, décision unique
         +----------------+
                  |
     +-------------------------------+
     |  époque publiée · certificat  |
     +-------------------------------+
                  |
                 clé
PLAN DU CONTENU   v
     pair <-----> pair <-----> pair
     CRDT chiffré — ne passe jamais par les arbitres
```

Le contenu reste entièrement sans coordination : deux pairs synchronisent un
document avec zéro administrateur en ligne. Seules les décisions d'autorité
transitent par les arbitres, qui s'accordent **entre eux** puis publient une
décision unique — jamais des votes que le réseau devrait dépouiller.

## Une seule structure

```
Époque {
  prev              chaînage par hash
  height, round
  ops[]             chaque op signée par SON initiateur
  keyCommit?        sha256(K_vault) — jamais la clé
  quorumSignatures  le certificat
}
```

Une op qui n'est dans aucune époque **n'a aucun effet**. L'époque N se valide
contre l'ensemble d'arbitres défini par N−1, jusqu'à la racine.

## Ce qui est garanti, et ce qui ne l'est pas

| | |
|---|---|
| Écriture révoquée | à la position causale, jamais « maintenant » |
| Lecture révoquée | à la rotation suivante, propagée |
| Un révoqué garde ce qu'il a lu | irréductible, aucun système ne fait mieux |
| Forward secrecy | **aucune**, par construction |
| Admin légitime malveillant | aucune parade — seulement détection et réparation |
| Byzantins | détectables et attribuables, pas empêchés |

Le mode pair-à-pair vise des **organisations préexistantes, responsables de la
protection de leur propre réseau**. Ce cadrage justifie l'ACL en clair et le modèle
de menace : un membre invité dont l'appareil est compromis, jamais un inconnu.

## Structure

```
src/core/      identity, envelope, keyring, acl-ops, acl-chain, codec
src/ports/     ICrdt, ITransport, IBroadcast, IStorage, PeerStore
src/adapters/  Yjs, in-process, WebSocket, stockage, diffusion par inondation
src/protocol/  Session (l'orchestrateur), messages, persistance
docs/adr/      les décisions structurantes, ADR-0001 à 0018
docs/          spécifications : ACL et arbitrage, modèle de canal, format de fil
```

Le cœur (`src/core`) est **pur** : aucune E/S, entièrement testable sans réseau ni
stockage. C'est ce qui rend la couche auditable.

## Commandes

```bash
npm install
npm test          # 66 tests
npm run typecheck
npm run peer      # un pair sans interface, sur WebSocket
```

## Documentation

- [`docs/adr/`](docs/adr/) — les décisions, avec leur contexte et leurs conséquences
- [`docs/edgesync-acl-arbitrage-spec.md`](docs/edgesync-acl-arbitrage-spec.md) — la
  spécification ACL complète : décisions, limites assumées, horizons
- [`docs/security-channel-model.md`](docs/security-channel-model.md) — le modèle de canal
- [`docs/edgesync-wire-protocol.md`](docs/edgesync-wire-protocol.md) — le format de fil

Le banc de stress et d'attaque vit dans un dépôt séparé : **EdgeSync-bench**.

## Licence

AGPL-3.0-or-later. Voir [LICENSE](LICENSE).
