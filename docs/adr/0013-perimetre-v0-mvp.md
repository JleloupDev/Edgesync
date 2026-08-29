<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0013 — Périmètre v0 (MVP) et limites différées

**Statut** : Accepté

## Contexte

Les limites du POC ont été passées en revue une par une. Objectif désormais : un
protocole **fonctionnel pour un MVP** — pas *production-ready* — assez solide pour
que **l'architecture de l'app se base dessus**, puis retour au dev de l'app.

## Décision

**Figer le périmètre v0.** Le protocole est fonctionnellement complet pour de la
collaboration E2E **mono-ressource** : identité (2 paires), clés en enveloppe
`K_vault→K_doc`, rotation, **révocation best-effort**, signature d'auteur (porte
« utilisateur connu »), catch-up, **persistance** (contenu chiffré au repos). 18
tests verts, typecheck strict.

**Aucune** des limites ci-dessous n'est jugée essentielle au MVP : elles seront
traitées quand un besoin réel les justifiera.

## Limites différées (récapitulatif)

| Limite | Renvoi | Impact |
|---|---|---|
| Blanchiment / signature d'auteur durable / op-log / ACL (B2) | [ADR-0005](0005-encrypt-a-lenvoi-revocation-forward-only.md), [ADR-0009](0009-signature-auteur-utilisateur-connu.md) | écriture best-effort |
| Ordre faisant autorité / multi-admin / owner dynamique | [ADR-0010](0010-ordre-faisant-autorite-differe.md) | mono-owner only |
| Vérif hors-bande / transparence (TOFU → S4) | [ADR-0012](0012-verification-hors-bande-differee.md) | MITM 1ᵉʳ contact |
| Liste de révocation (durable face à un re-`HELLO` du révoqué) | README POC | révocation best-effort |
| Rotation indépendante par note (époques vault/doc séparées) | [ADR-0007](0007-modele-cles-enveloppe.md) | granularité |
| `HELLO` sans challenge mutuel (rejeu de session) | — | **faible** (session stérile : per-op auth + clés scellées) |
| Autorité de snapshot non restreinte | — | intégrité (avec op-log) |
| Forward-secrecy du canal de wrap (sealed-box, pas de ratchet) | — | compromission `boxPriv` → wraps passés |
| Métadonnées en clair (tailles, timing, n° d'époque) | — | analyse de trafic |
| Robustesse / DoS (limites de taille, rate-limit, fuzzing) | — | durcissement |
| Vault multi-notes (`K_vault` partagé cross-doc) | — | l'app compose N `Session` |

## Contrat d'intégration (ce que l'app fournit)

Le protocole est agnostique ; pour s'en servir, l'app remplit ces emplacements :

- **`ITransport`** — adaptateur vers le réseau réel (SignalR, WebRTC, libp2p…).
- **`IStorage`** — adaptateur qui **chiffre les blobs `secret/`** au repos
  ([ADR-0011](0011-persistance-port-istorage.md)) ; et choisit *quand* appeler
  `Session.persist()`.
- **Canal hors-bande** — si mode S4 (comparaison d'empreintes), [ADR-0012](0012-verification-hors-bande-differee.md).
- **Composition d'un vault** — une `Session` pour le répertoire du vault + une par
  note (chaque `Session` = une ressource). Le partage d'une note sans le vault et le
  grant unique pour tout le vault (`K_vault` partagé cross-doc) sont **différés** :
  en v0 chaque ressource a son keyring indépendant.

## Conséquences

- On **repasse au dev de l'app**, en la basant sur ce protocole.
- Le périmètre v0 est stable : ces limites sont documentées, pas oubliées.
