<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# Architecture Decision Records

Décisions structurantes du protocole de collaboration P2P. Format MADR-lite :
*Statut · Contexte · Décision · Conséquences*. Le « pourquoi » détaillé vit dans
[../security-channel-model.md](../security-channel-model.md) et
[../edgesync-protocol.md](../edgesync-protocol.md).

| ADR | Titre | Statut |
|---|---|---|
| [0001](0001-collab-est-un-protocole-p2p.md) | La collaboration est un protocole P2P | Accepté |
| [0002](0002-serveur-hors-protocole.md) | Le serveur est hors du protocole | Accepté |
| [0003](0003-identite-deux-paires.md) | Identité = deux paires de clés | Accepté |
| [0004](0004-format-enveloppe.md) | Format d'enveloppe des ops | Accepté |
| [0005](0005-encrypt-a-lenvoi-revocation-forward-only.md) | Chiffrement-à-l'envoi & révocation forward-only | Accepté |
| [0006](0006-ports-icrdt-itransport.md) | Ports `ICrdt` / `ITransport` (hexagonal) | Accepté |
| [0007](0007-modele-cles-enveloppe.md) | Modèle de clés en enveloppe `K_vault→K_doc` | Accepté |
| [0008](0008-catch-up-par-state-vector.md) | Catch-up par state-vector | Accepté |
| [0009](0009-signature-auteur-utilisateur-connu.md) | Signature d'auteur : autorisation par utilisateur connu (B1) | Accepté |
| [0010](0010-ordre-faisant-autorite-differe.md) | Ordre faisant autorité différé (mono-owner v0) | Accepté |
| [0011](0011-persistance-port-istorage.md) | Persistance via port `IStorage`, chiffrement au repos délégué à l'app | Accepté |
| [0012](0012-verification-hors-bande-differee.md) | Vérification d'identité hors-bande différée (TOFU / S3 en v0) | Accepté (différé) |
| [0013](0013-perimetre-v0-mvp.md) | Périmètre v0 (MVP) et limites différées | Accepté |
