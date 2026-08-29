<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0012 — Vérification d'identité hors-bande différée (TOFU / S3 en v0)

**Statut** : Accepté (différé)

## Contexte

Le `PeerStore` épingle les clés d'un pair au **premier `HELLO`** (TOFU) et alerte si
une clé épinglée change ensuite. Faille : le **premier contact n'est pas vérifié**.
Un **MITM actif** qui intercepte ce premier `HELLO` fait épingler **ses** clés comme
celles de « Bob » ; aucun changement ultérieur → aucune alerte. C'est la frontière
**S3 / S4** du modèle (§4) : TOFU = S3 (sûr contre un relais *passif*, vulnérable à
un *actif*) ; vérification **hors-bande** = S4.

## Décision

**Rester en TOFU / S3 en v0.** Le correctif est conçu mais **non implémenté** :

- **Empreinte (safety-number)** : hash déterministe de `signPub‖boxPub`, comparable
  hors-bande (QR en personne, lecture à voix haute).
- **`verify(id)`** : statut `pinned` → `verified-oob` (le champ existe déjà dans
  `KnownPeer` — format prêt, pas de migration le jour venu).
- **Garde de politique** optionnelle : `Session` refuse de **sceller une clé** vers
  un pair non `verified-oob` (mode S4) ; sinon auto-acceptation TOFU (S3). Même
  donnée, la politique change (§4.1).
- Le **canal hors-bande** (afficher/scanner, comparer) reste **côté app**, comme le
  chiffrement au repos ([ADR-0011](0011-persistance-port-istorage.md)).

## Conséquences

- v0 sûr contre un relais/serveur **passif** ; vulnérable à un **actif** au premier
  contact (S3 assumé).
- Passage S4 = ajouter empreinte + `verify()` + garde, sans changer le format
  (le statut `verified-oob` est déjà prévu).
- **Hors scope, plus gros** : transparence de clé (CONIKS / CT + gossip) et
  web-of-trust (Keybase) — chantiers séparés.
