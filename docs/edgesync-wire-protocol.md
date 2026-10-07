<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# EdgeSync — protocole de fil (référence des interactions)

Catalogue des messages échangés entre pairs et de leurs enchaînements. Décrit
l'état **implémenté** ([poc/edgesync-protocol](../../poc/edgesync-protocol/));
la section finale liste l'évolution **prévue** (B2, non implémentée). Voir aussi le
design [edgesync-protocol.md](edgesync-protocol.md) et le modèle de confiance
[security-channel-model.md](security-channel-model.md).

## Cadre commun

- **Encadrement** : tout message est `[ type:1 ][ payload ]` (`messages.ts`).
- **Deux familles** :
  - *Contrôle* (`HELLO`, `KEY`, `SYNC_REQ`) — payload **JSON** (champs binaires en
    base64). En clair, mais sans secret exploitable (clés publiques, state-vector ;
    la clé de `KEY` est elle-même scellée).
  - *Contenu* (`OP`, `SYNC_RESP`) — payload = une **enveloppe binaire** chiffrée +
    signée (`[epoch:4][nonce:24][ciphertext][sig:64][signerPub:32]`).
- **Adressage** : `transport.send(peerId, bytes)`. `peerId` est l'id de transport ;
  l'identité protocole (`signPub`/`boxPub`) est apprise au `HELLO` et épinglée
  (TOFU) dans le `PeerStore`.

## Messages

### `HELLO` (type 1) — handshake d'identité

| | |
|---|---|
| **Direction** | pair ↔ pair, à la connexion |
| **Déclencheur** | `transport.onPeerUp` |
| **Payload** | `{ signPub, boxPub, nonce, sig }` (JSON/base64), `sig = sign(nonce)` |
| **Chiffrement** | clair (clés publiques) |
| **Réception** | `verify(sig, nonce, signPub)` ; sinon ignore. Puis `PeerStore.observe` (TOFU : épingle au 1ᵉʳ contact, **alerte** si la clé change) ; mémorise l'identité ; si je suis *granting* → envoie `KEY` ; envoie un `SYNC_REQ`. |
| **Réponse** | `KEY` (si granting) + `SYNC_REQ` |

### `KEY` (type 3) — livraison de clé d'époque

| | |
|---|---|
| **Direction** | détenteur de clés → pair |
| **Déclencheur** | grant (au `HELLO` d'un pair, si *granting*) ou `rotate()` |
| **Payload** | `{ resource, epoch, sealedVaultKey, docWrap }` (JSON/base64) ; `sealedVaultKey = seal(boxPub_dest, K_vault^epoch)` ; `docWrap = Enc(K_vault, K_doc)` |
| **Chiffrement** | clé scellée vers la clé publique X25519 du destinataire |
| **Réception** | si `resource` ≠ la mienne → ignore ; `unseal` → `K_vault` ; `keyring.import(epoch, K_vault, docWrap)` (déballe `K_doc`) ; puis **re-pousse** son état (`STATE_PUSH`) sous l'époque courante + redemande un `SYNC_REQ`. |
| **Réponse** | un `STATE_PUSH` (état re-poussé) + un `SYNC_REQ` |

### `OP` (type 2) — opération de contenu

| | |
|---|---|
| **Direction** | auteur → tous les pairs (broadcast) |
| **Déclencheur** | édition locale (`crdt.onLocalUpdate` → `publishOp`) |
| **Payload** | enveloppe ; `ciphertext = Enc(K_doc^epoch, update Yjs)` ; `sig = sign(epoch‖nonce‖ciphertext)` |
| **Chiffrement** | XChaCha20-Poly1305 sous `K_doc` de l'**époque courante** (encrypt-à-l'envoi) |
| **Réception** | `verify(sig)` sinon ignore ; **`signerPub` doit être un utilisateur épinglé** (B1, [ADR-0009](adr/0009-signature-auteur-utilisateur-connu.md)) ; **rejet si `epoch < epoque_courante`** (révocation d'écriture, tous chemins) ; si pas de `K_doc^epoch` → ignore ; `decrypt` → `crdt.applyRemote`. |
| **Réponse** | aucune |

### `SYNC_REQ` (type 4) — demande de rattrapage

| | |
|---|---|
| **Direction** | pair → pair |
| **Déclencheur** | `onHello`, `onKey` |
| **Payload** | `{ stateVector }` (JSON/base64) — résumé Yjs de « ce que j'ai déjà » |
| **Chiffrement** | clair (le state-vector ne révèle pas le contenu) |
| **Réception** | calcule `diffSince(stateVector)` et répond par `SYNC_RESP`. |
| **Réponse** | `SYNC_RESP` |

### `SYNC_RESP` (type 5) — réponse de rattrapage

| | |
|---|---|
| **Direction** | pair → pair (réponse à `SYNC_REQ`) |
| **Déclencheur** | `onSyncReq` |
| **Payload** | enveloppe ; `ciphertext = Enc(K_doc^courant, diff)` — **toujours à l'époque courante** |
| **Chiffrement** | comme `OP` |
| **Réception** | **identique à `OP`** — y compris le rejet d'époque périmée. (C'est l'absence de cette règle qui ouvrait le contournement de la révocation d'écriture ; cf. [ADR-0005](adr/0005-encrypt-a-lenvoi-revocation-forward-only.md).) |
| **Réponse** | aucune |

### `STATE_PUSH` (type 12) — état re-poussé après une clé

| | |
|---|---|
| **Direction** | pair → tous les pairs |
| **Déclencheur** | `onKey` |
| **Payload** | enveloppe ; `ciphertext = Enc(K_doc^courant, snapshot)` |
| **Chiffrement** | comme `OP` |
| **Réception** | **identique à `OP`**. |
| **Réponse** | aucune |

Pourquoi un type à part : l'état complet contient les écritures de **tous** les
pairs, sous la signature de celui qui le pousse. En `OP`, il ferait croire à un
observateur que le pousseur a écrit le texte des autres. `OP` est réservé aux
transactions **en direct** : ce que son signataire vient d'écrire, rien de relayé.
`SYNC_RESP` et `STATE_PUSH` sont du rattrapage.

## Séquences d'interaction

**Onboarding** (un pair rejoint) :
`HELLO ↔ HELLO` → `KEY →` (le détenteur scelle la clé) → `SYNC_REQ ↔` → `SYNC_RESP ↔` → convergence.

**Édition courante** : édition locale → `OP` (broadcast, chiffré époque courante).

**Rotation / révocation** : `rotate()` → nouvelle époque → `KEY →` chaque pair **sauf le révoqué** → les écritures du révoqué (forcément vieux-époque) sont rejetées.

**Catch-up après coupure** : à la reconnexion, `HELLO` → `SYNC_REQ(state-vector)` → `SYNC_RESP(diff)` chiffré sous l'époque courante.

**Course honnête** (pair en retard sur une rotation) : son `OP` vieux-époque est rejeté par les pairs rotés, puis re-livré sous l'époque courante via le `STATE_PUSH` d'`onKey` ; Yjs dédoublonne.

## Invariants transverses

- **Encrypt-à-l'envoi** : `OP` et `SYNC_RESP` sont **toujours** à l'époque courante de l'émetteur. Conséquence : on peut rejeter le vieux-époque **partout**, sans casser le catch-up.
- **Chiffrement ⊥ signature** : l'AEAD authentifie le groupe (qui a la clé), la signature l'individu (qui a émis l'enveloppe).
- **Identité = état local épinglé** (TOFU au `HELLO`), jamais un lookup refait à chaque op.

## Évolution prévue — B2 (journal de changements signés)

Non implémenté. Quand on ajoutera la signature d'auteur **durable** (fondation de
l'ACL, cf. discussion §1.7.1 du modèle), les interactions changent ainsi :

- **`OP`** ne transporte plus un update Yjs opaque mais un **changement signé**
  `{ update, authorPub, authorSig }` (la signature couvre l'update *en clair*, donc
  elle survit au re-chiffrement et au relais).
- **`SYNC_REQ`** porte un **ensemble d'identifiants de changements** (hash de
  contenu) au lieu (ou en plus) du state-vector Yjs.
- **`SYNC_RESP`** renvoie un **ensemble de changements signés** manquants, chacun
  conservant sa signature d'auteur — au lieu d'un diff mergé qui la perdrait.
- La vérification de droits (membre autorisé à la position) viendra **par-dessus**
  ce format, sans migration : c'est l'op-log / ACL (phase 7).
