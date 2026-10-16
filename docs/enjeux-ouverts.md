<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# EdgeSync — ce qui tient, ce qui reste à résoudre

État au 16 octobre 2026. Ce document ne dit pas comment finir. Il dit ce qui est
résolu, ce qui ne l'est pas, et sur quoi s'appuie chaque affirmation : un test, un
scénario du banc ([EdgeSync-bench](../../EdgeSync-bench)) ou une mesure.

Les identifiants renvoient à la [spécification ACL](edgesync-acl-arbitrage-spec.md)
(D, Q, C), aux [ADR](adr/) et aux sujets de recherche du dossier de financement
(R1 à R12).

## Ce qui tient

| Brique | Preuve |
| --- | --- |
| Deux plans : contenu sans coordination, autorité ordonnée par des arbitres | `session.inproc.test.ts` : le contenu circule sans arbitre en ligne |
| Chaîne d'époques signée, validée par tous contre les arbitres de la position précédente | `acl-chain.test.ts` |
| Droits à quatre niveaux, groupes (un niveau), owners en groupe, D17, D20 | `acl-chain.test.ts`, `attacks.test.ts` |
| Gossip simple, relais à l'identique après vérification, stratégie injectable (ADR-0018) | `gossip.test.ts` : ligne, triangle, arbitre non voisin |
| Fraîcheur des demandes : base, historique, backlink (ADR-0019) | `freshness.test.ts`, scénarios `rejeu-acl`, `desordre-emetteur`, `demande-perimee`, `fourche-emetteur` |
| La clé tourne dès qu'un membre perd la lecture, quel que soit le verbe (D11) | `retrogradation-sous-lecture` |
| Sans quorum, les droits gèlent sans jamais diverger | `arbitres-multiples`, `freshness.test.ts` |
| Résistance à des pairs malveillants qui forgent des messages bien formés | `byzantins`, `twins`, `attacks.test.ts` |

## Les enjeux ouverts

### 1. Élection et propagation des arbitres — R2, R3

**Comment c'est aujourd'hui.** L'ensemble d'arbitres se **calcule depuis les
droits**, jamais depuis la présence (D28) : les admins déclarés candidats, à
défaut les admins les plus gradés, ramenés à un nombre impair (D37). Il se
**propage par la chaîne** : tout pair qui a la tête de chaîne sait qui arbitre.
Il n'y a donc ni élection à proprement parler, ni désaccord possible sur
l'identité des arbitres.

**Ce qui manque.**

- **Plusieurs arbitres ne savent pas s'accorder** (C7). Avec trois arbitres, il
  faut deux signatures, et rien ne les produit. Jusqu'au 16 octobre, l'arbitre
  signait seul et sa chaîne se séparait sans bruit de celle du réseau. C'est
  corrigé : il ne signe plus, **les droits gèlent**. Mais n'importe quel admin
  peut aujourd'hui déclarer deux arbitres de plus, et geler les droits du vault
  pour de bon. Preuve : `arbitres-multiples`.
- **Un arbitre unique absent gèle les droits pour toujours.** La voie de secours
  des owners (D26), qui permet de retirer un arbitre, est conçue mais pas codée.
- **Savoir qui arbitre ne dit pas comment le joindre.** Une demande l'atteint par
  le gossip, si le graphe des connexions est connexe. Aucun annuaire ne relie une
  clé d'arbitre à une adresse.
- **Arbitre = admin** (D23). Le serveur, pair privilégié par défaut, devrait
  arbitrer sans pouvoir lire. Il faut un arbitre qui ordonne sans autoriser, avec
  son propre chemin de retrait (horizon de la spécification).
- **Un réseau sans machine configurée** : quand les arbitres sont des appareils
  d'admins qui vont et viennent, combien sont en ligne en pratique ? Rien n'est
  mesuré.

**Pistes.** Interdire, tant que C7 n'existe pas, un changement d'arbitres qui
porte k au-dessus de 1. Coder D26. Un accord à pannes franches avec suiveurs
validants, éprouvé plutôt qu'écrit à la main (pas de Raft de qualité production
en TypeScript). Un arbitre non-admin.

### 2. Le coût des rotations de clé — R1

**Mesure** (`npm run bench`, 10 pairs, 20 rotations à la suite) : **1,3 Mio sur
le fil par rotation**, dont **84 % de `StatePush`**. À chaque nouvelle clé, chaque
pair repousse tout son état à tous ses voisins : le coût croît comme le carré du
nombre de pairs, multiplié par la taille du document. Chaque keyring garde **une
clé par rotation**, pour toujours. Le scénario `rotations-massives` (8 pairs,
20 rotations) tient, mais met une minute à tourner.

**Pistes.** Repousser seulement ce que le voisin n'a pas (vecteur d'état) au lieu
de l'état entier, ou seulement aux pairs qui ont refusé une écriture. Rotation
paresseuse par canal (CP). Élaguer les vieilles clés quand plus rien de chiffré
avec elles n'est servi.

### 3. Le gossip et la perte de messages — R1, R4

- **Inondation** : un message par lien et par message. Correct pour quelques
  centaines de pairs, pas pour des milliers. Cible : Plumtree sur une vue
  partielle HyParView, derrière le même port.
- **Pas d'anti-entropie.** Une trame de contenu perdue n'est jamais redemandée.
  Le scénario `perte` converge maintenant, mais seulement parce que le maillage
  donne plusieurs chemins : sur une ligne, ou si toutes les copies se perdent, la
  réplique reste fausse.
- **Le contenu chiffré part à tous les voisins**, membres ou non.
- **La mémoire des messages vus est volatile.** Elle n'est plus une protection
  depuis ADR-0019, seulement une économie.

### 4. Le contenu antidaté — R4, R5

Une écriture est autorisée **à la position qu'elle déclare**. Or cette position
est choisie par celui qui signe. Un membre révoqué en écriture peut donc dater ses
nouvelles écritures d'avant sa révocation : il avait le droit à cette position,
et il a la clé de cette époque-là. **La révocation d'écriture se contourne en
antidatant.** Le scénario `revocation` ne le voit pas, parce que son révoqué est
honnête.

On ne distingue pas une écriture en retard d'une écriture antidatée sans un repère
commun. **Pistes** : refuser le contenu daté d'avant la dernière rotation (au prix
du service de vieux contenu par un relais `pull`), ou s'appuyer sur un canal de
logs ancré (enjeu 6).

### 5. La fraîcheur des demandes de droits : les limites restantes — R5, R9, R10

Résolu pour l'essentiel (ADR-0019). Restent :

- une demande refusée **plus tard** par l'arbitre, alors qu'elle passait chez son
  émetteur, bloque les suivantes de cet émetteur jusqu'à la prochaine rotation ;
- les **conflits** entre admins ne sont visibles que de l'arbitre, et rien ne gèle
  (D34 : départage par l'ordre en attendant) ;
- aucun message ne dit à un émetteur que sa demande est périmée ;
- sans rotation, l'historique grossit sans fin ;
- la limite de demandes par émetteur contre l'inondation (A9) n'est pas posée.

### 6. Qui a écrit quoi — R12, Q3

La signature d'une enveloppe prouve qui l'a envoyée, pas qui l'a écrite. Le
**canal de logs** (description du protocole, section K) répond à la question :
des témoins notent, pour chaque transaction reçue en direct, la plage
d'identifiants et la clé qui l'a émise. **Conçu, pas codé** ; prérequis fait
(`StatePush` séparé d'`Op`).

### 7. Ce que vit un membre rétrogradé

Un écrivain passé en lecture garde chez lui les écritures qu'il a faites avant
d'apprendre sa rétrogradation, et que les autres ont refusées. Sa réplique diverge
de celle du groupe, sans qu'il le sache. Observé dans `admins-concurrents`. Le
protocole a raison de refuser, mais l'application doit le montrer.

### 8. La taille de la chaîne

Environ **385 octets par époque** (mesure du bench), soit près de 4 Mio par an à
30 changements de droits par jour. Pas d'élagage. **Pistes** : garder les en-têtes
et jeter les ops ; une racine de Merkle de l'historique par époque permettrait de
prouver une op à un pair qui l'a élaguée. Des domaines d'arbitrage par groupe
(D30) contiendraient la croissance pour les grands vaults.

### 9. Sécurité et maturité — R8

- Aucun audit extérieur, aucune vérification formelle de la chaîne ni de
  l'arbitrage.
- Pas de fuzzing systématique des décodeurs.
- Premier contact en confiance (TOFU) : la vérification hors bande est conçue,
  pas codée (ADR-0012).
- Métadonnées en clair : tailles, horaires, positions.
- Aucune confidentialité persistante (forward secrecy), par construction.

### 10. Écosystème

- Savoire, la première application, utilise encore l'ancienne API.
- Transports : WebSocket et bus local seulement ; ni WebRTC ni libp2p.
- Pas de version publiée ; documentation en français.
- Aucun connecteur pour les applications de gestion (R6) : une base CRUD tourne
  dans les mini-apps du banc, mais rien ne fait respecter une règle métier qui ne
  fusionne pas (unicité, stock positif) sans passer par l'arbitrage.

## Récapitulatif

| Enjeu | Statut | Preuve | Sujet |
| --- | --- | --- | --- |
| Accord entre plusieurs arbitres | ouvert ; gel au lieu de scission | `arbitres-multiples` | R2 |
| Voie de secours des owners | conçu, pas codé | — | R2, R5 |
| Désignation des arbitres sans machine configurée | ouvert | — | R3 |
| Coût des rotations | mesuré, pas optimisé | bench, `rotations-massives` | R1 |
| Gossip à grande échelle | inondation seulement | `gossip.test.ts` | R1 |
| Anti-entropie | ouvert | `perte` | R4 |
| Contenu antidaté | ouvert | — | R4, R5 |
| Fraîcheur des demandes | résolu, limites listées | `freshness.test.ts`, scénarios | R5, R9, R10 |
| Attribution du contenu | conçu, pas codé | — | R12 |
| Connecteur pour applications de gestion | ouvert | mini-app CRUD du banc | R6 |
| Taille de la chaîne | mesurée, pas d'élagage | bench | R1 |
| Audit, preuve formelle, fuzzing | à faire | — | R8 |
