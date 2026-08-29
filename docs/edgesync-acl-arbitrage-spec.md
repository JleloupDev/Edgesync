# EdgeSync — ACL, révocation et arbitrage

**Statut :** spécification de conception, non implémentée
**Version :** 20 août 2026
**Portée :** `poc/edgesync-protocol`, et les couches applicatives qui en dépendent

Ce document remplace la section « Ordre d'attaque » des notes antérieures. Chaque
décision porte un identifiant stable (`D1`…`D42`) ; la numérotation n'est jamais
réutilisée, et les décisions retirées restent listées avec leur motif.

---

## 00 — Description générale

EdgeSync est un protocole de collaboration chiffré de bout en bout, capable de
fonctionner entre pairs sans serveur, et d'utiliser un serveur comme super-pair
quand il en existe un. Un *vault* regroupe des documents partagés par un groupe
de personnes — quelques centaines au plus, qui se connaissent.

> **Périmètre.** Le mode pair-à-pair est réservé à des **organisations
> préexistantes, responsables de la protection de leur propre réseau**. Ce cadrage
> justifie plusieurs décisions qui suivent : l'ACL en clair, l'absence de défense
> contre un administrateur légitime malveillant, et un modèle de menace centré sur
> le membre invité dont l'appareil est compromis — jamais sur l'inconnu venu
> d'Internet.

### L'asymétrie qui a tout dicté

Un vault maintient deux états qui changent ensemble mais ne se comportent pas
pareil : **qui est membre**, et **quelle est la clé**.

> Deux listes de membres fusionnent toujours : on met les lignes bout à bout.
>
> Deux clés ne fusionnent jamais. Et l'entropie fraîche est indispensable à la
> révocation — sans quoi le révoqué recalculerait la nouvelle clé lui-même.

Deux administrateurs qui révoquent en même temps produisent deux clés
différentes : le vault se scinde en deux moitiés sourdes l'une à l'autre, sans que
personne ne s'en aperçoive. Aucune règle de fusion ne rattrape ça proprement.

### La résolution : séparer l'autorité du contenu

Le problème de l'ACL est, au fond, un problème **d'ordonnancement** et de
**sous-réseaux divergents**. Les deux se règlent en désignant des *arbitres*
connus de tous, qui s'accordent entre eux sur l'ordre des décisions d'autorité —
et sur rien d'autre.

```
PLAN D'AUTORITÉ
    nœud A      nœud B      nœud C
       \           |           /
        \      demande       /
         \         |        /
          +----------------+
          |    ARBITRES    |   accord interne, décision unique
          +----------------+
                  |
     +-------------------------------+
     |  époque publiée · certificat  |
     +-------------------------------+
                  |
                clé (K_vault)
                  |
PLAN DU CONTENU   v
     pair <-----> pair <-----> pair
     CRDT chiffré — ne passe jamais par les arbitres
```

Le contenu reste entièrement sans coordination. Seules les décisions d'autorité
transitent par les arbitres, qui s'accordent **entre eux** puis publient une
décision unique — jamais des votes que le réseau devrait dépouiller.

### Une seule structure : la chaîne d'époques

```
Époque {
  prevEpochId       chaînage par hash
  height            position
  round             voir D38
  ops[]             le lot d'ops d'ACL, chacune signée par SON initiateur
  keyMaterial?      présent seulement si le lot contient une révocation
  quorumSignatures  le certificat, portant sur l'époque entière
}
```

Il n'y a ni journal séparé, ni DAG, ni points de finalité distincts. Une op qui
n'est dans aucune époque n'a **aucun effet** — elle circule, c'est tout. L'époque
N se valide contre la liste d'arbitres définie par l'époque N−1, et ainsi de suite
jusqu'à l'op racine, scellée par une clé détruite juste après.

Conséquences : la synchronisation devient un intervalle linéaire, l'élagage
devient possible (garder les en-têtes, jeter les ops), et « cet auteur
était-il autorisé ? » devient une lecture d'état à une époque au lieu d'un calcul
d'ascendance.

### Qui arbitre

**Il y a toujours au moins un arbitre.** Par défaut le plus gradé, calculé depuis
l'ACL et jamais depuis la présence. Dès que des membres se déclarent, ils prennent
le relais. **k est toujours impair** — si le nombre de candidats est pair, on
écarte le moins gradé.

Il n'existe donc **qu'un seul mode** : pas de seuil, pas de bascule, pas de
seconde implémentation sans arbitrage.

### Ce qui dégrade et ce qui ne dégrade pas

Sans quorum : plus de promotion, plus de nouvelle époque. Mais les documents
continuent de s'éditer, la clé continue d'être redonnée à ceux que l'ACL autorise
déjà, et le réseau se répare seul.

> **L'arbitrage n'est jamais une condition de progression, seulement un
> accélérateur de décision.**

C'est ce qui distingue EdgeSync des alternatives évaluées : chez Any-Sync, DXOS ou
Jazz, le serveur est une ancre de confiance *obligatoire*. Ici il est la meilleure
option d'arbitrage quand il existe, et son absence ne change pas de protocole.

---

## 01 — Les décisions

### Modèle d'autorisation

**D1 — Modèle ACL, pas capability.**
Retirer quelqu'un ne doit pas éjecter tous ceux qu'il a intégrés : c'est le cas
nominal d'un outil documentaire, et c'est le comportement par défaut de Keyhive.
*Coût :* l'héritage d'un admin compromis se nettoie membre par membre.

**D4 — Quatre niveaux `pull ⊂ read ⊂ write ⊂ manage`, avec atténuation.**
Sépare répliquer du chiffré, déchiffrer, écrire, administrer. L'atténuation
(`can ≤ proof.can`, empruntée à Keyhive) interdit d'accorder plus qu'on ne détient.

**D5 — Groupes imbriqués : un membre peut être un groupe.**
Un DAG, pas un arbre. `min` en descendant (atténuation), `max` entre chemins.
Résout la succession d'owner, l'identité multi-appareils, les équipes, le cas
annuaire.
*Portée v1 :* **une seule chaîne pour le vault et tous ses groupes.** Le sharding
par groupe est l'horizon `D30`.

**D17 — Un groupe ne peut jamais être vidé de ses `manage`.**
Vérification *post-résolution* — deux retraits laissant chacun un manager en
laissent zéro appliqués ensemble. Ré-admission canonique par hash jusqu'à ce qu'il
en reste un. Rend « le vault meurt » structurellement impossible ; fonde `D25`.

**D18 — Identité et équipe sont deux types de groupe, au niveau du protocole.**
Un groupe d'identité contient des clés d'appareils, tous `manage` — sinon le vol
d'appareil serait irréversible. Un groupe d'équipe contient des identités.

**D19 — La racine délègue à un groupe, jamais à un individu.**
`sk_vault` détruite rend l'op racine permanente, donc son destinataire aussi. Un
groupe reste mutable : la succession du fondateur redevient un changement
d'appartenance ordinaire.

**D20 — Seuls les admins modifient l'ACL, et délèguent strictement en dessous d'eux.**
Un `read` ou un `write` n'accorde jamais rien. Seul le groupe owners mint un
`manage`. Sans ça, un admin compromis crée cinquante admins avant d'être retiré, et
ils survivent tous puisque `D1` exclut la cascade.
*Clarification :* « owner » n'est pas un niveau mais une **position** —
l'appartenance au groupe désigné par la racine.

### La chaîne

**D31 — L'époque *est* le certificat.**
Un lot d'ops d'ACL, un matériel de clé optionnel, les signatures du quorum,
chaînés à l'époque précédente par hash. L'époque N se valide contre la liste
d'arbitres définie par N−1 — chaîne terminant à l'op racine. Personne ne peut
invalider rétroactivement l'historique en changeant les arbitres.

*Signature.* Chaque arbitre signe le **hash de l'époque entière**, sur une région
préfixée :

```
epochId  = H(encodage canonique de epochBody)
région   = "edgesync-epoch-v1" ‖ vaultId ‖ epochId
sig_i    = Sign(sk_arbitre_i, région)
```

Le préfixe et le `vaultId` interdisent tout rejeu dans un autre contexte. Le
certificat est l'ensemble des couples `(clé publique, signature)` atteignant le
quorum.

*Vérification par un pair :*

1. recalculer `epochId` depuis le corps ;
2. déterminer l'ensemble d'arbitres défini par l'époque h−1 ;
3. compter les signatures valides et **distinctes** de cet ensemble ≥ quorum ;
4. vérifier que `prevEpochId` chaîne bien à la tête connue ;
5. pour chaque op : signature de l'initiateur + son autorisation à h−1 (`D39`).

**D7 — Canal ACL dédié, hash-*chaîne*, pas un `Y.Doc`.**
Yjs fusionne inconditionnellement et jette l'enveloppe, donc les signatures. Le
consensus linéarise, donc une chaîne suffit. Sync : « donne-moi les époques après
E(n) » — un intervalle linéaire.

**D8 — Servable par n'importe qui, relais compris.**
Signée et auto-validante : un non-membre peut la stocker et la servir sans pouvoir
la forger. La disponibilité de l'ACL ne dépend plus qu'un membre soit en ligne.

**D22 — Les arbitres sont le chemin d'écriture de l'ACL.**
Tout nœud **émet** une demande, par gossip sur le canal existant ; seuls les
arbitres la **committent**. Ils sont aussi les premiers destinataires de toute
action. Plus de duels, plus de bulles de concurrence, plus de fork d'époque.
*Coût :* une majorité d'arbitres peut refuser de committer un changement de droits.

**D35 — Une op peut porter plusieurs changements ; aucun regroupement dans le temps.**
Un admin qui retire trois membres émet **une** op portant trois changements — « je
retire 1, 2, 3 puis j'enregistre ». Le regroupement vient de l'intention de
l'auteur, jamais d'une fenêtre temporelle. Aucun délai n'est donc introduit : la
révocation prend effet dès que le consensus ordonne l'op, et la fenêtre d'accès
résiduel se réduit à la latence du consensus.
*Reporté, non tranché :* le regroupement **temporel** réintroduirait un délai avant
effet. À rouvrir seulement si le volume d'époques devient un problème mesuré, et
alors gradué selon `D41`.

**D11 — Une époque ne porte de clé nouvelle que si son lot contient une révocation.**
Évite de tourner les clés pour rien, et rend une rotation non justifiée détectable.

**D13 — Identifiant de vault auto-certifiant.**
`vaultId = pk_vault`, une clé publique Ed25519. Le fondateur signe l'op racine puis
détruit la clé privée. Deux créations donnent deux vaults distincts : la course
n'existe plus, et `EdgeSyncHub.ClaimOwner` est retiré.

**D29 — `K_doc` dérivée par défaut, mintée explicitement en option.**
`K_doc = KDF(K_vault, resourceId)` : deux pairs calculent la même valeur, le fork
de canal devient impossible sans arbitrage. Le partage d'un fichier isolé et le
vault logique fonctionnent toujours — seules les rotations se couplent.

**D40 — L'enveloppe distingue la position et la clé.**
Avec `D11`, une op scellée « sous l'époque 47 » peut utiliser la clé mintée à
l'époque 45. À la réception, deux gestes distincts : **autorisation** — lire l'état
de l'ACL à la position 47 ; **déchiffrement** — remonter la chaîne depuis 47
jusqu'au dernier changement de clé. Le champ `epoch` actuel porte les deux sens à
la fois : trivial une fois écrit, bug garanti sinon.

### Arbitrage

**D21 — Accord interne, décision unique, sans leader.**
Les arbitres s'accordent **entre eux** puis publient **une** décision. Le réseau ne
dépouille jamais de votes : il a le certificat complet, ou rien. La quasi-totalité
des ops commutent — il n'y a rien à ordonner ; seules les paires conflictuelles
demandent un vote. Deux arbitres qui publient des choses différentes : l'un ne fait
pas son travail, et c'est prouvable.

**D37 — Il y a toujours un arbitre, et k est toujours impair.**
Par défaut le plus gradé, calculé depuis l'ACL. Si le nombre de candidats est pair,
on écarte le moins gradé — k ∈ {1, 3, 5…}. Aucun seuil à fixer, aucune bascule à
spécifier, un seul mode.
*Coût :* à k=1, l'arbitre hors ligne gèle l'ACL. Le recours est `D26`.

**D23 — Arbitre = admin, en v1.**
Supprime trois problèmes : le chemin de retrait d'un arbitre, la modélisation d'un
nouveau type de principal, et l'admission des candidats.
*Horizon :* un arbitre qui ordonne sans pouvoir autoriser reste le meilleur design.

**D28 — L'ensemble d'arbitres ne dépend jamais de la présence.**
La présence est précisément ce qui diffère de part et d'autre d'une partition. Deux
moitiés qui tirent chacune ses arbitres atteignent chacune un quorum et avancent —
la divergence exacte qu'on veut empêcher.

**D32 — Suiveurs validants.**
Un arbitre vérifie signature et autorisation **avant** d'acquitter, jamais un
simple append. Le refus d'acquitter est le mécanisme de censure d'un arbitre
déviant : il faut corrompre une majorité, pas un seul.

**D33 — L'équivocation est prouvable.**
Deux propositions signées contradictoires pour la même position constituent une
preuve auto-portante, diffusable par quiconque la détient.
*Horizon :* révocation automatique sur preuve, avec annulation a posteriori par les
owners.

**D43 — Les fautes prouvables se rapportent ; les soupçons restent locaux.**

C'est le tuyau qui manquait entre la preuve (`D33`) et la sanction.

*Faute auto-portante* — équivocation (`D33`), double signature à la même hauteur
(`D38`), op émise par quelqu'un qui n'en avait pas le droit. Le rapport **contient
sa propre preuve**, donc le rapporteur n'a pas à être cru : il a besoin d'être
vérifié. Conséquence — **n'importe qui peut rapporter**, y compris un non-membre ou
un hostile : s'il ment, la preuve ne vérifie pas et le rapport tombe. Aucune
réputation à gérer. Le rapport prend la forme d'une **op d'ACL ordinaire**, gossipée
et committée comme les autres ; ce n'est pas un mécanisme séparé.

*Soupçon non prouvable* — clé épinglée qui change, inondation de demandes. Il **ne
franchit jamais le protocole** : il remonte à l'application (`onSecurityAlert`).
Une clé épinglée qui change ne prouve rien — un identifiant de transport n'est lié à
aucune identité, donc deux identités sur le même slot n'est pas une faute ; et « X
m'a envoyé dix mille demandes » ne se prouve pas. **Router des soupçons vers les
arbitres créerait une attaque neuve : l'inondation par fausses accusations.**

*Routage selon le fautif* — et c'est le cas que ni `D33` ni `D26` ne couvraient
seuls :

```
faute prouvée, fautif ordinaire  →  op ordinaire, committée par les arbitres
faute prouvée, fautif ARBITRE    →  voie de secours des owners (D26)
soupçon non prouvable            →  reste local, aucun rapport
```

À k=1, une preuve visant l'arbitre serait adressée au pair même qu'elle accuse, qui
n'aurait qu'à l'ignorer. Elle va donc aux owners, dont c'est précisément le seul
privilège : retirer des arbitres.

**D34 — Départage déterministe sur cycle (temporaire).**
Le vote majoritaire est infaillible à deux ops. À trois, il peut produire un cycle
(paradoxe de Condorcet). Règle v1 : ordonner les ops en conflit par leur hash,
détecté *à l'intérieur* du consensus, donc le réseau ne voit qu'un résultat.
*Cible :* le **gel** des participants — parce que la réalité est que personne ne
peut dire qui gagne.

**D38 — Un arbitre ne signe jamais deux candidats différents à la même paire `(hauteur, round)`.**
Registre local `(hauteur, round) → epochId signé`.

*Ce que ça garantit.* Forker exige deux époques valides à la même hauteur, donc
deux quorums. Deux quorums pris dans le même ensemble **s'intersectent
nécessairement** : à k=3 quorum 2, deux sous-ensembles de 2 parmi 3 partagent au
moins un arbitre — qui aurait donc signé les deux, ce que la règle interdit.
**À k≥3, forker exige une majorité corrompue.**

*Pourquoi un round.* Sans lui, deux proposeurs concurrents à la même hauteur
peuvent se partager les signatures sans qu'aucun n'atteigne le quorum — et comme
personne ne peut re-signer, la chaîne est bloquée à cette hauteur pour toujours.
Contrainte associée, non négociable : **un round supérieur doit reprendre toute
valeur qui a pu être choisie à un round inférieur.**

*Si la règle est violée.* Les deux signatures du même arbitre à la même hauteur
constituent la preuve auto-portante de `D33`, exploitable par `D26`.

*Reste à k=1.* Un arbitre unique peut équivoquer sans contradiction possible.
Réponse assumée : élagage manuel de la branche perdante, le cas étant tenu pour
rare. En contrepartie, à k=1 toute la machinerie de round disparaît.

*Recommandation.* **Ne pas écrire ce consensus soi-même.** Voir annexe 07.

**D42 — Le consensus de la v1 est volontairement simple, et devra évoluer.**
Un mécanisme d'accord minimal, suffisant pour valider la *forme* — la chaîne, les
certificats, la double vérification. À k=1 il n'y a rien à faire : l'arbitre signe,
c'est committé, et la v1 se déploie entièrement sans algorithme de consensus.
*Dette assumée :* dès que k ≥ 3 est réellement utilisé, il faudra un algorithme
éprouvé. Cette évolution est **prévue et acceptée**. La forme de la chaîne ne
change pas — seul le mécanisme qui produit le certificat change.

**D36 — Au plus un changement d'ensemble d'arbitres par époque.**
Un lot qui retire deux arbitres sur trois fait passer le quorum de 2 à 1 d'un coup ;
si ce dernier tombe, la chaîne est morte. C'est le problème du *joint consensus*.

**D41 — Si le lot temporel revient, il devra être gradué par type de droit.**
Toutes les révocations n'ont pas la même urgence.

| Droit révoqué | Traitement |
|---|---|
| `manage` | époque publiée **instantanément**, jamais regroupée |
| `read` | regroupable librement — quelques minutes de plus sans conséquence |
| `write` | regroupable **si on sait qui a écrit quoi** (`C3`) |

Pour `write` : la révocation porte la position à laquelle elle prend effet, et
chaque pair retire les ops du révoqué produites après — un changement compensatoire
au sens de `D15`, sur un ensemble identifié et petit. Sur une fenêtre courte, le
volume est faible et presque rien n'a été construit dessus ; sauf comportement
volontairement malveillant, ça ne touche pas de grosses portions de contenu.
*Statut :* piste notée, non tranchée. Dépend de `C3`.

**D25 — Le groupe owners est l'arbitre de dernier recours.**
Répond à « qui désigne les arbitres ». La récursion termine : `D19` rend la racine
permanente, `D17` garantit qu'il reste toujours un owner.
*Coût :* le groupe owners est la dépendance de disponibilité ultime.

**D26 — Voie de secours des owners.**
Une époque signée par un quorum du groupe owners au lieu du quorum d'arbitres, et
dont le lot ne contient **que des retraits d'arbitres**. Rien d'autre. Elle se
propage par le canal ACL, que chacun valide seul.
*Motif :* à k=1, un arbitre compromis ne peut pas committer son propre retrait. Le
privilège des owners se limite à *refaire l'arbitrage* — jamais à modifier des
droits.
*Pourquoi ce périmètre :* sans matériel de clé, elle ne peut pas provoquer de fork.
Deux ops de secours concurrentes sont deux retraits, donc monotones : elles
s'unionnent. Et elle reste inutilisable en routine.
*Exigence :* marquée `emergency`, visible dans le journal.

### Comportement du protocole

**D14 — Retour d'erreur : `Reject` + `KeyRequest`.**
`Reject`, pas `Nack` : « je refuse », pas « je n'ai pas reçu ». Jamais à un
non-membre. Jamais de motif `NotAuthorized`. Plus petit que son déclencheur, limité
en débit, sans état.

**D15 — Pierre tombale + attribution, pas de rejeu filtré.**
Un rejeu filtré orpheline tout ce qui dépend causalement de l'op retirée — en Yjs
*comme* en Automerge. La bonne annulation est un changement compensatoire, purement
additif. Ne dépend pas du CRDT choisi, donc pas de `Q3`.

**D12 — `regrant` ouvert à tous ; `add` réservé à `manage`.**
Sceller l'époque courante pour quelqu'un que l'ACL autorise *déjà* ne crée aucun
droit — c'est une réparation, pas une modification d'ACL. C'est ce qui rend le
réseau vivable en l'absence totale d'administrateurs.

**D39 — Double vérification : les arbitres ordonnent, l'initiateur autorise.**
Toute op d'ACL est signée par son initiateur. **Chaque pair du réseau vérifie cette
signature et l'autorisation de l'initiateur** — pas seulement les arbitres, et pas
seulement le certificat de quorum. Le certificat prouve *l'ordre* ; la signature de
l'initiateur prouve *l'autorité*. Un quorum d'arbitres ne peut donc ni usurper une
identité, ni exercer un droit qui n'est pas le sien.

### Horizon

**D30 — Sharding de l'arbitrage par groupe.**
Chaque groupe devient son propre domaine de consensus : une organisation de 10 000
personnes en 200 équipes = 201 petits consensus, pas un à 10 000 nœuds.
*Le blocage :* les domaines sont indépendants pour l'autorisation, **couplés pour
les clés** — retirer quelqu'un d'un groupe qui a `read` exige une rotation
vault-level.
*Contrainte :* en tension directe avec `D29` — une `K_doc` dérivée est attachée à
*un* vault, alors que le sharding exige qu'elle en soit indépendante. Les canaux
partagés entre domaines devront être **mintés explicitement** ; le chemin de scaling
passe donc par les canaux qui gardent le risque de fork de clé.
*La sortie :* un domaine de clés par groupe — c'est-à-dire le **vault logique**.
Sharder l'autorité exige de sharder les clés : le scaling et l'extension différée
sont la même idée à deux étages.

### Décisions retirées

| | Motif |
|---|---|
| **D2** | Un admin ne retire pas un admin. N'existait que pour empêcher les duels ; les arbitres les suppriment. |
| **D3** | ACL en OR-Set. Le consensus ordonne tout, les tags n'ont plus d'objet. |
| **D6** | Afficher tous les chemins d'accès. Confondait appartenance à un groupe et attribution de droits : deux objets distincts, et l'accès effectif est une affaire d'interface. |
| **D9, D10** | Chaînage puis fusion d'époques. Absorbés par `D31` ; la fusion n'a plus d'objet, l'arbitre est seul minteur. |
| **D16** | Résolveur Quarantine. Plus jamais de concurrence à résoudre. |
| **D24** | Ensemble stable / annonceur tournant. Il n'y a pas de leader. |
| **D27** | Seuil d'activation de l'arbitrage. Supprimé par `D37` : il y a toujours un arbitre. |

---

## 02 — Tranché et ouvert

### Tranché

- **Q1 — `sk_vault` détruite** après la genèse. Impose `D19`.
- **Q2 — ACL en clair.** Seule option qui casse la circularité et permet l'amorçage
  d'un pair neuf.
- **Q4 — Un nouveau membre voit tout l'historique : assumé.**
- **Q5 · Q6 · Q7 — retirées.** Récupération après vol (hors sujet), synchronisation
  des points de finalité (absorbée par `D31`), seuil d'arbitrage (supprimé par `D37`).

### Ouvert

**Q3 — Attribution indicative, ou non-répudiation ?**

Le lien `clientID ↔ signPub` donne *qui a écrit*, pas la *preuve*. Un membre peut
forger un update portant le `clientID` d'un autre — il ne gagne aucun droit, mais il
peut mettre des mots dans la bouche de quelqu'un.

- **Accepter** — quelques lignes. Ce que fait la quasi-totalité des éditeurs
  collaboratifs.
- **Non-répudiation** — migrer les canaux de contenu vers Automerge, dont les
  `Change` sont adressés par hash et signables.

*État :* ne conditionne aucune autre décision, y compris `D15`. Peut rester ouverte
indéfiniment.
*Coût révisé :* jours-à-semaines — le découplage `ICrdt` a été vérifié dans le code.
*Prérequis avant tout chiffrage :* vérifier le **déterminisme inter-pairs des ancres
Automerge**. L'identifiant de chaque entrée d'index en dépend.

---

## 03 — Les chantiers

### C0 — Encodage binaire à longueur préfixée

Remplacer JSON + base64. Retire 33 % de surcoût et un parseur JSON exposé aux
entrées hostiles. La chaîne d'époques ajoute une famille de messages : mieux vaut
changer l'encodage avant de l'écrire.
*Touche :* `protocol/messages.ts`

### C1 — `Reject` + `KeyRequest`

Le protocole cesse d'échouer en silence. Un pair en retard reçoit un motif et la
tête de chaîne ; s'il ne peut se corriger seul, il demande la clé.
*Pourquoi en premier :* sans ça, tout le reste se débogue à l'aveugle. C'est aussi
le déclencheur de synchronisation de la chaîne d'ACL.
*Fini quand :* un pair qui rate une époque se répare seul, sans qu'un admin soit en
ligne.

### C1b — Correctifs isolés

Quatre défauts indépendants, aucun couvert par le reste du plan.

- **Injection de `docWrap`** — `import()` accepte des clés pour n'importe quelle
  époque et remplace l'existante si elle est plus petite en octets : destruction
  silencieuse d'un canal. *(Réglé au passage par `D29` si la dérivation est retenue.)*
- **Alarme MITM avalée** par le `catch` de `onMessage`.
- **Dérivation `boxPriv = sha256(signSeed)`** — lie signature et chiffrement.
- **Dépinnage impossible** — `PeerStore.signers` n'a pas de retrait.

### C2 — Chaîne d'époques, à un seul arbitre

La structure de `D31`, avec k=1 : l'arbitre signe seul, aucun protocole de
consensus nécessaire. Journal d'ACL et matériel de clé dans le même objet. Toute la
forme se valide sans écrire une ligne de consensus ; le multi-arbitre s'ajoute
ensuite sans changer la structure.
*Touche :* `core/keyring.ts`, `core/envelope.ts`, `session.ts`, nouveau magasin de
chaîne.

### C3 — Attribution et positions par les ports

**(a)** `clientID = int(sha256(signPub)[0..6])` — collision de l'ordre de 10⁻¹¹ à
300 membres.
**(b)** Router les curseurs par `ICollaborativeText` : `YjsCrdtAdapter.ts:87-91`
appelle Yjs directement alors que le port fait exactement ça.
*Bénéfice annexe :* (b) teste le port sur un second cas d'usage avant qu'on mise
dessus.
*Note :* `D41` fait de (a) un prérequis fonctionnel, pas seulement une dette.

### C4 — Niveaux, `resolveAccess`, groupes imbriqués

`isAuthorized(signPub) → bool` devient `resolveAccess(signPub, epoch) → Access` —
une lecture d'état à une époque, pas un calcul d'ascendance. Puis les principals
composites et la résolution récursive.
*Obligatoire dans la spec :* détection de cycle et mémoïsation sur
`(signPub, epochId)`.
*Débloque :* succession d'owner, clés par appareil (retrait de `ServerKeyProvider`
et de la dette « clé privée via l'API »), équipes, cas annuaire.
*Effet annexe :* rend redondante la règle stricte sur l'époque dans `onOp` — un
relais `pull` redevient capable de servir du contenu stocké.

### C7 — Multi-arbitres

Accord interne sur les paires conflictuelles, suiveurs validants, preuve
d'équivocation, reconfiguration.
*Point de vigilance :* la reconfiguration est le morceau difficile de tout
consensus, et elle se déclenche à chaque changement du set manage.
*Choix ouvert :* journal répliqué ou certificats de quorum. Voir annexe 07.

### C5 — Identifiant auto-certifiant

Le `vaultId` devient `pk_vault`. Retire `EdgeSyncHub.ClaimOwner`.

### C6 — Appairage d'appareil

Canal hors bande : QR code, code à usage unique, confirmation depuis un appareil
déjà membre. Rendu nécessaire par le retrait de `ServerKeyProvider`.

### CP — Performance des rotations (indépendant)

Diffuser le lot de `docWraps` une seule fois — ils sont identiques pour tous, seul
`sealedVaultKey` est personnalisé. Rotation paresseuse par canal.
*Effet :* une révocation passe de ~500 Mo à quelques kilo-octets ; le plafond
`MAX_MSG` disparaît.
*À modéliser :* impact du volume d'époques sur un grand réseau.

---

## 04 — Ce que le plan introduit

- **Les arbitres peuvent censurer et réordonner.** Ils ne peuvent pas forger — les
  ops restent signées par leurs émetteurs — mais l'ordre est un pouvoir : placer un
  retrait avant un octroi l'invalide. Borné par la majorité, rendu attribuable par
  le journal.
- **La reconfiguration se déclenche souvent**, à chaque changement du set manage.
  `D36` en limite la casse.
- **Le cycle de groupes est un déni de service accessible par accident.** Créable en
  concurrence, donc ininterdisable. Sans détection à la résolution, boucle infinie.
- **`regrant` ouvert à tous est spammable.** Limitation de débit par
  `(demandeur, époque)`.
- **Inondation de demandes d'ACL.** Le vivier des émetteurs légitimes est petit et
  attribuable (`D20`), mais il faut une limitation de débit et une règle d'alerte —
  candidat au gel de l'émetteur.
- **Le curseur fantôme d'un révoqué.** La présence doit passer par `resolveAccess`
  au niveau `read`, pas seulement par la possession de clé.
- **Référencer un groupe délègue à ses administrateurs.** C'est le but, mais sans
  affichage explicite c'est un piège.

---

## 05 — Limites assumées

- **Un révoqué garde ce qu'il a déjà lu.** Irréductible. La révocation vaut « à
  partir de maintenant », jamais rétroactivement.
- **Aucune forward secrecy.** Structurellement impossible avec `encrypt-at-send` —
  qui est par ailleurs ce qui fait qu'un contenu se re-scelle tout seul à l'époque
  courante.
- **Aucune défense contre un admin légitime malveillant.** Seulement détection,
  attribution et réparation.
- **Sans quorum, l'ACL gèle.** Les documents continuent de s'éditer et `regrant`
  continue de réparer. À k=1, l'arbitre hors ligne suffit à geler — le recours est
  `D26`.
- **Byzantins détectables, pas empêchés.** L'équivocation ne se prévient pas sans
  consensus sur tout. Le chaînage la rend attribuable.
- **Un utilisateur seul avec un seul appareil n'a aucune récupération.** `D17`
  empêche de retirer le dernier manager, pas de le perdre. Exigence applicative :
  pousser à enrôler un second appareil.
- **Connaître l'identifiant d'un vault révèle sa liste de membres, indéfiniment.**
  Conséquence de `Q2` + `D8` + `D13`. Un ex-membre garde l'identifiant et continue
  de voir le graphe évoluer. Couvert par le périmètre annoncé en tête.
- **Dans un vault à deux, le non-arbitre n'a aucun recours** contre l'arbitre : il ne
  peut ni le retirer ni contourner. « Deux collaborateurs égaux » n'existe pas dans
  ce protocole — l'interface ne doit pas le laisser croire.
- **On ne contrôle pas qui *reçoit*, seulement qui *déchiffre*.** Vrai de tout
  réseau en diffusion. C'est pourquoi `pull` et `read` sont deux niveaux distincts.

---

## 06 — Horizons et écarté

### Horizons

- **Gel plutôt que départage.** Quand deux admins se révoquent en concurrence,
  personne ne peut dire qui a raison : la bonne sémantique est de geler les deux.
  `D34` n'est qu'une réponse d'attente.
- **Politiques de sécurité graduables.** Révocation automatique sur preuve
  d'équivocation, annulation a posteriori par les owners, curseur strict/laxiste
  selon que le réseau est déjà protégé ou ouvert.
- **Arbitre non-admin.** Une machine `pull` toujours allumée : elle ordonne sans
  pouvoir ni lire ni autoriser. Meilleure séparation des pouvoirs, à condition de
  traiter son chemin de retrait.
- **Sharding par groupe et vault logique.** `D30` — la même idée à deux étages, et
  le vrai chemin de passage à l'échelle.

### Écarté après examen

| | Motif |
|---|---|
| Ordonnancement des admins par ancienneté | N'existait que pour départager les duels, que les arbitres suppriment. Contournable par antidatage. |
| Arbitrage purement déterministe | Toute règle déterministe est broyable par qui produit les entrées — mode d'échec documenté de Matrix. |
| Tirage au sort des arbitres, sélection sur la présence | L'aléa minimise la disponibilité, seule chose qui compte pour ce rôle. Un tirage sur la présence laisse deux moitiés d'un réseau coupé avancer chacune de son côté. |
| Vote publié par chaque arbitre, dépouillé par le réseau | Laisserait les pairs calculer des résultats partiels divergents. Les arbitres s'accordent d'abord, publient ensuite. |
| Bannissement | Appartenance et attribution sont deux objets distincts. La gestion fine est applicative. |
| Scission révocation d'écriture / de lecture pendant un gel | Sa seule justification était l'urgence après un vol. Le temps de consensus est négligeable devant le temps humain de détection. |

### Reporté

- **CGKA (BeeKEM / DCGKA).** O(log n) au lieu de O(n). Seul écart avec Keyhive et
  p2panda qui ne se comble pas par du simple travail — mais à quelques centaines de
  membres il ne se mesure pas.
- **Réécriture de la présence hors `y-protocols/awareness`.** Faisable — transport,
  hors-CRDT et port de positions existent déjà. Mais c'est du code éprouvé qu'il
  serait inutile de rouvrir sans raison.
- **Réconciliation d'ensembles, rotation indépendante par canal.** Optimisations,
  pas corrections.

---

## 07 — Annexe : le consensus en bref

Le domaine derrière `C7`, pour savoir dans quoi on met les pieds.

### Le problème, et son impossibilité

Plusieurs machines doivent s'accorder sur **une seule valeur** malgré pannes et
retards réseau. Deux exigences : la **sûreté** (jamais deux valeurs différentes,
jamais de rétractation) et la **vivacité** (on finit par décider). Ici : *quelle
époque occupe la hauteur 48 ?*

**Fischer, Lynch et Paterson, 1985** : dans un système asynchrone, avec une seule
panne possible, aucun algorithme déterministe ne garantit les deux à la fois. C'est
une impossibilité, pas une limite d'ingénierie. Tous les algorithmes réels
choisissent donc **toujours sûrs, vivants seulement quand le réseau se comporte
bien** — exactement notre position : sans quorum, l'ACL gèle, elle ne diverge pas.

### Paxos

Lamport, écrit en 1989, publié en 1998. Deux phases : le proposeur obtient d'une
majorité la promesse de ne plus rien accepter en dessous de son numéro de scrutin,
puis fait accepter sa valeur. La règle qui fait tout tenir :

> Si un accepteur signale une valeur déjà acceptée, le proposeur **doit reprendre
> cette valeur** — pas la sienne.

La sûreté vient de l'intersection des majorités — le même argument que `D38`. Et
notre contrainte « un round supérieur reprend toute valeur déjà choisie » n'est pas
une précaution ajoutée : c'est le cœur de Paxos.

*Piège :* Paxos décide **une** valeur. Pour un journal il faut le relancer par case,
à deux allers-retours chacune. D'où Multi-Paxos, qui élit un proposeur stable —
donc Paxos finit avec un leader de toute façon.

### Raft

Ongaro et Ousterhout, 2014, écrit explicitement pour être compréhensible, parce que
la plupart des implémentations de Paxos étaient boguées. Trois états (suiveur,
candidat, leader), un compteur de *terme*, un seul leader par terme. Seul le leader
écrit ; une entrée est committée quand une majorité l'a stockée. Un candidat ne
gagne que si son journal est au moins aussi à jour que celui de chaque votant, donc
un leader détient toujours tout ce qui est committé.

Utilisé par etcd (donc Kubernetes), Consul, CockroachDB, TiKV. Paxos est derrière
Chubby et Spanner.

### Ce qu'ils ne font pas : mentir

Paxos et Raft supposent des **pannes franches**, pas des acteurs malveillants. Une
machine peut s'arrêter ou ralentir ; elle ne ment jamais.

D'où `D32`, « suiveurs validants » : chaque arbitre vérifie signature et
autorisation avant d'acquitter. Ça bloque un leader qui voudrait faire passer une op
non autorisée — pas celui qui censure ou ment sur l'ordre.

| | Nœuds pour tolérer f fautes | Messages |
|---|---|---|
| Raft / Paxos (pannes) | 2f+1 → 3 pour 1 | O(n) |
| PBFT (menteurs) | 3f+1 → 4 pour 1, 7 pour 2 | O(n²) |

Le BFT complet (Castro & Liskov 1999, puis Tendermint, HotStuff) est
disproportionné pour « quelques admins d'une entreprise ». Crash-fault plus
suiveurs validants est le bon niveau, cohérent avec le périmètre annoncé en 00.

### La contrainte pratique qui pèse sur l'architecture

Les implémentations mûres de Raft sont en **Go** (etcd/raft, hashicorp/raft),
**Rust** (openraft, raft-rs) et **Java** (Ratis). **Il n'existe pas
d'implémentation TypeScript de qualité production.**

Or en mode P2P, les arbitres sont des navigateurs. Faire tourner un consensus entre
navigateurs via WebRTC est faisable, mais sans filet — il faudrait l'écrire, ce que
`D38` déconseille explicitement.

```
mode par défaut         k = 1, l'arbitre est le serveur
                        → aucun consensus à écrire

déploiement entreprise  k ≥ 3, les arbitres sont de vrais services
                        → une implémentation éprouvée, hors navigateur
```

Le consensus multi-arbitres n'a de sens que là où tourne du vrai logiciel de
serveur — pas entre trois onglets. Ce qui recoupe exactement l'architecture visée.

**Bonne nouvelle pour la suite :** la chaîne d'époques signée *est déjà* un journal
répliqué. Ce qui manque de Raft, c'est l'élection et la règle de commit — pas la
machinerie de réplication.

---

## Notes de fiabilité

Les constats sur le code portent sur `poc/edgesync-protocol/src`, hors `codec.ts`,
`storage.ts` et les transports, et hors diff en cours sur la branche `p2p`.

Les détails d'implémentation Keyhive et p2panda viennent de la documentation des
dépôts, pas d'une lecture du code Rust : les noms de types sont fiables, les règles
précises méritent vérification à la source.

**Sources principales :** Ink & Switch, *Keyhive notebook* · p2panda, *Access
Control in Decentralised Systems* et *Notes on a convergent Access Control CRDT* ·
Willow, *Meadowcap* · Jacob et al., *Matrix Decomposition* (SACMAT 2020) · Weidner
et al., *DCGKA* (CCS 2021) · Backes/Cachin/Oprea, *Secure Key-Updating for Lazy
Revocation* · Dougal, *ERA: Epoch-Resolved Arbitration* (PaPoC 2026) · Lamport,
*Byzantine Generals* (1982) et *Paxos Made Simple* (2001) · Ongaro & Ousterhout,
*In Search of an Understandable Consensus Algorithm* (2014) · Fischer, Lynch &
Paterson (1985) · Castro & Liskov, *PBFT* (1999).
