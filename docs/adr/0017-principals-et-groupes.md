<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0017 — Principals, groupes, et la racine qui délègue à un groupe

**Statut** : Accepté

## Contexte

Un modèle ACL plat — une clé, un niveau — ne sait modéliser ni une personne à
plusieurs appareils, ni une équipe, ni la succession d'un fondateur. Ce dernier
point est bloquant : la clé qui signe l'op racine est détruite juste après la
genèse, donc l'op racine est permanente. Si elle désigne un **individu**, cet
individu est fondateur à vie, irrévocablement.

## Décision

Un membre est un **principal** : une clé, ou un **groupe**.

- **La racine délègue à un GROUPE, jamais à un individu.** L'op racine est
  permanente ; un groupe, lui, reste mutable. La succession du fondateur redevient
  un changement d'appartenance ordinaire.
- **Quatre niveaux cumulatifs** : `pull` (répliquer du chiffré), `read`
  (déchiffrer), `write` (écrire), `manage` (administrer). `pull` et `read` sont
  distincts pour qu'un relais aveugle existe.
- **`min` en descendant** : un groupe qui n'a que `read` sur le vault ne peut pas
  donner `manage` à ses membres. Sans cette atténuation, l'imbrication serait une
  escalade de privilèges. **`max` entre chemins** : joignable deux fois, on garde
  le meilleur.
- **Seuls les admins modifient l'ACL.** Un `read` ou un `write` n'accorde jamais
  rien. Un `manage` ne mint jamais un `manage` **au niveau du vault** — seul le
  groupe owners le peut ; nommer un responsable *à l'intérieur* d'une équipe reste
  de l'administration ordinaire, plafonnée par l'atténuation.
- **Un groupe ne peut jamais être vidé de ses `manage`.** Vérifié *après* le lot
  entier : deux retraits qui laissent chacun un manager n'en laissent aucun
  appliqués ensemble. Une op qui viderait un groupe est refusée **en entier**.
- **Groupes plats en passe 1** : le type admet déjà l'imbrication, la résolution ne
  fait qu'un niveau d'indirection. Le modèle de données n'aura pas à changer quand
  la récursion arrivera.

## Conséquences

- La succession d'owner, l'identité multi-appareils et les équipes sont couvertes
  par un seul mécanisme.
- **Chaque appareil peut porter sa propre paire de clés**, la personne étant le
  groupe — ce qui retire la nécessité d'une identité dérivée d'une graine unique
  fournie par le serveur, et la dette qui va avec.
- Créer un groupe s'autorise contre le vault : la liste visée n'existe pas encore,
  donc il n'y a rien dont être `manage`. L'invariant du non-vidage force l'op
  créatrice à y laisser au moins un manager.
- La résolution devient récursive et tourne sur chaque op : la mémoïsation et la
  détection de cycle ne sont pas des optimisations mais des conditions de
  fonctionnement, dès que l'imbrication arrivera.
