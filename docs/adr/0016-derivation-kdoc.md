<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Jean Leloup -->

# ADR-0016 — `K_doc` dérivée, et disparition des `docWrap`

**Statut** : Accepté — révise le modèle d'[ADR-0007](0007-modele-cles-enveloppe.md)

## Contexte

`K_vault` *enveloppait* N `K_doc` tirées au hasard. Chaque grant transportait tout
le lot, signé en bloc contre la recombinaison partielle, et `Keyring.import()`
réconciliait les collisions par comparaison d'octets.

Trois défauts en découlaient :

- **Un fork de clé par canal.** Deux pairs ouvrant le même canal minaient chacun
  une clé aléatoire. Rare pour un document, quasi garanti pour un index — tout le
  monde ouvre les mêmes namespaces au démarrage.
- **Un départage broyable.** La comparaison d'octets converge entre honnêtes, mais
  un byzantin régénère sa clé jusqu'à en obtenir une plus petite et gagne
  systématiquement — rendant illisible le contenu déjà chiffré.
- **Un plafond de taille.** Le lot atteignait `MAX_MSG` vers 6 000 canaux, en
  dessous de la cible de 10 000 documents.

## Décision

Dériver au lieu de miner :

```
K_doc = sha256(K_vault ‖ "edgesync-dockey-v1" ‖ resourceId)
```

## Conséquences

- **Le fork de canal devient impossible** — deux pairs calculent la même valeur.
  Le problème est supprimé plutôt que réparé : il n'y a plus rien à départager.
- Un grant transporte **une seule clé scellée** au lieu d'un lot. Le plafond
  `MAX_MSG` et la signature anti-recombinaison disparaissent avec.
- Le partage d'un canal isolé à un extérieur fonctionne toujours : on lui remet la
  valeur dérivée. Le KDF étant à sens unique, elle ne révèle ni `K_vault` ni aucun
  canal voisin.
- **Ce qu'on perd** : un `K_doc` est attaché à *un* `K_vault`. Le « vault logique »
  reste possible — on peut envelopper la valeur dérivée sous un second `K_vault` —
  mais les rotations des deux domaines deviennent couplées. Un canal destiné à
  plusieurs domaines devra être **minté explicitement**, ce que le `Keyring`
  autorise toujours.
