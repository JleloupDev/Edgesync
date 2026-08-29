// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// The pure core of the ACL: op vocabulary, epoch chain, folded state. No
// network, no storage — every invariant of the spec is testable here, which is
// the point of keeping this layer pure.
import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2'
import { OwnIdentity } from '../src/core/identity'
import { resourceId, randomBytes } from '../src/core/envelope'
import {
  Access, ROOT_GROUP, signAclOp, verifyAclOp, encodeAclOp, decodeAclOp,
  keyPrincipal, groupPrincipal, type AclOp,
} from '../src/core/acl-ops'
import {
  AclChain, signEpoch, epochId, encodeEpoch, decodeEpoch, validateEpoch,
  resolveAccess, isOwner, arbiterSet, quorumSize, fold, GENESIS_PREV,
} from '../src/core/acl-chain'

const VAULT = resourceId('vault-acl')
const OWNERS = sha256(new TextEncoder().encode('owners-group'))

const idOf = (o: OwnIdentity) => ({ signPub: o.signPub, sign: (m: Uint8Array) => o.sign(m) })
const op = (issuer: OwnIdentity, group: Uint8Array, changes: AclOp['changes']) =>
  signAclOp(VAULT, { group, changes, issuer: issuer.signPub }, (m) => issuer.sign(m))

/** Genesis: the founder is manage inside the owners GROUP, and the root
 *  delegates to that group — never to the individual (D19). */
function genesis(founder: OwnIdentity) {
  return AclChain.genesis(VAULT, idOf(founder), [
    op(founder, OWNERS, [{ t: 'set', principal: keyPrincipal(founder.signPub), access: Access.Manage }]),
    op(founder, ROOT_GROUP, [
      { t: 'set', principal: groupPrincipal(OWNERS), access: Access.Manage },
      { t: 'arbiter', principal: keyPrincipal(founder.signPub), on: true },
    ]),
  ], randomBytes(32))
}

/** Build + sign the next epoch as `by` (k=1: one signature IS the certificate). */
function next(chain: AclChain, by: OwnIdentity, ops: AclOp[], keyCommit?: Uint8Array) {
  return signEpoch(VAULT, {
    prev: chain.head(), height: chain.height() + 1, round: 0, ops, keyCommit,
  }, by.signPub, (m) => by.sign(m))
}

describe('acl-ops — vocabulaire signé', () => {
  it('fait un aller-retour et detecte la moindre alteration', () => {
    const a = OwnIdentity.generate()
    const o = op(a, ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(a.signPub), access: Access.Write },
      { t: 'remove', principal: groupPrincipal(OWNERS) },
      { t: 'arbiter', principal: keyPrincipal(a.signPub), on: true },
    ])
    const bytes = encodeAclOp(o)
    const { op: back, read } = decodeAclOp(bytes)
    expect(read).toBe(bytes.length)
    expect(back).toEqual(o)
    expect(verifyAclOp(VAULT, back)).toBe(true)

    // Un octet du corps modifie -> la signature ne verifie plus (D39).
    const tampered = decodeAclOp(bytes).op
    ;(tampered.changes[0] as { access: Access }).access = Access.Manage
    expect(verifyAclOp(VAULT, tampered)).toBe(false)
  })

  it('une op signee pour un autre vault ne verifie pas (separation de domaine)', () => {
    const a = OwnIdentity.generate()
    const o = op(a, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(a.signPub), access: Access.Read }])
    expect(verifyAclOp(resourceId('un-autre-vault'), o)).toBe(false)
  })
})

describe('acl-chain — la chaine', () => {
  it('la genese donne au fondateur manage PAR le groupe owners (D19)', () => {
    const f = OwnIdentity.generate()
    const c = genesis(f)
    expect(resolveAccess(c.state(), f.signPub)).toBe(Access.Manage)
    expect(isOwner(c.state(), f.signPub)).toBe(true)
    expect(c.height()).toBe(0)
  })

  it('accepte une epoque valide et refuse un mauvais chainage', () => {
    const f = OwnIdentity.generate()
    const bob = OwnIdentity.generate()
    const c = genesis(f)

    const add = op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(bob.signPub), access: Access.Write }])
    c.append(next(c, f, [add]))
    expect(resolveAccess(c.state(), bob.signPub)).toBe(Access.Write)

    // prev qui ne correspond pas
    const bad = signEpoch(VAULT, { prev: GENESIS_PREV, height: c.height() + 1, round: 0, ops: [] }, f.signPub, (m) => f.sign(m))
    expect(() => c.append(bad)).toThrow(/prev mismatch/)

    // hauteur qui saute
    const skip = signEpoch(VAULT, { prev: c.head(), height: c.height() + 5, round: 0, ops: [] }, f.signPub, (m) => f.sign(m))
    expect(() => c.append(skip)).toThrow(/height mismatch/)
  })

  it('refuse une signature qui ne vient pas d\'un arbitre, et un quorum absent', () => {
    const f = OwnIdentity.generate()
    const intrus = OwnIdentity.generate()
    const c = genesis(f)
    const e = next(c, intrus, []) // signee par quelqu'un qui n'est pas arbitre
    expect(() => c.append(e)).toThrow(/quorum not met/)
  })

  it('D11 : materiel de cle si et seulement si le lot retire quelqu\'un', () => {
    const f = OwnIdentity.generate()
    const bob = OwnIdentity.generate()
    const c = genesis(f)
    c.append(next(c, f, [op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(bob.signPub), access: Access.Write }])]))

    // une cle sans retrait
    const gratuit = next(c, f, [], randomBytes(32))
    expect(() => c.append(gratuit)).toThrow(/key commitment/)

    // un retrait sans cle
    const rm = op(f, ROOT_GROUP, [{ t: 'remove', principal: keyPrincipal(bob.signPub) }])
    expect(() => c.append(next(c, f, [rm]))).toThrow(/key commitment/)

    // les deux ensemble : accepte
    c.append(next(c, f, [rm], randomBytes(32)))
    expect(resolveAccess(c.state(), bob.signPub)).toBeUndefined()
  })

  it('D40 : keyEpochAt remonte au dernier changement de cle', () => {
    const f = OwnIdentity.generate()
    const bob = OwnIdentity.generate()
    const c = genesis(f)
    const keyEpoch0 = c.head()

    // deux epoques SANS cle : la position avance, la cle ne bouge pas
    c.append(next(c, f, [op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(bob.signPub), access: Access.Read }])]))
    c.append(next(c, f, [op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(bob.signPub), access: Access.Write }])]))
    expect(c.head()).not.toEqual(keyEpoch0)
    expect(c.keyEpochAt(c.head())).toEqual(keyEpoch0)

    // une revocation : nouvelle cle, la position et la cle coincident a nouveau
    const rm = op(f, ROOT_GROUP, [{ t: 'remove', principal: keyPrincipal(bob.signPub) }])
    c.append(next(c, f, [rm], randomBytes(32)))
    expect(c.keyEpochAt(c.head())).toEqual(c.head())
  })

  it('encode/decode une epoque a l\'octet pres', () => {
    const f = OwnIdentity.generate()
    const c = genesis(f)
    const e = next(c, f, [op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(f.signPub), access: Access.Manage }])], randomBytes(32))
    const back = decodeEpoch(encodeEpoch(e))
    expect(back).toEqual(e)
    expect(epochId(back)).toEqual(epochId(e))
  })

  it('la sync est un intervalle lineaire (D7)', () => {
    const f = OwnIdentity.generate()
    const c = genesis(f)
    const at0 = c.head()
    for (let i = 0; i < 3; i++) c.append(next(c, f, []))
    expect(c.since(at0)).toHaveLength(3)
    expect(c.since(c.head())).toHaveLength(0)
  })
})

describe('acl-chain — les invariants de l\'etat', () => {
  it('D20 : un write ne modifie pas l\'ACL', () => {
    const f = OwnIdentity.generate()
    const bob = OwnIdentity.generate()
    const mallory = OwnIdentity.generate()
    const c = genesis(f)
    c.append(next(c, f, [op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(bob.signPub), access: Access.Write }])]))

    // bob (write) tente de s'octroyer manage : l'op est signee et valide, mais
    // le fold la refuse -> elle n'a aucun effet.
    const grab = op(bob, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(mallory.signPub), access: Access.Read }])
    c.append(next(c, f, [grab]))
    expect(resolveAccess(c.state(), mallory.signPub)).toBeUndefined()
  })

  it('D20 : un manage ne mint pas un manage, seul un owner le peut', () => {
    const f = OwnIdentity.generate()
    const admin = OwnIdentity.generate()
    const cible = OwnIdentity.generate()
    const c = genesis(f)

    // le fondateur (owner) peut creer un manage
    c.append(next(c, f, [op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(admin.signPub), access: Access.Manage }])]))
    expect(resolveAccess(c.state(), admin.signPub)).toBe(Access.Manage)
    expect(isOwner(c.state(), admin.signPub)).toBe(false)

    // cet admin, qui n'est PAS owner, ne peut pas en creer un autre
    c.append(next(c, f, [op(admin, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(cible.signPub), access: Access.Manage }])]))
    expect(resolveAccess(c.state(), cible.signPub)).toBeUndefined()

    // mais il peut accorder en dessous de lui
    c.append(next(c, f, [op(admin, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(cible.signPub), access: Access.Write }])]))
    expect(resolveAccess(c.state(), cible.signPub)).toBe(Access.Write)
  })

  it('D4/D5 : min en descendant — un groupe read ne donne pas write', () => {
    const f = OwnIdentity.generate()
    const carol = OwnIdentity.generate()
    const TEAM = sha256(new TextEncoder().encode('equipe-design'))
    const c = genesis(f)

    // Carol est manage DANS l'equipe, mais l'equipe n'a que read sur le vault.
    c.append(next(c, f, [
      op(f, TEAM, [{ t: 'set', principal: keyPrincipal(carol.signPub), access: Access.Manage }]),
      op(f, ROOT_GROUP, [{ t: 'set', principal: groupPrincipal(TEAM), access: Access.Read }]),
    ]))
    expect(resolveAccess(c.state(), carol.signPub)).toBe(Access.Read)
  })

  it('D5 : max entre chemins — le meilleur des deux l\'emporte', () => {
    const f = OwnIdentity.generate()
    const carol = OwnIdentity.generate()
    const TEAM = sha256(new TextEncoder().encode('equipe-design'))
    const c = genesis(f)
    c.append(next(c, f, [
      op(f, TEAM, [{ t: 'set', principal: keyPrincipal(carol.signPub), access: Access.Manage }]),
      op(f, ROOT_GROUP, [
        { t: 'set', principal: groupPrincipal(TEAM), access: Access.Read },
        { t: 'set', principal: keyPrincipal(carol.signPub), access: Access.Write }, // en direct
      ]),
    ]))
    expect(resolveAccess(c.state(), carol.signPub)).toBe(Access.Write)
  })

  it('D17 : un groupe ne peut jamais etre vide de ses manage', () => {
    const f = OwnIdentity.generate()
    const c = genesis(f)
    // le fondateur est le seul manage du groupe owners : se retirer est refuse
    const suicide = op(f, OWNERS, [{ t: 'remove', principal: keyPrincipal(f.signPub) }])
    c.append(next(c, f, [suicide], randomBytes(32)))
    expect(resolveAccess(c.state(), f.signPub)).toBe(Access.Manage) // toujours la

    // et un lot qui viderait le groupe est refuse EN ENTIER, pas a moitie
    const second = OwnIdentity.generate()
    c.append(next(c, f, [op(f, OWNERS, [{ t: 'set', principal: keyPrincipal(second.signPub), access: Access.Manage }])]))
    const vider = op(f, OWNERS, [
      { t: 'remove', principal: keyPrincipal(f.signPub) },
      { t: 'remove', principal: keyPrincipal(second.signPub) },
    ])
    c.append(next(c, f, [vider], randomBytes(32)))
    expect(resolveAccess(c.state(), f.signPub)).toBe(Access.Manage)
    expect(resolveAccess(c.state(), second.signPub)).toBe(Access.Manage)
  })

  it('D37 : k est toujours impair, et l\'ensemble ne depend pas de la presence', () => {
    const f = OwnIdentity.generate()
    const a = OwnIdentity.generate()
    const b = OwnIdentity.generate()
    const c = genesis(f)
    expect(arbiterSet(c.state())).toHaveLength(1)
    expect(quorumSize(1)).toBe(1)

    // deux declares -> on ecarte le moins gradé pour rester impair
    c.append(next(c, f, [op(f, ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(a.signPub), access: Access.Manage },
      { t: 'arbiter', principal: keyPrincipal(a.signPub), on: true },
    ])]))
    expect(arbiterSet(c.state())).toHaveLength(1)

    // trois declares -> k = 3, quorum 2
    c.append(next(c, f, [op(f, ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(b.signPub), access: Access.Manage },
      { t: 'arbiter', principal: keyPrincipal(b.signPub), on: true },
    ])]))
    expect(arbiterSet(c.state())).toHaveLength(3)
    expect(quorumSize(3)).toBe(2)

    // le fondateur (owner) est toujours en tete du classement
    expect(arbiterSet(c.state())[0]).toEqual(f.signPub)
  })

  it('fold est pur : memes epoques, meme etat', () => {
    const f = OwnIdentity.generate()
    const bob = OwnIdentity.generate()
    const c = genesis(f)
    c.append(next(c, f, [op(f, ROOT_GROUP, [{ t: 'set', principal: keyPrincipal(bob.signPub), access: Access.Write }])]))
    const refolded = fold(c.all())
    expect(resolveAccess(refolded, bob.signPub)).toBe(resolveAccess(c.state(), bob.signPub))
    expect(resolveAccess(refolded, f.signPub)).toBe(Access.Manage)
  })

  it('validateEpoch valide contre les arbitres de la position, pas d\'aujourd\'hui', () => {
    const f = OwnIdentity.generate()
    const c = genesis(f)
    const e = next(c, f, [])
    const why = validateEpoch(VAULT, e, { id: c.head(), height: c.height(), state: c.state() })
    expect(why).toBeUndefined()
  })
})
