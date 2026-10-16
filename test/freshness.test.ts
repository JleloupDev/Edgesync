// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// ADR-0019 over the network: what an arbiter does with requests that are
// replayed, reordered, or decided concurrently by two admins.
import { describe, it, expect } from 'vitest'
import {
  OwnIdentity, YjsCrdt, Bus, InProcessTransport, PeerStore, Session, Keyring,
  AclChain, Access, ROOT_GROUP, keyPrincipal, resolveAccess, signAclOp, aclOpId,
  encodeAclRequest, frame, MsgType, FloodBroadcast, type AclOp, type IBroadcast, type ITransport,
} from '../src/index'
import { VAULT, VAULT_ID, foundVault, joiner } from './vault-fixture'

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms))

function makePeer(id: string, bus: Bus, chain: AclChain, keyring: Keyring, identity = OwnIdentity.generate(),
  extra: { broadcast?: IBroadcast; onAclConflict?: (c: { op: AclOp; with: string[] }) => void } = {}) {
  const transport = new InProcessTransport(id, bus)
  const session = new Session({
    identity, crdt: new YjsCrdt(), keyring, chain, transport, peers: new PeerStore(), resource: VAULT, ...extra,
  })
  transport.connect()
  return { id, identity, chain, session, transport }
}

/** A gossip memory we can wipe, as a restart would. */
function forgetful(t: ITransport) {
  let inner = new FloodBroadcast(t)
  const b: IBroadcast = { seen: (x) => inner.seen(x), spread: (x, f) => inner.spread(x, f) }
  return { b, forget: () => { inner = new FloodBroadcast(t) } }
}

const set = (who: OwnIdentity, access: Access) => [{ t: 'set' as const, principal: keyPrincipal(who.signPub), access }]

describe('fraicheur des demandes de droits (ADR-0019)', () => {
  it('une admission rejouee apres revocation ne remet pas le revoque, meme apres redemarrage de l\'arbitre', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const t = new InProcessTransport('A', bus)
    const mem = forgetful(t)
    const session = new Session({
      identity: founder, crdt: new YjsCrdt(), keyring, chain, transport: t, peers: new PeerStore(),
      resource: VAULT, broadcast: mem.b,
    })
    t.connect()
    const p2 = OwnIdentity.generate()

    const admission = session.requestAclChange(ROOT_GROUP, set(p2, Access.Write))
    session.requestAclChange(ROOT_GROUP, [{ t: 'remove', principal: keyPrincipal(p2.signPub) }])
    expect(resolveAccess(chain.state(), p2.signPub)).toBeUndefined()

    mem.forget() // l'arbitre redemarre : sa memoire de gossip est vide
    const rejoueur = new InProcessTransport('R', bus)
    rejoueur.connect()
    await settle()
    rejoueur.send('A', frame(MsgType.AclRequest, encodeAclRequest(admission)))
    await settle()

    expect(resolveAccess(chain.state(), p2.signPub)).toBeUndefined()
  })

  it('les demandes d\'un emetteur livrees a l\'envers sont appliquees dans l\'ordre signe', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const a = makePeer('A', bus, chain, keyring, founder)
    // Un admin, hors de l'arbitre, qui prepare deux decisions a la suite.
    const admin = OwnIdentity.generate()
    a.session.requestAclChange(ROOT_GROUP, set(admin, Access.Manage))
    const bob = OwnIdentity.generate()

    const base = chain.head()
    const lecteur = signAclOp(VAULT_ID, { group: ROOT_GROUP, changes: set(bob, Access.Read), issuer: admin.signPub, base }, (m) => admin.sign(m))
    const promu = signAclOp(VAULT_ID, { group: ROOT_GROUP, changes: set(bob, Access.Write), issuer: admin.signPub, base, prev: aclOpId(lecteur) }, (m) => admin.sign(m))

    const r = new InProcessTransport('R', bus)
    r.connect()
    await settle()
    r.send('A', frame(MsgType.AclRequest, encodeAclRequest(promu))) // la seconde d'abord
    await settle()
    expect(resolveAccess(chain.state(), bob.signPub)).toBeUndefined() // elle attend sa precedente
    r.send('A', frame(MsgType.AclRequest, encodeAclRequest(lecteur)))
    await settle()
    expect(resolveAccess(chain.state(), bob.signPub)).toBe(Access.Write) // l'ordre voulu
  })

  it('deux admins qui decident en meme temps sur le meme membre : l\'arbitre le signale', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const conflits: { op: AclOp; with: string[] }[] = []
    const a = makePeer('A', bus, chain, keyring, founder, {
      onAclConflict: (c) => conflits.push(c),
    })
    const admin = OwnIdentity.generate()
    const bob = OwnIdentity.generate()
    a.session.requestAclChange(ROOT_GROUP, set(admin, Access.Manage))

    // L'admin signe sur la tete d'avant ; le fondateur decide sur bob entre-temps.
    const base = chain.head()
    const sienne = signAclOp(VAULT_ID, { group: ROOT_GROUP, changes: set(bob, Access.Read), issuer: admin.signPub, base }, (m) => admin.sign(m))
    a.session.requestAclChange(ROOT_GROUP, set(bob, Access.Write))

    const r = new InProcessTransport('R', bus)
    r.connect()
    await settle()
    r.send('A', frame(MsgType.AclRequest, encodeAclRequest(sienne)))
    await settle()

    expect(conflits).toHaveLength(1)
    expect(resolveAccess(chain.state(), bob.signPub)).toBe(Access.Read) // appliquee quand meme
  })

  it('une demande refusee ne bloque pas les suivantes du meme emetteur', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const a = makePeer('A', bus, chain, keyring, founder)
    const j = joiner()
    const admin = makePeer('B', bus, j.chain, j.keyring)
    await settle()
    a.session.requestAclChange(ROOT_GROUP, set(admin.identity, Access.Manage))
    await settle()

    const cible = OwnIdentity.generate()
    admin.session.requestAclChange(ROOT_GROUP, set(cible, Access.Manage)) // refusee : D20
    admin.session.requestAclChange(ROOT_GROUP, set(cible, Access.Write)) // ne doit pas l'attendre
    await settle()
    expect(resolveAccess(chain.state(), cible.signPub)).toBe(Access.Write)
  })

  it('un membre qui rejoint apres coup valide toute la chaine, rotations comprises', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const a = makePeer('A', bus, chain, keyring, founder)
    for (let i = 0; i < 5; i++) {
      const x = OwnIdentity.generate()
      a.session.requestAclChange(ROOT_GROUP, set(x, Access.Write))
      a.session.requestAclChange(ROOT_GROUP, [{ t: 'remove', principal: keyPrincipal(x.signPub) }])
    }
    const j = joiner()
    const b = makePeer('B', bus, j.chain, j.keyring)
    await settle()
    a.session.requestAclChange(ROOT_GROUP, set(b.identity, Access.Read))
    await settle()

    expect(b.chain.height()).toBe(chain.height())
    expect(resolveAccess(b.chain.state(), b.identity.signPub)).toBe(Access.Read)
  })
})

describe('arbitres multiples sans accord (D42)', () => {
  it('trois arbitres declares : les droits gelent, la chaine ne se scinde pas', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const a = makePeer('A', bus, chain, keyring, founder)
    const j = joiner()
    const b = makePeer('B', bus, j.chain, j.keyring)
    await settle()
    const x = OwnIdentity.generate()
    const y = OwnIdentity.generate()
    a.session.requestAclChange(ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(b.identity.signPub), access: Access.Read },
      { t: 'set', principal: keyPrincipal(x.signPub), access: Access.Manage },
      { t: 'set', principal: keyPrincipal(y.signPub), access: Access.Manage },
      { t: 'arbiter', principal: keyPrincipal(x.signPub), on: true },
      { t: 'arbiter', principal: keyPrincipal(y.signPub), on: true },
    ])
    await settle()
    const gelee = chain.height()

    // k = 3, quorum 2 : l'arbitre ne peut plus signer seul.
    a.session.requestAclChange(ROOT_GROUP, set(OwnIdentity.generate(), Access.Read))
    await settle()
    expect(chain.height()).toBe(gelee)
    expect(b.chain.head()).toEqual(chain.head())
  })
})
