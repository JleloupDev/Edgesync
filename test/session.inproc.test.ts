// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Integration: the protocol over the in-process transport. Pure P2P, no server —
// the arbiter here is a peer like any other (k=1, D37), which is what makes the
// serverless mode a real mode rather than a degraded one.
import { describe, it, expect } from 'vitest'
import {
  OwnIdentity, YjsCrdt, Bus, InProcessTransport, PeerStore, Session, Keyring,
  AclChain, Access, ROOT_GROUP, keyPrincipal, resolveAccess, randomBytes,
  encrypt, signedRegion, encodeEnvelope, resourceId, concat, encodeHello, encodeKey,
  frame, MsgType,
} from '../src/index'
import { VAULT, VAULT_ID, OWNERS, foundVault, joiner, aclOp } from './vault-fixture'

const settle = (ms = 140) => new Promise((r) => setTimeout(r, ms))

interface Peer {
  id: string
  identity: OwnIdentity
  crdt: YjsCrdt
  chain: AclChain
  keyring: Keyring
  session: Session
  transport: InProcessTransport
  text: () => string
}

function makePeer(
  id: string, bus: Bus, chain: AclChain, keyring: Keyring, identity = OwnIdentity.generate(),
): Peer {
  const crdt = new YjsCrdt()
  const transport = new InProcessTransport(id, bus)
  const session = new Session({
    identity, crdt, keyring, chain, transport, peers: new PeerStore(), resource: VAULT,
  })
  transport.connect()
  return { id, identity, crdt, chain, keyring, session, transport, text: () => crdt.text().toString() }
}

/** Found a vault and bring one more peer in at `access`. */
async function vaultWithTwo(access = Access.Write) {
  const bus = new Bus()
  const founder = OwnIdentity.generate()
  const { chain, keyring } = foundVault(founder)
  const a = makePeer('A', bus, chain, keyring, founder)
  const j = joiner()
  const b = makePeer('B', bus, j.chain, j.keyring)
  await settle()

  a.session.requestAclChange(ROOT_GROUP, [
    { t: 'set', principal: keyPrincipal(b.identity.signPub), access },
  ])
  await settle()
  return { bus, a, b }
}

function concatAll(chunks: Uint8Array[]): Uint8Array {
  let n = 0
  for (const c of chunks) n += c.length
  const out = new Uint8Array(n)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.length
  }
  return out
}

function containsSub(hay: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

describe('session — deux plans, un seul vault', () => {
  it('a+b: le fil ne porte que du chiffre, et deux pairs convergent', async () => {
    const { a, b } = await vaultWithTwo()
    expect(resolveAccess(b.chain.state(), b.identity.signPub)).toBe(Access.Write)

    a.crdt.text().insert(0, 'bonjour')
    await settle()
    expect(b.text()).toBe('bonjour')

    b.crdt.text().insert(7, ' le monde')
    await settle()
    expect(a.text()).toBe('bonjour le monde')
  })

  it('le contenu circule sans qu\'aucun arbitre soit necessaire', async () => {
    const { a, b } = await vaultWithTwo()
    // L'arbitre (A) se tait completement : le plan du contenu ne le traverse pas.
    a.session.dispose()
    b.crdt.text().insert(0, 'ecrit sans arbitre')
    await settle()
    expect(b.text()).toBe('ecrit sans arbitre')
  })

  it('un membre revoque ne lit plus le futur et n\'ecrit plus', async () => {
    const { a, b } = await vaultWithTwo()
    a.crdt.text().insert(0, 'avant')
    await settle()
    expect(b.text()).toBe('avant')

    // Revocation : le lot contient un remove, donc l'epoque porte une cle (D11).
    a.session.requestAclChange(ROOT_GROUP, [{ t: 'remove', principal: keyPrincipal(b.identity.signPub) }])
    await settle()
    expect(resolveAccess(a.chain.state(), b.identity.signPub)).toBeUndefined()

    // A ecrit apres la rotation : B ne peut plus le lire.
    a.crdt.text().insert(5, ' apres')
    await settle()
    expect(a.text()).toBe('avant apres')
    expect(b.text()).toBe('avant') // il garde ce qu'il avait deja (limite assumee)

    // B ecrit : A refuse, il n'est plus autorise a cette position.
    b.crdt.text().insert(0, 'INTRUS ')
    await settle()
    expect(a.text()).toBe('avant apres')
  })

  it('un lot porte plusieurs changements en une seule op (D35)', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const a = makePeer('A', bus, chain, keyring, founder)
    const x = OwnIdentity.generate()
    const y = OwnIdentity.generate()
    await settle()

    const before = a.chain.height()
    a.session.requestAclChange(ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(x.signPub), access: Access.Read },
      { t: 'set', principal: keyPrincipal(y.signPub), access: Access.Write },
    ])
    await settle()

    expect(a.chain.height()).toBe(before + 1) // UNE epoque, pas deux
    expect(resolveAccess(a.chain.state(), x.signPub)).toBe(Access.Read)
    expect(resolveAccess(a.chain.state(), y.signPub)).toBe(Access.Write)
  })

  it('D20 : un write ne s\'octroie rien, meme en emettant une demande valide', async () => {
    const { a, b } = await vaultWithTwo(Access.Write)
    const complice = OwnIdentity.generate()

    // B (write) demande d'ajouter un complice. L'op est signee et circule, mais
    // ni B ni l'arbitre ne peuvent la rendre valide : le fold la refuse.
    b.session.requestAclChange(ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(complice.signPub), access: Access.Read },
    ])
    await settle()
    expect(resolveAccess(a.chain.state(), complice.signPub)).toBeUndefined()
  })

  it('un pair rejoint en retard rattrape la chaine puis la cle', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const a = makePeer('A', bus, chain, keyring, founder)
    a.crdt.text().insert(0, 'deja la')
    await settle()

    // C arrive apres coup, sans rien : ni chaine, ni cle.
    const j = joiner()
    const c = makePeer('C', bus, j.chain, j.keyring)
    await settle()
    expect(c.chain.height()).toBe(0) // il a recupere la genese

    a.session.requestAclChange(ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(c.identity.signPub), access: Access.Write },
    ])
    await settle()

    expect(resolveAccess(c.chain.state(), c.identity.signPub)).toBe(Access.Write)
    expect(c.text()).toBe('deja la')
  })

  it('f: un frame malforme est silencieusement rejete sans casser la session', async () => {
    const { bus, a, b } = await vaultWithTwo()
    const m = new InProcessTransport('M', bus)
    m.connect()
    for (const t of [MsgType.Op, MsgType.Key, MsgType.EpochPush, MsgType.ChainResp]) {
      m.send('A', frame(t, randomBytes(9)))
    }
    await settle()
    a.crdt.text().insert(0, 'vivant')
    await settle()
    expect(b.text()).toBe('vivant')
  })

  it('b1: une op signee par une identite inconnue est rejetee', async () => {
    const { bus, a } = await vaultWithTwo()
    a.crdt.text().insert(0, 'base')
    await settle()

    const etranger = OwnIdentity.generate()
    const pos = a.chain.head()
    const keyEpoch = a.chain.keyEpochAt(pos)!
    const key = a.keyring.docKey(keyEpoch, VAULT_ID)!
    const { nonce, ciphertext } = encrypt(key, new Uint8Array([1, 2, 3]))
    const env = encodeEnvelope({
      resourceId: VAULT_ID, epochId: pos, nonce, ciphertext,
      sig: etranger.sign(signedRegion(VAULT_ID, pos, nonce, ciphertext)),
      signerPub: etranger.signPub,
    })
    const m = new InProcessTransport('M', bus)
    m.connect()
    m.send('A', frame(MsgType.Op, env))
    await settle()
    expect(a.text()).toBe('base') // rien n'a ete applique
  })

  it('C1b: un changement de cle epinglee remonte en alerte au lieu d\'etre avale', async () => {
    const bus = new Bus()
    const alerts: { kind: string; peer: string }[] = []
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)

    const transport = new InProcessTransport('A', bus)
    new Session({
      identity: founder, crdt: new YjsCrdt(), keyring, chain, transport,
      peers: new PeerStore(), resource: VAULT,
      onSecurityAlert: (a) => alerts.push(a),
    })
    transport.connect()

    const m = new InProcessTransport('M', bus)
    m.connect()
    await settle()

    const helloFrom = (who: OwnIdentity) => {
      const nonce = randomBytes(24)
      const transcript = concat(new Uint8Array([1]), who.signPub, who.boxPub, VAULT_ID, nonce)
      return frame(MsgType.Hello, encodeHello({ signPub: who.signPub, boxPub: who.boxPub, nonce, sig: who.sign(transcript) }))
    }
    m.send('A', helloFrom(OwnIdentity.generate()))
    await settle()
    expect(alerts).toHaveLength(0)

    m.send('A', helloFrom(OwnIdentity.generate()))
    await settle()
    expect(alerts).toEqual([{ kind: 'pinned-key-changed', peer: 'M' }])
  })

  it('i: une KEY d\'un grantor non membre est rejetee', async () => {
    const bus = new Bus()
    const j = joiner()
    const x = makePeer('X', bus, j.chain, j.keyring)
    await settle()

    const g = OwnIdentity.generate()
    const m = new InProcessTransport('M', bus)
    m.connect()
    m.send('X', frame(MsgType.Key, encodeKey({
      resource: VAULT, keyEpochId: randomBytes(32), sealedVaultKey: randomBytes(48),
      grantorSignPub: g.signPub, recipientSignPub: x.identity.signPub, sig: randomBytes(64),
    })))
    await settle()
    expect(x.keyring.knownEpochs()).toHaveLength(0)
  })

  it('le contenu sur le fil ne contient jamais le clair', async () => {
    const { bus, a } = await vaultWithTwo()
    const from = bus.wire.length

    a.crdt.text().insert(0, 'MOT-SECRET-42')
    await settle()

    const needle = new TextEncoder().encode('MOT-SECRET-42')
    expect(containsSub(concatAll(bus.wire.slice(from)), needle)).toBe(false)
  })
})
