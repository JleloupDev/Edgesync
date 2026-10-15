// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Gossip: live messages reach peers we are not connected to. The bus is laid out
// as a line or a ring instead of the default full mesh — the only case where
// relaying matters, and the normal one in real peer-to-peer.
import { describe, it, expect } from 'vitest'
import {
  OwnIdentity, YjsCrdt, Bus, InProcessTransport, PeerStore, Session, Keyring,
  AclChain, Access, ROOT_GROUP, keyPrincipal, resolveAccess,
  encrypt, signedRegion, encodeEnvelope, decodeEnvelope, frame, unframe, MsgType,
  FloodBroadcast, type IBroadcast, type ITransport,
} from '../src/index'
import { VAULT, VAULT_ID, foundVault, joiner } from './vault-fixture'

const settle = (ms = 250) => new Promise((r) => setTimeout(r, ms))

function makePeer(
  id: string, bus: Bus, chain: AclChain, keyring: Keyring,
  identity = OwnIdentity.generate(),
  broadcast?: (t: ITransport) => IBroadcast,
) {
  const crdt = new YjsCrdt()
  const transport = new InProcessTransport(id, bus)
  const session = new Session({
    identity, crdt, keyring, chain, transport, peers: new PeerStore(), resource: VAULT,
    broadcast: broadcast?.(transport),
  })
  transport.connect()
  return { id, identity, crdt, chain, keyring, session, text: () => crdt.text().toString() }
}

/** A founds the vault, B and C join; the arbiter A admits them in one op. */
async function threePeers(links?: [string, string][], cAccess = Access.Write) {
  const bus = new Bus(links)
  const founder = OwnIdentity.generate()
  const { chain, keyring } = foundVault(founder)
  const a = makePeer('A', bus, chain, keyring, founder)
  const jb = joiner()
  const b = makePeer('B', bus, jb.chain, jb.keyring)
  const jc = joiner()
  const c = makePeer('C', bus, jc.chain, jc.keyring)
  await settle()

  a.session.requestAclChange(ROOT_GROUP, [
    { t: 'set', principal: keyPrincipal(b.identity.signPub), access: Access.Write },
    { t: 'set', principal: keyPrincipal(c.identity.signPub), access: cAccess },
  ])
  await settle()
  return { bus, a, b, c }
}

const opsFrom = (bus: Bus, since: number) =>
  bus.frames.slice(since).filter((f) => unframe(f.bytes).type === MsgType.Op)

describe('gossip — diffusion simple par inondation', () => {
  it('ligne A-B-C : l\'epoque et le contenu traversent B, signes par leur auteur', async () => {
    const { bus, a, c } = await threePeers([['A', 'B'], ['B', 'C']])

    // C n'est pas voisin de l'arbitre : il a appris son admission par B, puis
    // obtenu la cle aupres de B (D12, n'importe quel detenteur repare).
    expect(c.chain.height()).toBe(a.chain.height())
    expect(resolveAccess(c.chain.state(), c.identity.signPub)).toBe(Access.Write)

    const since = bus.frames.length
    a.crdt.text().insert(0, 'bonjour')
    await settle()
    expect(c.text()).toBe('bonjour')

    // Ce que C a recu de B est un Op en direct, octet pour octet celui de A.
    const relayed = opsFrom(bus, since).filter((f) => f.from === 'B' && f.to === 'C')
    expect(relayed).toHaveLength(1)
    const env = decodeEnvelope(unframe(relayed[0].bytes).payload)
    expect(env.signerPub).toEqual(a.identity.signPub)
  })

  it('triangle : chaque pair relaie une fois, le flot s\'arrete seul', async () => {
    const { bus, a, b, c } = await threePeers()
    const since = bus.frames.length
    a.crdt.text().insert(0, 'une fois')
    await settle()

    expect(b.text()).toBe('une fois')
    expect(c.text()).toBe('une fois')
    // A vers B et C, puis B vers C et C vers B ; les copies deja vues s'arretent la.
    expect(opsFrom(bus, since)).toHaveLength(4)
  })

  it('une demande de droits atteint un arbitre qui n\'est pas voisin', async () => {
    // C est admin (manage) : sa demande est valide, B la relaie jusqu'a A.
    const { a, c } = await threePeers([['A', 'B'], ['B', 'C']], Access.Manage)
    const d = OwnIdentity.generate()

    c.session.requestAclChange(ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(d.signPub), access: Access.Read },
    ])
    await settle()

    expect(resolveAccess(a.chain.state(), d.signPub)).toBe(Access.Read)
    // Et l'epoque est revenue jusqu'a C, toujours par B.
    expect(resolveAccess(c.chain.state(), d.signPub)).toBe(Access.Read)
  })

  it('une op forgee par un non-membre n\'est pas relayee', async () => {
    const { bus, a, b } = await threePeers([['A', 'B'], ['B', 'C'], ['B', 'X']])
    const etranger = OwnIdentity.generate()
    const pos = b.chain.head()
    const key = a.keyring.docKey(b.chain.keyEpochAt(pos)!, VAULT_ID)!
    const { nonce, ciphertext } = encrypt(key, new Uint8Array([1, 2, 3]))
    const forged = frame(MsgType.Op, encodeEnvelope({
      resourceId: VAULT_ID, epochId: pos, nonce, ciphertext,
      sig: etranger.sign(signedRegion(VAULT_ID, pos, nonce, ciphertext)),
      signerPub: etranger.signPub,
    }))

    const x = new InProcessTransport('X', bus)
    x.connect()
    await settle()
    const since = bus.frames.length
    x.send('B', forged)
    await settle()

    // B l'a recue, ne l'a pas appliquee, et n'a rien fait suivre.
    expect(opsFrom(bus, since).filter((f) => f.from === 'B')).toHaveLength(0)
  })

  it('la strategie de diffusion s\'injecte sans toucher a la session', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const spread: MsgType[] = []
    const spy = (t: ITransport): IBroadcast => {
      const inner = new FloodBroadcast(t)
      return {
        seen: (bytes) => inner.seen(bytes),
        spread: (bytes, from) => { spread.push(unframe(bytes).type); inner.spread(bytes, from) },
      }
    }
    const a = makePeer('A', bus, chain, keyring, founder, spy)
    a.crdt.text().insert(0, 'x')
    await settle()

    expect(spread).toContain(MsgType.Op)
  })
})
