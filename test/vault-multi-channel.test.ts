// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// One vault, several channels. Since D29 derives K_doc from K_vault instead of
// minting it, this file tests something much smaller than it used to: there is
// no per-channel key exchange left to get wrong.
//
// What it replaces: the old suite covered a docWraps batch, a partial
// recombination attack on its signature, and a race where two peers both elected
// themselves owner and minted rival keys. None of those exist any more — the
// first two because there is no batch, the third because the chain decides.
import { describe, it, expect } from 'vitest'
import {
  OwnIdentity, YjsCrdt, Bus, InProcessTransport, PeerStore, Session, Keyring,
  AclChain, Access, ROOT_GROUP, keyPrincipal, resourceId, resolveAccess,
} from '../src/index'
import { VAULT, VAULT_ID, foundVault, joiner } from './vault-fixture'

const settle = (ms = 140) => new Promise((r) => setTimeout(r, ms))

/**
 * A peer: ONE transport, ONE PeerStore, and as many Sessions as channels. That
 * is the real shape — the app multiplexes every channel of a vault over a single
 * connection, and each Session filters on its own resourceId.
 */
function makePeer(id: string, bus: Bus, chain: AclChain, keyring: Keyring, identity: OwnIdentity) {
  const transport = new InProcessTransport(id, bus)
  const peers = new PeerStore()
  const channels = new Map<string, { crdt: YjsCrdt; session: Session }>()

  const open = (resource: string) => {
    const crdt = new YjsCrdt()
    const session = new Session({ identity, crdt, keyring, chain, transport, peers, resource })
    channels.set(resource, { crdt, session })
    return { crdt, session, text: () => crdt.text().toString() }
  }
  return {
    identity, chain, keyring, transport, open,
    connect: () => transport.connect(),
    dispose: () => { for (const c of channels.values()) c.session.dispose() },
  }
}

describe('vault multi-canal — une chaine, un keyring, des cles derivees', () => {
  it('le grant sur le vault suffit : aucun echange de cle par canal', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder)
    const j = joiner()
    const guest = OwnIdentity.generate()

    // Le canal du vault : c'est lui qui porte l'autorite et la cle.
    const a = makePeer('A', bus, chain, keyring, founder)
    const b = makePeer('B', bus, j.chain, j.keyring, guest)
    const aVault = a.open(VAULT)
    b.open(VAULT)
    a.connect(); b.connect()
    await settle()

    aVault.session.requestAclChange(ROOT_GROUP, [
      { t: 'set', principal: keyPrincipal(guest.signPub), access: Access.Write },
    ])
    await settle()
    expect(resolveAccess(j.chain.state(), guest.signPub)).toBe(Access.Write)

    // Deux canaux document, ouverts APRES le grant, sur le meme keyring partage.
    // Aucun message KEY n'est echange pour eux : la cle se DERIVE.
    const keyEpoch = chain.keyEpochAt(chain.head())!
    for (const doc of ['vault-1/doc/1', 'vault-1/doc/2']) {
      const rid = resourceId(doc)
      expect(keyring.docKey(keyEpoch, rid)).toEqual(j.keyring.docKey(keyEpoch, rid))
    }

    const a1 = a.open('vault-1/doc/1')
    const b1 = b.open('vault-1/doc/1')
    await settle()

    a1.crdt.text().insert(0, 'contenu du doc 1')
    await settle()
    expect(b1.text()).toBe('contenu du doc 1')

    a.dispose(); b.dispose()
  })

  it('D29 : deux pairs qui ouvrent le MEME canal derivent la meme cle', () => {
    // C'etait le fork de K_doc : deux pairs minaient chacun une cle aleatoire
    // pour un meme resourceId, et il fallait les departager par comparaison
    // d'octets — departage qu'un byzantin pouvait broyer. La derivation le
    // rend impossible plutot que reparable.
    const founder = OwnIdentity.generate()
    const { chain, keyring, vaultKey } = foundVault(founder)
    const other = Keyring.empty()
    other.adopt(chain.head(), vaultKey)

    const rid = resourceId('vault-1/index/wikilinks')
    expect(keyring.docKey(chain.head(), rid)).toEqual(other.docKey(chain.head(), rid))
  })

  it('un canal ouvert apres coup marche sans rien renegocier', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const guest = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder, [{ signPub: guest.signPub, access: Access.Write }])
    const j = joiner()

    const a = makePeer('A', bus, chain, keyring, founder)
    const b = makePeer('B', bus, j.chain, j.keyring, guest)
    a.open(VAULT); b.open(VAULT)
    a.connect(); b.connect()
    await settle()
    expect(j.keyring.knownEpochs()).toHaveLength(1) // la cle est arrivee

    // Nouveau document, bien apres la connexion : il fonctionne tout de suite.
    const a2 = a.open('vault-1/doc/tardif')
    const b2 = b.open('vault-1/doc/tardif')
    await settle()

    a2.crdt.text().insert(0, 'ouvert plus tard')
    await settle()
    expect(b2.text()).toBe('ouvert plus tard')

    a.dispose(); b.dispose()
  })

  it('une revocation coupe TOUS les canaux d\'un coup', async () => {
    const bus = new Bus()
    const founder = OwnIdentity.generate()
    const guest = OwnIdentity.generate()
    const { chain, keyring } = foundVault(founder, [{ signPub: guest.signPub, access: Access.Write }])
    const j = joiner()

    const a = makePeer('A', bus, chain, keyring, founder)
    const b = makePeer('B', bus, j.chain, j.keyring, guest)
    const aVault = a.open(VAULT)
    b.open(VAULT)
    const a1 = a.open('vault-1/doc/1')
    const b1 = b.open('vault-1/doc/1')
    a.connect(); b.connect()
    await settle()

    a1.crdt.text().insert(0, 'avant')
    await settle()
    expect(b1.text()).toBe('avant')

    aVault.session.requestAclChange(ROOT_GROUP, [
      { t: 'remove', principal: keyPrincipal(guest.signPub) },
    ])
    await settle()

    a1.crdt.text().insert(5, ' apres')
    await settle()
    expect(a1.text()).toBe('avant apres')
    expect(b1.text()).toBe('avant') // une seule rotation, tous les canaux coupes

    a.dispose(); b.dispose()
  })
})
