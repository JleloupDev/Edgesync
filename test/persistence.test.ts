// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Persistence through the IStorage port. The protocol stores content as
// ciphertext (never in clear at rest); only secret/… blobs would need the app's
// at-rest protection.
import { describe, it, expect } from 'vitest'
import { readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  OwnIdentity, YjsCrdt, Bus, InProcessTransport, PeerStore, Session, resourceId, toHex,
  InMemoryStorage, FileSystemStorage, loadIdentity, loadKeyring, loadChain, loadContent,
} from '../src/node'
import { VAULT, VAULT_ID, foundVault } from './vault-fixture'

const RID = resourceId('vault-1')
const settle = (ms = 60) => new Promise((r) => setTimeout(r, ms))

function containsSub(hay: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

async function writeAndPersist(storage: InMemoryStorage | FileSystemStorage, text: string) {
  const identity = OwnIdentity.generate()
  const { chain, keyring } = foundVault(identity)
  const crdt = new YjsCrdt()
  const transport = new InProcessTransport('A', new Bus())
  const session = new Session({ identity, crdt, keyring, chain, peers: new PeerStore(), transport, resource: VAULT, storage })
  transport.connect()
  crdt.text().insert(0, text)
  await settle()
  await session.persist()
  session.dispose()
  return identity.signPub
}

describe('persistence — IStorage, contenu chiffre au repos', () => {
  it('in-memory : restaure identite + keyring + contenu ; contenu jamais en clair', async () => {
    const storage = new InMemoryStorage()
    const text = 'persisted secret content'
    const signPubBefore = await writeAndPersist(storage, text)

    // le blob de contenu est du ciphertext
    const contentBlob = await storage.get(`open/content/${toHex(RID)}`)
    expect(contentBlob).toBeDefined()
    expect(containsSub(contentBlob!, new TextEncoder().encode(text))).toBe(false)

    // "redemarrage" : on recharge depuis le storage
    const identity2 = await loadIdentity(storage)
    const keyring2 = await loadKeyring(storage)
    const chain2 = await loadChain(storage, VAULT_ID)
    expect(identity2).toBeDefined()
    expect(keyring2).toBeDefined()
    expect(chain2).toBeDefined()
    expect(identity2!.signPub).toEqual(signPubBefore) // meme identite

    const crdt2 = new YjsCrdt()
    await loadContent(storage, RID, crdt2, keyring2!, chain2!)
    expect(crdt2.text().toString()).toBe(text) // contenu restaure
  })

  it('filesystem : roundtrip et contenu chiffre sur disque', async () => {
    const dir = join(tmpdir(), `edgesync-poc-${Date.now()}-${Math.random().toString(36).slice(2)}`)
    const storage = new FileSystemStorage(dir)
    const text = 'on disk secret'
    const signPubBefore = await writeAndPersist(storage, text)

    // le fichier de contenu ne contient pas le clair
    const onDisk = new Uint8Array(await readFile(join(dir, `open__content__${toHex(RID)}`)))
    expect(containsSub(onDisk, new TextEncoder().encode(text))).toBe(false)

    // recharge depuis un nouveau storage sur le meme repertoire
    const storage2 = new FileSystemStorage(dir)
    const id2 = await loadIdentity(storage2)
    const kr2 = await loadKeyring(storage2)
    const ch2 = await loadChain(storage2, VAULT_ID)
    const crdt2 = new YjsCrdt()
    await loadContent(storage2, RID, crdt2, kr2!, ch2!)
    expect(crdt2.text().toString()).toBe(text)
    expect(id2!.signPub).toEqual(signPubBefore)

    await rm(dir, { recursive: true, force: true })
  })
})
