// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Persistence through the IStorage port. The protocol decides WHAT to persist and
// under WHICH sensitivity namespace; it never decides HOW it is protected at rest
// (the app's adapter does — ADR-0011). Content is stored per channel as
// protocol-ciphertext (reusing that channel's derived K_doc), so it is never in
// clear at rest even under a plaintext adapter; only `secret/…` (identity,
// keyring) needs the app's at-rest protection.
//
// The chain lives under `open/…`: it is public by decision (Q2), signed and
// self-validating, so storing it in clear leaks nothing that serving it to any
// peer (D8) would not already leak.
import { OwnIdentity } from '../core/identity'
import { Keyring } from '../core/keyring'
import { AclChain, encodeEpoch, decodeEpoch } from '../core/acl-chain'
import { encrypt, decrypt, concat } from '../core/envelope'
import { toHex } from '../core/codec'
import { PeerStore } from '../ports/peer-store'
import type { IStorage } from '../ports/storage'
import type { ICrdt } from '../ports/crdt'

const K_IDENTITY = 'secret/identity'
const K_KEYRING = 'secret/keyring'
const K_PEERS = 'open/peers'
const K_CHAIN = 'open/chain'
const K_CONTENT = 'open/content'

const EPOCH_ID = 32
const NONCE = 24

function contentKey(resourceId: Uint8Array): string {
  return `${K_CONTENT}/${toHex(resourceId)}`
}

export async function loadIdentity(s: IStorage): Promise<OwnIdentity | undefined> {
  const b = await s.get(K_IDENTITY)
  return b ? OwnIdentity.deserialize(b) : undefined
}

export async function loadKeyring(s: IStorage): Promise<Keyring | undefined> {
  const b = await s.get(K_KEYRING)
  return b ? Keyring.deserialize(b) : undefined
}

export async function loadPeers(s: IStorage): Promise<PeerStore | undefined> {
  const b = await s.get(K_PEERS)
  return b ? PeerStore.deserialize(b) : undefined
}

/**
 * Restore the chain. Every epoch is re-validated on the way in — a chain read
 * from disk is no more trusted than one read from the network.
 */
export async function loadChain(s: IStorage, vaultId: Uint8Array): Promise<AclChain | undefined> {
  const b = await s.get(K_CHAIN)
  if (!b) return undefined
  const chain = new AclChain(vaultId)
  let o = 0
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  while (o + 4 <= b.length) {
    const len = view.getUint32(o, false)
    o += 4
    if (o + len > b.length) break
    // Height 0 bootstraps the chain; every later epoch must chain AND certify.
    chain.adoptEpoch(decodeEpoch(b.subarray(o, o + len)))
    o += len
  }
  return chain
}

/** Decrypt one channel's persisted content into the given CRDT. */
export async function loadContent(
  s: IStorage,
  resourceId: Uint8Array,
  crdt: ICrdt,
  keyring: Keyring,
  chain: AclChain,
): Promise<void> {
  const b = await s.get(contentKey(resourceId))
  if (!b || b.length < EPOCH_ID + NONCE) return
  const position = b.subarray(0, EPOCH_ID)
  const nonce = b.subarray(EPOCH_ID, EPOCH_ID + NONCE)
  const ciphertext = b.subarray(EPOCH_ID + NONCE)
  // D40 — the stored id is a POSITION; the key is the last one committed at or
  // before it.
  const keyEpoch = chain.keyEpochAt(position)
  const key = keyEpoch && keyring.docKey(keyEpoch, resourceId)
  if (!key) return
  try {
    crdt.applyRemote(decrypt(key, nonce, ciphertext))
  } catch {
    // unreadable with the keys we hold
  }
}

export interface PersistableChannel {
  resourceId: Uint8Array
  crdt: ICrdt
}

export interface PersistableParts {
  identity: OwnIdentity
  keyring: Keyring
  peers: PeerStore
  chain: AclChain
  /** One entry per channel to persist (a Session persists only its own). */
  channels: PersistableChannel[]
}

export async function saveAll(s: IStorage, parts: PersistableParts): Promise<void> {
  await s.set(K_IDENTITY, parts.identity.serialize())
  await s.set(K_KEYRING, parts.keyring.serialize())
  await s.set(K_PEERS, parts.peers.serialize())

  const epochs = parts.chain.all().map((e) => {
    const bytes = encodeEpoch(e)
    const len = new Uint8Array(4)
    new DataView(len.buffer).setUint32(0, bytes.length, false)
    return concat(len, bytes)
  })
  await s.set(K_CHAIN, concat(...epochs))

  // Content at rest = ciphertext under the current position's K_doc.
  const position = parts.chain.head()
  const keyEpoch = parts.chain.keyEpochAt(position)
  for (const { resourceId, crdt } of parts.channels) {
    const key = keyEpoch && parts.keyring.docKey(keyEpoch, resourceId)
    if (!key) continue
    const { nonce, ciphertext } = encrypt(key, crdt.snapshot())
    await s.set(contentKey(resourceId), concat(position, nonce, ciphertext))
  }
}
