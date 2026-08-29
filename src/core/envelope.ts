// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Cryptographic primitives and the op wire-envelope. Pure functions over bytes:
// no identity, no network, no CRDT. Everything here is independently testable.
import { x25519 } from '@noble/curves/ed25519'
import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { sha256 } from '@noble/hashes/sha2'

const NONCE = 24 // XChaCha20 nonce
const SIG = 64 // Ed25519 signature
const PUB = 32 // Ed25519 / X25519 public key
const EPOCH_ID = 32 // epochId: a POSITION in the chain, not a key (D40)
const RES = 32 // resourceId (sha256 of the resource name)

/**
 * Stable 32-byte id of a resource (channel), derived from its name. Used to
 * bind an op to its channel in the signed region and to route on a shared
 * transport. Not secret; not reversible to the human-readable name.
 */
export function resourceId(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(name))
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

export function concat(...arrs: Uint8Array[]): Uint8Array {
  let total = 0
  for (const a of arrs) total += a.length
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrs) {
    out.set(a, off)
    off += a.length
  }
  return out
}

// ── Symmetric content encryption (XChaCha20-Poly1305) ───────────────────────
export function encrypt(key: Uint8Array, plaintext: Uint8Array): { nonce: Uint8Array; ciphertext: Uint8Array } {
  const nonce = randomBytes(NONCE)
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext)
  return { nonce, ciphertext }
}

export function decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce).decrypt(ciphertext)
}

// ── Hybrid wrap to a public key (sealed box, ephemeral X25519 + AEAD) ────────
// Layout: ephPub(32) || nonce(24) || ciphertext. The symmetric key binds the
// ephemeral and recipient public keys to thwart key-reuse/substitution.
export function seal(recipientBoxPub: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const ephPriv = randomBytes(PUB)
  const ephPub = x25519.getPublicKey(ephPriv)
  const shared = x25519.getSharedSecret(ephPriv, recipientBoxPub)
  const key = sha256(concat(shared, ephPub, recipientBoxPub))
  const { nonce, ciphertext } = encrypt(key, plaintext)
  return concat(ephPub, nonce, ciphertext)
}

export function unseal(boxPriv: Uint8Array, sealed: Uint8Array): Uint8Array {
  const ephPub = sealed.subarray(0, PUB)
  const nonce = sealed.subarray(PUB, PUB + NONCE)
  const ciphertext = sealed.subarray(PUB + NONCE)
  const recipientBoxPub = x25519.getPublicKey(boxPriv)
  const shared = x25519.getSharedSecret(boxPriv, ephPub)
  const key = sha256(concat(shared, ephPub, recipientBoxPub))
  return decrypt(key, nonce, ciphertext)
}

// ── Op envelope: [resourceId:32][epochId:32][nonce:24][ciphertext:N][sig:64][signerPub:32]
// resourceId + epochId travel in clear (routing + decryption hint, self-validated
// by the AEAD). The signature covers resourceId || epochId || nonce || ciphertext,
// so an op signed for one channel cannot be replayed into another.
//
// D40 — `epochId` is a POSITION in the chain, NOT a key. Most epochs carry no key
// material (D11), so a receiver does two distinct things with it:
//   authorisation  read the ACL state AT that position
//   decryption     walk the chain back from it to the last key change
// One field, two meanings: obvious once written, a guaranteed bug if it is not.
export interface Envelope {
  resourceId: Uint8Array
  epochId: Uint8Array
  nonce: Uint8Array
  ciphertext: Uint8Array
  sig: Uint8Array
  signerPub: Uint8Array
}

export function signedRegion(rid: Uint8Array, epochId: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return concat(rid, epochId, nonce, ciphertext)
}

export function encodeEnvelope(e: Envelope): Uint8Array {
  return concat(signedRegion(e.resourceId, e.epochId, e.nonce, e.ciphertext), e.sig, e.signerPub)
}

// Smallest possible envelope: resourceId + header + nonce + (empty ciphertext)
// + sig + pub. Anything shorter cannot be parsed without out-of-bounds reads.
const MIN_ENVELOPE = RES + EPOCH_ID + NONCE + SIG + PUB

export function decodeEnvelope(bytes: Uint8Array): Envelope {
  const len = bytes.length
  if (len < MIN_ENVELOPE) throw new Error('envelope too short')
  const resourceId = bytes.subarray(0, RES)
  const epochId = bytes.subarray(RES, RES + EPOCH_ID)
  const nonce = bytes.subarray(RES + EPOCH_ID, RES + EPOCH_ID + NONCE)
  const ciphertext = bytes.subarray(RES + EPOCH_ID + NONCE, len - SIG - PUB)
  const sig = bytes.subarray(len - SIG - PUB, len - PUB)
  const signerPub = bytes.subarray(len - PUB)
  return { resourceId, epochId, nonce, ciphertext, sig, signerPub }
}
