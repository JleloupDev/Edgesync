// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Key material, indexed by the epoch that INTRODUCED it (D31/D40). The chain
// owns epochs; this holds only the secrets they commit to.
//
// A channel key is DERIVED, never minted (D29):
//
//     K_doc = sha256(K_vault ‖ tag ‖ resourceId)
//
// Two peers therefore compute the same value for the same channel, which deletes
// a whole family of problems rather than solving them: no docWrap to carry, no
// batch to sign against partial recombination, no byte-comparison tiebreak to be
// ground down by a hostile member, and no MAX_MSG ceiling around 6 000 channels.
// A single channel can still be handed to an outsider — importDocKey below
// passes the derived value directly, and the KDF being one-way means holding it
// reveals nothing about K_vault or any other channel.
//
// The chain never carries K_vault itself: it is public (Q2), so it carries only
// sha256(K_vault). adopt() checks the key it is handed against that commitment,
// which is what makes "someone handed me a bogus key" detectable instead of
// something to reconcile after the fact.
import { sha256 } from '@noble/hashes/sha2'
import { concat } from './envelope'
import { toBase64, fromBase64, toHex } from './codec'

const DOC_TAG = new TextEncoder().encode('edgesync-dockey-v1')

/** What an epoch publishes about a new vault key: its hash, never the key. */
export function keyCommitment(vaultKey: Uint8Array): Uint8Array {
  return sha256(vaultKey)
}

export class Keyring {
  /** hex(keyEpochId) → K_vault */
  private readonly vaultKeys = new Map<string, Uint8Array>()
  /** hex(keyEpochId)|hex(resourceId) → K_doc, for channels shared without K_vault */
  private readonly loose = new Map<string, Uint8Array>()

  static empty(): Keyring {
    return new Keyring()
  }

  /**
   * Take the vault key an epoch committed to. `commit` comes from the chain, so
   * a key that does not hash to it is refused outright — there is nothing to
   * reconcile, only something to reject.
   */
  adopt(keyEpochId: Uint8Array, vaultKey: Uint8Array, commit?: Uint8Array): void {
    if (commit && toHex(keyCommitment(vaultKey)) !== toHex(commit)) {
      throw new Error('keyring: vault key does not match the epoch commitment')
    }
    this.vaultKeys.set(toHex(keyEpochId), vaultKey)
  }

  has(keyEpochId: Uint8Array): boolean {
    return this.vaultKeys.has(toHex(keyEpochId))
  }

  vaultKey(keyEpochId: Uint8Array): Uint8Array | undefined {
    return this.vaultKeys.get(toHex(keyEpochId))
  }

  /** Every key epoch we hold — used to answer "what can I still decrypt?". */
  knownEpochs(): Uint8Array[] {
    return [...this.vaultKeys.keys()].map(fromHex)
  }

  /** D29 — derived, so it needs no transport and cannot fork. */
  docKey(keyEpochId: Uint8Array, resourceId: Uint8Array): Uint8Array | undefined {
    const direct = this.loose.get(looseKey(keyEpochId, resourceId))
    if (direct) return direct
    const vk = this.vaultKeys.get(toHex(keyEpochId))
    return vk ? sha256(concat(vk, DOC_TAG, resourceId)) : undefined
  }

  /**
   * Hand ONE channel to an outsider, without K_vault (note sharing). The value
   * is the derived one; the KDF being one-way, it discloses neither the vault
   * key nor any sibling channel.
   */
  importDocKey(keyEpochId: Uint8Array, resourceId: Uint8Array, docKey: Uint8Array): void {
    this.loose.set(looseKey(keyEpochId, resourceId), docKey)
  }

  /** Serialize every secret held. A SECRET blob (ADR-0011: `secret/…`). */
  serialize(): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({
      vaultKeys: [...this.vaultKeys.entries()].map(([e, k]) => [e, toBase64(k)]),
      loose: [...this.loose.entries()].map(([e, k]) => [e, toBase64(k)]),
    }))
  }

  static deserialize(bytes: Uint8Array): Keyring {
    const o = JSON.parse(new TextDecoder().decode(bytes))
    const kr = new Keyring()
    for (const [e, k] of o.vaultKeys ?? []) kr.vaultKeys.set(e, fromBase64(k))
    for (const [e, k] of o.loose ?? []) kr.loose.set(e, fromBase64(k))
    return kr
  }
}

function looseKey(keyEpochId: Uint8Array, resourceId: Uint8Array): string {
  return `${toHex(keyEpochId)}|${toHex(resourceId)}`
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  return out
}
