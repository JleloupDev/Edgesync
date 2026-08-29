// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// The ACL vocabulary: what a right IS, who can hold one, and what an operation
// on the list looks like. Pure bytes and pure functions — no chain, no state, no
// I/O. See docs/Architecture/edgesync-acl-arbitrage-spec.md.
//
// Every op is signed by its INITIATOR and that signature is verified by EVERY
// peer, not only by the arbiters (D39). The arbiters order; the initiator
// authorizes. A quorum of arbiters therefore cannot push through an op that no
// rights-holder asked for.
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { concat } from './envelope'
import { toHex } from './codec'

const PUB = 32
const SIG = 64
const ID = 32 // group id / resourceId

/** Domain separator: an AclOp signature can never be replayed as anything else. */
const OP_TAG = new TextEncoder().encode('edgesync-aclop-v1')

/**
 * The four levels, cumulative (D4). `pull` replicates ciphertext, `read`
 * decrypts, `write` emits accepted ops, `manage` edits the list. Ordered so that
 * a plain `>=` is the authorization test everywhere.
 */
export enum Access {
  Pull = 0,
  Read = 1,
  Write = 2,
  Manage = 3,
}

/**
 * A member is a key, or a GROUP (D5). Groups are what make owner succession an
 * ordinary membership change instead of an impossibility (D19), and what let a
 * person be their devices rather than one key (D18).
 *
 * Pass 1 is FLAT: a group contains keys. The type already admits nested groups
 * so the data model does not have to change when recursion arrives.
 */
export type Principal =
  | { kind: 'key'; signPub: Uint8Array }
  | { kind: 'group'; groupId: Uint8Array }

/** The vault itself. Reserved id: 32 zero bytes; no real group can collide. */
export const ROOT_GROUP = new Uint8Array(ID)

export type AclChange =
  /** Add, promote AND demote — one verb, because they are the same write. */
  | { t: 'set'; principal: Principal; access: Access }
  | { t: 'remove'; principal: Principal }
  /** Declare or withdraw an arbiter (D23: arbiter = admin in v1). */
  | { t: 'arbiter'; principal: Principal; on: boolean }

/**
 * One operation carries SEVERAL changes (D35): "je retire 1, 2, 3 puis
 * j'enregistre" is one op, not three. The grouping comes from the author's
 * intent — never from a time window, which would delay revocation.
 */
export interface AclOp {
  /** Which group's list this edits. ROOT_GROUP = the vault. */
  group: Uint8Array
  changes: AclChange[]
  /** signPub of the initiator. */
  issuer: Uint8Array
  /** Initiator's signature over the canonical body (D39). */
  sig: Uint8Array
}

// ── Stable identity for map keys ────────────────────────────────────────────

/** Stable string id of a principal, for Map/Set keys. Not a wire format. */
export function principalId(p: Principal): string {
  return p.kind === 'key' ? `k:${toHex(p.signPub)}` : `g:${toHex(p.groupId)}`
}

export function keyPrincipal(signPub: Uint8Array): Principal {
  return { kind: 'key', signPub }
}

export function groupPrincipal(groupId: Uint8Array): Principal {
  return { kind: 'group', groupId }
}

// ── Canonical encoding ──────────────────────────────────────────────────────
// The bytes below are BOTH what gets signed and what goes on the wire. One
// encoding, so a peer can never verify a signature over bytes different from
// the ones it will act on.
//
//   Principal   [kind:1][id:32]                       kind 0 = key, 1 = group
//   AclChange   [t:1][principal:33]( [access:1] | [on:1] | )
//   body        [group:32][count:u32][changes…][issuer:32]
//   wire        [body][sig:64]

function encodePrincipal(p: Principal): Uint8Array {
  return p.kind === 'key'
    ? concat(new Uint8Array([0]), p.signPub)
    : concat(new Uint8Array([1]), p.groupId)
}

function encodeChange(c: AclChange): Uint8Array {
  if (c.t === 'set') return concat(new Uint8Array([0]), encodePrincipal(c.principal), new Uint8Array([c.access]))
  if (c.t === 'remove') return concat(new Uint8Array([1]), encodePrincipal(c.principal))
  return concat(new Uint8Array([2]), encodePrincipal(c.principal), new Uint8Array([c.on ? 1 : 0]))
}

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

/** The signed region of an op: everything except the signature. */
export function aclOpBody(op: Omit<AclOp, 'sig'>): Uint8Array {
  return concat(op.group, u32(op.changes.length), ...op.changes.map(encodeChange), op.issuer)
}

export function encodeAclOp(op: AclOp): Uint8Array {
  return concat(aclOpBody(op), op.sig)
}

/**
 * Bounds-checked decode. Throws on anything malformed — a decoder that returned
 * a truncated field would hand a meaningless signature to the verifier.
 */
export function decodeAclOp(b: Uint8Array): { op: AclOp; read: number } {
  let o = 0
  const take = (n: number): Uint8Array => {
    if (o + n > b.length) throw new Error('aclop truncated')
    const out = b.subarray(o, o + n)
    o += n
    return out
  }
  const readPrincipal = (): Principal => {
    const kind = take(1)[0]
    const id = take(ID)
    if (kind === 0) return { kind: 'key', signPub: id }
    if (kind === 1) return { kind: 'group', groupId: id }
    throw new Error('aclop: unknown principal kind')
  }

  const readU32 = (): number => {
    const v = take(4)
    return new DataView(v.buffer, v.byteOffset, 4).getUint32(0, false)
  }

  const group = take(ID)
  const count = readU32()
  const changes: AclChange[] = []
  for (let i = 0; i < count; i++) {
    const t = take(1)[0]
    const principal = readPrincipal()
    if (t === 0) changes.push({ t: 'set', principal, access: take(1)[0] as Access })
    else if (t === 1) changes.push({ t: 'remove', principal })
    else if (t === 2) changes.push({ t: 'arbiter', principal, on: take(1)[0] === 1 })
    else throw new Error('aclop: unknown change type')
  }
  const issuer = take(PUB)
  const sig = take(SIG)
  return { op: { group, changes, issuer, sig }, read: o }
}

// ── Signing ─────────────────────────────────────────────────────────────────

/**
 * What an initiator signs: tag ‖ vaultId ‖ body. The tag stops the signature
 * from being read as any other kind of message; the vaultId stops it from being
 * replayed into a different vault (D31, same discipline as the epoch region).
 */
export function aclOpSignRegion(vaultId: Uint8Array, op: Omit<AclOp, 'sig'>): Uint8Array {
  return concat(OP_TAG, vaultId, aclOpBody(op))
}

export function signAclOp(
  vaultId: Uint8Array,
  draft: Omit<AclOp, 'sig'>,
  sign: (msg: Uint8Array) => Uint8Array,
): AclOp {
  return { ...draft, sig: sign(aclOpSignRegion(vaultId, draft)) }
}

export function verifyAclOp(vaultId: Uint8Array, op: AclOp): boolean {
  try {
    return ed25519.verify(op.sig, aclOpSignRegion(vaultId, op), op.issuer)
  } catch {
    return false
  }
}

/** Content-addressed id of an op — used by reports and by tests. */
export function aclOpId(op: AclOp): Uint8Array {
  return sha256(encodeAclOp(op))
}
