// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Wire messages. Framed as [type:1][payload]. Payloads are BINARY: fixed-size
// cryptographic fields written raw, variable-size fields length-prefixed with a
// big-endian uint32. Same discipline as the op envelope (ADR-0004).
//
// Binary rather than JSON+base64 (C0, edgesync-acl-arbitrage-spec.md §03):
// base64 costs 33% on payloads that are bytes all the way down, and a JSON
// parser sitting on the hostile-input path is attack surface we do not need.
// core/codec.ts keeps base64 for persistence and tests, off the network path.
//
// Every decoder is bounds-checked and THROWS on malformed input. Session.onMessage
// treats any throw as a silent drop, so a hostile frame from one peer can never
// take down the session.
import { concat } from '../core/envelope'
import { encodeAclOp, decodeAclOp, type AclOp } from '../core/acl-ops'
import { encodeEpoch, decodeEpoch, type Epoch } from '../core/acl-chain'

export enum MsgType {
  Hello = 1,
  Op = 2,
  Key = 3,
  SyncReq = 4,
  SyncResp = 5,
  /** D22 — a request circulates; it has no effect until an arbiter commits it. */
  AclRequest = 6,
  /** A committed epoch, certificate included. */
  EpochPush = 7,
  ChainReq = 8,
  ChainResp = 9,
  /** D14 — "I refuse", never "I did not receive". */
  Reject = 10,
  KeyRequest = 11,
}

export function frame(type: MsgType, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + payload.length)
  out[0] = type
  out.set(payload, 1)
  return out
}

export function unframe(bytes: Uint8Array): { type: MsgType; payload: Uint8Array } {
  if (bytes.length < 1) throw new Error('empty frame')
  return { type: bytes[0] as MsgType, payload: bytes.subarray(1) }
}

// ── Primitives ──────────────────────────────────────────────────────────────
// Sizes of the fixed cryptographic fields. Duplicated from core/envelope rather
// than imported: this module owns the control-message layout, envelope.ts owns
// the op layout, and neither should drift because the other changed.
const PUB = 32 // Ed25519 / X25519 public key
const NONCE = 24 // XChaCha20 nonce
const SIG = 64 // Ed25519 signature
const RES = 32 // resourceId (sha256 of the resource name)

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

/** A variable-length field: [len:u32][bytes]. */
function lp(bytes: Uint8Array): Uint8Array {
  return concat(u32be(bytes.length), bytes)
}

const enc = new TextEncoder()
const dec = new TextDecoder()

/**
 * Bounds-checked cursor over a payload. Every read validates that the bytes are
 * actually there, so a truncated or crafted frame throws instead of producing a
 * short/garbage field that would then be signature-checked against nothing.
 */
class Reader {
  private off = 0
  constructor(private readonly b: Uint8Array) {}

  fixed(n: number): Uint8Array {
    if (this.off + n > this.b.length) throw new Error('message truncated')
    const out = this.b.subarray(this.off, this.off + n)
    this.off += n
    return out
  }

  u32(): number {
    const v = this.fixed(4)
    return new DataView(v.buffer, v.byteOffset, 4).getUint32(0, false)
  }

  /** A [len:u32][bytes] field. */
  varbytes(): Uint8Array {
    return this.fixed(this.u32())
  }

  str(): string {
    return dec.decode(this.varbytes())
  }

  /** Reject trailing garbage: a well-formed message consumes its payload exactly. */
  end(): void {
    if (this.off !== this.b.length) throw new Error('trailing bytes')
  }
}

// ── HELLO ───────────────────────────────────────────────────────────────────
// [signPub:32][boxPub:32][nonce:24][sig:64] — fixed 152 bytes.

export interface HelloMsg {
  signPub: Uint8Array
  boxPub: Uint8Array
  nonce: Uint8Array
  sig: Uint8Array
}

export function encodeHello(m: HelloMsg): Uint8Array {
  return concat(m.signPub, m.boxPub, m.nonce, m.sig)
}

export function decodeHello(p: Uint8Array): HelloMsg {
  const r = new Reader(p)
  const m = { signPub: r.fixed(PUB), boxPub: r.fixed(PUB), nonce: r.fixed(NONCE), sig: r.fixed(SIG) }
  r.end()
  return m
}

// ── KEY ─────────────────────────────────────────────────────────────────────
// [resource:lp][keyEpochId:32][sealedVaultKey:lp]
// [grantorSignPub:32][recipientSignPub:32][sig:64]
//
// No docWraps any more (D29): channel keys are DERIVED from K_vault, so a grant
// carries one sealed key instead of one wrap per channel. That is what removed
// the MAX_MSG ceiling around 6 000 channels, and with it the whole class of
// partial-recombination and key-collision problems.

export interface KeyMsg {
  /** id of the VAULT (not a single document) — routes the grant to the vault Session. */
  resource: string
  /** The epoch that INTRODUCED this key, not the current position (D40). */
  keyEpochId: Uint8Array
  sealedVaultKey: Uint8Array
  /** Signing key of the grantor; must be a pinned peer on receipt. */
  grantorSignPub: Uint8Array
  /** Signing key of the intended recipient; binds the grant to one peer. */
  recipientSignPub: Uint8Array
  /** Grantor signature over the grant region (see Session.keyGrantRegion). */
  sig: Uint8Array
}

export function encodeKey(m: KeyMsg): Uint8Array {
  return concat(
    lp(enc.encode(m.resource)), m.keyEpochId, lp(m.sealedVaultKey),
    m.grantorSignPub, m.recipientSignPub, m.sig,
  )
}

export function decodeKey(p: Uint8Array): KeyMsg {
  const r = new Reader(p)
  const m = {
    resource: r.str(), keyEpochId: r.fixed(RES), sealedVaultKey: r.varbytes(),
    grantorSignPub: r.fixed(PUB), recipientSignPub: r.fixed(PUB), sig: r.fixed(SIG),
  }
  r.end()
  return m
}

// ── SYNC_REQ ────────────────────────────────────────────────────────────────
// [resourceId:32][stateVector:lp]

export interface SyncReqMsg {
  resourceId: Uint8Array
  stateVector: Uint8Array
}

export function encodeSyncReq(m: SyncReqMsg): Uint8Array {
  return concat(m.resourceId, lp(m.stateVector))
}

export function decodeSyncReq(p: Uint8Array): SyncReqMsg {
  const r = new Reader(p)
  const m = { resourceId: r.fixed(RES), stateVector: r.varbytes() }
  r.end()
  return m
}

// ── ACL / chain messages ────────────────────────────────────────────────────

/** D22 — anyone MAY emit a request; only arbiters commit it. */
export function encodeAclRequest(op: AclOp): Uint8Array {
  return encodeAclOp(op)
}

export function decodeAclRequest(p: Uint8Array): AclOp {
  const { op, read } = decodeAclOp(p)
  if (read !== p.length) throw new Error('acl request: trailing bytes')
  return op
}

export function encodeEpochPush(e: Epoch): Uint8Array {
  return encodeEpoch(e)
}

export function decodeEpochPush(p: Uint8Array): Epoch {
  return decodeEpoch(p)
}

/** D7 — sync is a linear interval: "give me the epochs after this one". */
export function encodeChainReq(fromEpochId: Uint8Array): Uint8Array {
  return fromEpochId
}

export function decodeChainReq(p: Uint8Array): Uint8Array {
  const r = new Reader(p)
  const id = r.fixed(RES)
  r.end()
  return id
}

export function encodeChainResp(epochs: Epoch[]): Uint8Array {
  return concat(u32be(epochs.length), ...epochs.map((e) => lp(encodeEpoch(e))))
}

export function decodeChainResp(p: Uint8Array): Epoch[] {
  const r = new Reader(p)
  const n = r.u32()
  const out: Epoch[] = []
  for (let i = 0; i < n; i++) out.push(decodeEpoch(r.varbytes()))
  r.end()
  return out
}

/**
 * D14 — why a frame was refused. NEVER carries "not authorized": that is the one
 * reason that would leak membership to someone who has no business knowing it,
 * so an unauthorized peer gets the silent drop it always got.
 */
export enum RejectReason {
  /** Your position is not one I know — you are behind, or on another branch. */
  EpochUnknown = 1,
  /** I know the position but hold no key for it. */
  Undecryptable = 2,
}

export interface RejectMsg {
  resourceId: Uint8Array
  reason: RejectReason
  /** My current head, so you can ask for exactly what you are missing. */
  head: Uint8Array
}

export function encodeReject(m: RejectMsg): Uint8Array {
  return concat(m.resourceId, new Uint8Array([m.reason]), m.head)
}

export function decodeReject(p: Uint8Array): RejectMsg {
  const r = new Reader(p)
  const m = { resourceId: r.fixed(RES), reason: r.fixed(1)[0] as RejectReason, head: r.fixed(RES) }
  r.end()
  return m
}

/** D12 — a repair, not a grant: anyone holding the key may answer it. */
export interface KeyRequestMsg {
  resource: string
  keyEpochId: Uint8Array
}

export function encodeKeyRequest(m: KeyRequestMsg): Uint8Array {
  return concat(lp(enc.encode(m.resource)), m.keyEpochId)
}

export function decodeKeyRequest(p: Uint8Array): KeyRequestMsg {
  const r = new Reader(p)
  const m = { resource: r.str(), keyEpochId: r.fixed(RES) }
  r.end()
  return m
}
