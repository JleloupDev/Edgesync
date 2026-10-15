// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// The single orchestrator. It wires Identity + AclChain + Keyring + CRDT + Transport:
//   local update -> encrypt(key of the current position) -> sign -> frame -> transport
//   inbound      -> route -> verify -> authorise AT THE POSITION -> decrypt -> applyRemote
// It knows nothing about Yjs or about the network: only the ports.
//
// Two planes, and they never touch (see the spec's §00 figure):
//   AUTHORITY  requests gossip, arbiters commit, epochs carry the decisions
//   CONTENT    peers exchange directly, always, even with no arbiter online
import { OwnIdentity, verify, type PeerIdentity } from '../core/identity'
import {
  encrypt, decrypt, seal, encodeEnvelope, decodeEnvelope, signedRegion, resourceId, concat, randomBytes,
} from '../core/envelope'
import { Keyring, keyCommitment } from '../core/keyring'
import {
  AclChain, arbiterSet, resolveAccess, hasRemoval, signEpoch, epochId, applyOp, type Epoch,
} from '../core/acl-chain'
import { Access, signAclOp, verifyAclOp, type AclChange, type AclOp } from '../core/acl-ops'
import type { ICrdt } from '../ports/crdt'
import type { ITransport } from '../ports/transport'
import type { IBroadcast } from '../ports/broadcast'
import { FloodBroadcast } from '../adapters/flood-broadcast'
import { PeerStore, PinnedKeyChangedError } from '../ports/peer-store'
import type { IStorage } from '../ports/storage'
import { saveAll } from './persistence'
import {
  MsgType, frame, unframe, RejectReason,
  encodeHello, decodeHello, encodeKey, decodeKey, encodeSyncReq, decodeSyncReq,
  encodeAclRequest, decodeAclRequest, encodeEpochPush, decodeEpochPush,
  encodeChainReq, decodeChainReq, encodeChainResp, decodeChainResp,
  encodeReject, decodeReject, encodeKeyRequest, decodeKeyRequest,
} from './messages'

export interface SessionOpts {
  identity: OwnIdentity
  crdt: ICrdt
  keyring: Keyring
  /**
   * The vault's epoch chain — the ACL journal and the key commitments in one
   * structure (D31). Shared BY REFERENCE across every Session of a vault, the
   * way the Keyring already is: authority is vault-scoped, channels are not.
   *
   * This replaces the old `isAuthorized` boolean, which answered "now" instead
   * of "at the causal position of the op" — and therefore made two peers who
   * learned of a revocation ten minutes apart diverge for good.
   */
  chain: AclChain
  transport: ITransport
  /** How live messages reach peers we are not connected to. Defaults to plain
   *  flooding; inject another strategy without touching the Session. */
  broadcast?: IBroadcast
  peers: PeerStore
  resource: string
  /** Optional persistence port. The app decides at-rest protection (ADR-0011). */
  storage?: IStorage
  /** Raised when a PINNED peer presents a different key — the protocol's only
   *  alarm. Everything else stays a silent drop (no-error-message philosophy),
   *  but this one used to die in the generic per-peer catch below, so the one
   *  place the code shouted was the one place nobody heard. The session still
   *  drops the frame; this callback only makes the event observable.
   *
   *  D43 — an unprovable suspicion stops HERE. It never becomes a report to the
   *  arbiters: a changed pinned key proves nothing (a transport id is bound to
   *  no identity), and routing suspicions would open a false-accusation flood. */
  onSecurityAlert?: (alert: { kind: 'pinned-key-changed'; peer: string }) => void
}

export class Session {
  private readonly id: OwnIdentity
  private readonly crdt: ICrdt
  private readonly keyring: Keyring
  private readonly chain: AclChain
  private readonly transport: ITransport
  private readonly gossip: IBroadcast
  private readonly peers: PeerStore
  private readonly resource: string
  private readonly resourceId: Uint8Array
  private readonly storage?: IStorage
  private readonly onSecurityAlert?: SessionOpts['onSecurityAlert']
  private readonly idByPeer = new Map<string, PeerIdentity>()
  private readonly cleanups: (() => void)[] = []
  private readonly rand = () => randomBytes(32)

  /** Only the Session whose channel IS the vault handles chain traffic — the
   *  others would process every epoch once per open document. */
  private readonly isVaultRoot: boolean

  /** D38 — a registry of what we have already signed. An arbiter never signs two
   *  DIFFERENT candidates at the same (height, round): that single rule is what
   *  makes forking require a corrupted majority rather than one bad arbiter,
   *  because any two quorums of an odd set necessarily intersect. */
  private readonly signedAt = new Map<string, string>()

  constructor(o: SessionOpts) {
    this.id = o.identity
    this.crdt = o.crdt
    this.keyring = o.keyring
    this.chain = o.chain
    this.transport = o.transport
    this.gossip = o.broadcast ?? new FloodBroadcast(o.transport)
    this.peers = o.peers
    this.resource = o.resource
    this.resourceId = resourceId(o.resource)
    this.storage = o.storage
    this.onSecurityAlert = o.onSecurityAlert
    this.isVaultRoot = eqBytes(this.resourceId, o.chain.vaultId)

    this.cleanups.push(this.crdt.onLocalUpdate((u) => this.publishOp(u)))
    this.cleanups.push(this.transport.onMessage((from, b) => this.onMessage(from, b)))
    this.cleanups.push(this.transport.onPeerUp((peer) => this.onPeerUp(peer)))
  }

  dispose(): void {
    for (const c of this.cleanups) c()
  }

  async persist(): Promise<void> {
    if (!this.storage) return
    await saveAll(this.storage, {
      identity: this.id, keyring: this.keyring, peers: this.peers, chain: this.chain,
      channels: [{ resourceId: this.resourceId, crdt: this.crdt }],
    })
  }

  // ── Authorisation ─────────────────────────────────────────────────────────

  /**
   * The level a key holds AT A POSITION in the chain (D40). `at` omitted means
   * the head. This is the whole authorization surface — there is no other.
   */
  private access(signPub: Uint8Array, at?: Uint8Array): Access | undefined {
    const state = at ? this.chain.stateAt(at) : this.chain.state()
    return state && resolveAccess(state, signPub)
  }

  private can(signPub: Uint8Array, level: Access, at?: Uint8Array): boolean {
    const a = this.access(signPub, at)
    return a !== undefined && a >= level
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Ask for a change of rights (D22). Any node MAY emit; only arbiters commit.
   * One op carries several changes (D35): the batching comes from the author's
   * intent, never from a time window — so a revocation takes effect as soon as
   * the arbiter orders it, not at the end of some interval.
   */
  requestAclChange(group: Uint8Array, changes: AclChange[]): void {
    const op = signAclOp(
      this.chain.vaultId,
      { group, changes, issuer: this.id.signPub },
      (m) => this.id.sign(m),
    )
    // Gossip it regardless: a request has no effect until it is in an epoch, so
    // circulating it costs nothing, and every peer that can check it relays it —
    // which is how it reaches an arbiter we are not adjacent to.
    this.gossip.spread(frame(MsgType.AclRequest, encodeAclRequest(op)))
    this.mint([op])
  }

  /** Are WE the arbiter? Computed from the ACL, never from presence (D28). */
  isArbiter(): boolean {
    return arbiterSet(this.chain.state()).some((a) => eqBytes(a, this.id.signPub))
  }

  /**
   * Commit a batch. D42 — at k=1 the arbiter signs alone and there is no
   * consensus algorithm at all; the multi-arbiter case (C7) adds the agreement
   * without changing this shape.
   */
  mint(ops: AclOp[]): boolean {
    if (!this.isVaultRoot || !this.isArbiter()) return false

    // D39 — the arbiter checks the INITIATOR's signature before embedding an op,
    // exactly as every other peer will on receipt. Skipping it corrupts only the
    // arbiter: peers reject the epoch at validateEpoch, but the arbiter has
    // already folded the forged op into its own state and goes on minting from
    // there. Ordering is the arbiter's job; vouching for content is not.
    ops = ops.filter((op) => verifyAclOp(this.chain.vaultId, op))

    // …and only commits ops that would actually APPLY. Without this dry run, a
    // correctly-signed but unauthorised op still produced an epoch — one with no
    // effect on the state, but a real link in the chain. Which means ANY peer,
    // member or not, could force one epoch per request: unbounded amplification
    // from an attacker who holds nothing but a keypair.
    let probe = this.chain.state()
    const effective: AclOp[] = []
    for (const op of ops) {
      const next = applyOp(probe, op)
      if (!next) continue
      probe = next
      effective.push(op)
    }
    if (effective.length === 0) return false
    ops = effective

    const height = this.chain.height() + 1
    const round = 0
    const slot = `${height}/${round}`

    // D11 — key material if and only if the batch removes someone.
    const rotates = hasRemoval(ops)
    const vaultKey = rotates ? this.rand() : undefined
    const draft = {
      prev: this.chain.head(), height, round, ops,
      keyCommit: vaultKey ? keyCommitment(vaultKey) : undefined,
    }
    const id = epochId(draft)

    // D38 — refuse to sign a second, different candidate at this slot.
    const already = this.signedAt.get(slot)
    if (already && already !== hex(id)) return false
    this.signedAt.set(slot, hex(id))

    const epoch = signEpoch(this.chain.vaultId, draft, this.id.signPub, (m) => this.id.sign(m))
    this.chain.appendLocal(epoch)
    if (vaultKey) this.keyring.adopt(id, vaultKey, draft.keyCommit)

    this.gossip.spread(frame(MsgType.EpochPush, encodeEpochPush(epoch)))
    // Hand the current key to everyone the NEW state authorises. Unconditional
    // on purpose: an epoch that ADDS someone carries no key material (D11 — no
    // removal), so keying the newcomer cannot be tied to a rotation happening.
    // grantPeer re-checks the ACL itself, so this is a no-op for anyone else.
    for (const p of this.transport.peers()) this.grantPeer(p)
    return true
  }

  /**
   * Seal the current vault key to a connected, identified peer.
   *
   * D12 — this is a REPAIR, not a grant: it hands a key to someone the ACL
   * already authorises, so it creates no right and any key-holder may do it.
   * That is what keeps the network self-healing with no administrator online.
   */
  grantPeer(peer: string, keyEpochId?: Uint8Array): void {
    const identity = this.idByPeer.get(peer)
    if (!identity) return
    if (!this.can(identity.signPub, Access.Read)) return

    const keyEpoch = keyEpochId ?? this.chain.keyEpochAt(this.chain.head())
    if (!keyEpoch) return
    const vaultKey = this.keyring.vaultKey(keyEpoch)
    if (!vaultKey) return

    const sealedVaultKey = seal(identity.boxPub, vaultKey)
    const region = this.keyGrantRegion(keyEpoch, identity.signPub, sealedVaultKey)
    this.transport.send(peer, frame(MsgType.Key, encodeKey({
      resource: this.resource, keyEpochId: keyEpoch, sealedVaultKey,
      grantorSignPub: this.id.signPub, recipientSignPub: identity.signPub,
      sig: this.id.sign(region),
    })))
  }

  /** vault ‖ keyEpoch ‖ recipient ‖ sealed — a captured KEY replays nowhere. */
  private keyGrantRegion(keyEpochId: Uint8Array, recipient: Uint8Array, sealed: Uint8Array): Uint8Array {
    return concat(this.resourceId, keyEpochId, recipient, sealed)
  }

  // ── outbound ──────────────────────────────────────────────────────────────

  private onPeerUp(peer: string): void {
    this.transport.send(peer, frame(MsgType.Hello, this.hello()))
  }

  private hello(): Uint8Array {
    const nonce = randomBytes(24)
    const sig = this.id.sign(this.helloTranscript(this.id.signPub, this.id.boxPub, nonce))
    return encodeHello({ signPub: this.id.signPub, boxPub: this.id.boxPub, nonce, sig })
  }

  private helloTranscript(signPub: Uint8Array, boxPub: Uint8Array, nonce: Uint8Array): Uint8Array {
    return concat(new Uint8Array([Session.PROTO]), signPub, boxPub, this.resourceId, nonce)
  }

  private publishOp(update: Uint8Array): void {
    const env = this.sealAt(update)
    if (env) this.gossip.spread(frame(MsgType.Op, env))
  }

  /** Seal under the key in force at the current position (D40). */
  private sealAt(update: Uint8Array): Uint8Array | undefined {
    const pos = this.chain.head()
    const keyEpoch = this.chain.keyEpochAt(pos)
    const key = keyEpoch && this.keyring.docKey(keyEpoch, this.resourceId)
    if (!key) return undefined
    const { nonce, ciphertext } = encrypt(key, update)
    const sig = this.id.sign(signedRegion(this.resourceId, pos, nonce, ciphertext))
    return encodeEnvelope({ resourceId: this.resourceId, epochId: pos, nonce, ciphertext, sig, signerPub: this.id.signPub })
  }

  private reject(peer: string, reason: RejectReason): void {
    // D14 — never to a non-member, and never a NotAuthorized reason: that is the
    // one motive that would leak membership. An unauthorized peer keeps getting
    // the silent drop it always got.
    const identity = this.idByPeer.get(peer)
    if (!identity || !this.can(identity.signPub, Access.Pull)) return
    this.transport.send(peer, frame(MsgType.Reject, encodeReject({
      resourceId: this.resourceId, reason, head: this.chain.head(),
    })))
  }

  // ── inbound ───────────────────────────────────────────────────────────────

  private static readonly MAX_MSG = 1 << 20 // 1 MiB
  private static readonly PROTO = 1

  private onMessage(from: string, bytes: Uint8Array): void {
    if (bytes.length < 1 || bytes.length > Session.MAX_MSG) return
    try {
      const { type, payload } = unframe(bytes)
      // Gossiped types: a copy we already relayed is dropped whole — not applied
      // twice, not spread again. That single check is what ends the flood.
      if (GOSSIPED.has(type) && this.gossip.seen(bytes)) return
      switch (type) {
        case MsgType.Hello: return this.onHello(from, payload)
        case MsgType.Op: return this.onOp(from, payload, bytes)
        case MsgType.Key: return this.onKey(payload)
        case MsgType.SyncReq: return this.onSyncReq(from, payload)
        // Catch-up is point to point and re-signed by whoever answers: never relayed.
        case MsgType.SyncResp: return this.onOp(from, payload)
        case MsgType.StatePush: return this.onOp(from, payload)
        case MsgType.AclRequest: return this.onAclRequest(from, payload, bytes)
        case MsgType.EpochPush: return this.onEpochPush(from, payload, bytes)
        case MsgType.ChainReq: return this.onChainReq(from, payload)
        case MsgType.ChainResp: return this.onChainResp(from, payload)
        case MsgType.Reject: return this.onReject(from, payload)
        case MsgType.KeyRequest: return this.onKeyRequest(from, payload)
      }
    } catch (e) {
      // drop: bad frame from `from`, session stays alive. One exception is
      // SURFACED before dropping — a pinned key that changed is the protocol's
      // only alarm, and silently eating it defeats its purpose.
      if (e instanceof PinnedKeyChangedError) {
        this.onSecurityAlert?.({ kind: 'pinned-key-changed', peer: e.peerId })
      }
    }
  }

  private onHello(from: string, payload: Uint8Array): void {
    const h = decodeHello(payload)
    if (!verify(h.sig, this.helloTranscript(h.signPub, h.boxPub, h.nonce), h.signPub)) return
    const identity: PeerIdentity = { signPub: h.signPub, boxPub: h.boxPub }
    const firstTimeSeeingThisPeer = !this.idByPeer.has(from)
    this.peers.observe(from, identity) // TOFU
    this.idByPeer.set(from, identity)

    // D12 — anyone holding the key repairs anyone the ACL authorises.
    this.grantPeer(from)
    if (firstTimeSeeingThisPeer) this.transport.send(from, frame(MsgType.Hello, this.hello()))
    this.transport.send(from, frame(MsgType.SyncReq, encodeSyncReq({ resourceId: this.resourceId, stateVector: this.crdt.stateVector() })))
    // Catch the newcomer up on authority before anything else needs it.
    if (this.isVaultRoot) this.transport.send(from, frame(MsgType.ChainReq, encodeChainReq(this.chain.head())))
  }

  /** `live` is the whole frame when it came as a gossiped Op: once checked, it
   *  is relayed byte for byte, so it keeps its author's signature hop after hop. */
  private onOp(from: string, payload: Uint8Array, live?: Uint8Array): void {
    const env = decodeEnvelope(payload)
    if (!eqBytes(env.resourceId, this.resourceId)) return
    if (!verify(env.sig, signedRegion(env.resourceId, env.epochId, env.nonce, env.ciphertext), env.signerPub)) return

    // The position must be one we know, otherwise we cannot say who was allowed
    // to write there. Telling the sender is safe and is how they catch up.
    const state = this.chain.stateAt(env.epochId)
    if (!state) return this.reject(from, RejectReason.EpochUnknown)

    // D20/D40 — authorised AT THE POSITION, never "now". This is what makes two
    // peers who learn of a revocation at different moments still converge.
    const acc = resolveAccess(state, env.signerPub)
    if (acc === undefined || acc < Access.Write) return // silent (D14)

    // Signature and right at the position are all a relay needs: it never has to
    // decrypt, so a `pull` peer — a blind server — relays as well as a reader.
    // Only checked messages travel, so a flooder cannot make the network work
    // for it.
    if (live) this.gossip.spread(live, from)

    // No "epoch must be the current one" rule any more: authorisation at the
    // position already cuts a revoked writer off, and dropping it lets a `pull`
    // relay serve stored content again after a rotation.
    const keyEpoch = this.chain.keyEpochAt(env.epochId)
    const key = keyEpoch && this.keyring.docKey(keyEpoch, this.resourceId)
    if (!key) return this.reject(from, RejectReason.Undecryptable)

    let update: Uint8Array
    try {
      update = decrypt(key, env.nonce, env.ciphertext)
    } catch {
      return
    }
    this.crdt.applyRemote(update)
  }

  private onKey(payload: Uint8Array): void {
    const k = decodeKey(payload)
    if (k.resource !== this.resource) return
    if (!eqBytes(k.recipientSignPub, this.id.signPub)) return
    if (!this.peers.knowsSigner(k.grantorSignPub)) return
    // A regrant is a repair, but the repairer must at least be a member itself.
    if (!this.can(k.grantorSignPub, Access.Read)) return
    const region = this.keyGrantRegion(k.keyEpochId, k.recipientSignPub, k.sealedVaultKey)
    if (!verify(k.sig, region, k.grantorSignPub)) return

    const vaultKey = this.id.unseal(k.sealedVaultKey)
    // The chain committed to this key's hash: a mismatch is refused outright.
    // Nothing to reconcile, only something to reject.
    this.keyring.adopt(k.keyEpochId, vaultKey, this.chain.keyCommitOf(k.keyEpochId))

    // Encrypt-at-send: now keyed, push our state and re-request theirs.
    const snapshot = this.sealAt(this.crdt.snapshot())
    if (!snapshot) return
    for (const peer of this.transport.peers()) {
      this.transport.send(peer, frame(MsgType.StatePush, snapshot))
      this.transport.send(peer, frame(MsgType.SyncReq, encodeSyncReq({ resourceId: this.resourceId, stateVector: this.crdt.stateVector() })))
    }
  }

  private onSyncReq(from: string, payload: Uint8Array): void {
    const { resourceId: rid, stateVector } = decodeSyncReq(payload)
    if (!eqBytes(rid, this.resourceId)) return
    const identity = this.idByPeer.get(from)
    // `pull` is enough to be served ciphertext — that is the whole point of the
    // level existing separately from `read`.
    if (!identity || !this.can(identity.signPub, Access.Pull)) return
    const diff = this.sealAt(this.crdt.diffSince(stateVector))
    if (diff) this.transport.send(from, frame(MsgType.SyncResp, diff))
  }

  // ── authority plane ───────────────────────────────────────────────────────

  private onAclRequest(from: string, payload: Uint8Array, bytes: Uint8Array): void {
    if (!this.isVaultRoot) return
    const op = decodeAclRequest(payload)
    // Relay only what would apply on our head: correctly signed AND issued by
    // someone allowed to make that change. A request nobody may grant dies at
    // the first hop instead of costing every peer a verification.
    if (!verifyAclOp(this.chain.vaultId, op) || !applyOp(this.chain.state(), op)) return
    this.gossip.spread(bytes, from)
    // Signature and authorisation of the INITIATOR are checked again by the fold
    // and by validateEpoch (D39) — an arbiter cannot smuggle in an op nobody
    // asked for, because every peer re-checks it on receipt of the epoch.
    this.mint([op])
  }

  private onEpochPush(from: string, payload: Uint8Array, bytes: Uint8Array): void {
    if (!this.isVaultRoot) return
    const epoch = decodeEpochPush(payload)
    if (this.chain.has(epochId(epoch))) return
    try {
      this.chain.adoptEpoch(epoch)
    } catch {
      // Not applicable on our head: we are behind, or it is invalid. Asking
      // costs one message and tells the two apart. Not relayed: we could not
      // check it, and the peers behind us will ask the same way.
      this.transport.send(from, frame(MsgType.ChainReq, encodeChainReq(this.chain.head())))
      return
    }
    // Adopted means validated against our chain: certificate and every
    // initiator. Only now does it travel on.
    this.gossip.spread(bytes, from)
    this.maybeRequestKey(from)
  }

  /**
   * Learning about authority can make us a member, or rotate the key out from
   * under us. Either way: entitled to read and holding no key for the current
   * position means asking for it (D12 — any key-holder may answer, so this works
   * with no administrator online).
   *
   * Called after EVERY way the chain can advance. A peer that syncs the chain
   * before it is granted anything would otherwise sit keyless forever: the grant
   * it was sent arrived before it had the chain to validate the grantor against.
   */
  private maybeRequestKey(from: string): void {
    const keyEpoch = this.chain.keyEpochAt(this.chain.head())
    if (!keyEpoch || this.keyring.has(keyEpoch)) return
    if (!this.can(this.id.signPub, Access.Read)) return
    this.transport.send(from, frame(MsgType.KeyRequest, encodeKeyRequest({
      resource: this.resource, keyEpochId: keyEpoch,
    })))
  }

  private onChainReq(from: string, payload: Uint8Array): void {
    if (!this.isVaultRoot) return
    // D8 — the chain is signed and self-validating, so serving it to anyone is
    // safe: a non-member can store and relay it without being able to forge it.
    const epochs = this.chain.since(decodeChainReq(payload))
    if (epochs.length) this.transport.send(from, frame(MsgType.ChainResp, encodeChainResp(epochs)))
  }

  private onChainResp(from: string, payload: Uint8Array): void {
    if (!this.isVaultRoot) return
    for (const e of decodeChainResp(payload)) {
      if (this.chain.has(epochId(e))) continue
      try {
        this.chain.adoptEpoch(e)
      } catch {
        break // the rest cannot chain either
      }
    }
    this.maybeRequestKey(from)
  }

  private onReject(from: string, payload: Uint8Array): void {
    const m = decodeReject(payload)
    if (!eqBytes(m.resourceId, this.resourceId)) return
    if (m.reason === RejectReason.EpochUnknown) {
      this.transport.send(from, frame(MsgType.ChainReq, encodeChainReq(this.chain.head())))
    } else {
      const keyEpoch = this.chain.keyEpochAt(this.chain.head())
      if (keyEpoch) {
        this.transport.send(from, frame(MsgType.KeyRequest, encodeKeyRequest({ resource: this.resource, keyEpochId: keyEpoch })))
      }
    }
  }

  private onKeyRequest(from: string, payload: Uint8Array): void {
    const m = decodeKeyRequest(payload)
    if (m.resource !== this.resource) return
    this.grantPeer(from, m.keyEpochId) // grantPeer re-checks the ACL itself
  }
}

/** Live messages that travel beyond the neighbours, relayed byte for byte. Key,
 *  Hello and the catch-up messages stay point to point. */
const GOSSIPED = new Set<MsgType>([MsgType.Op, MsgType.AclRequest, MsgType.EpochPush])

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function hex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

export type { Epoch }
