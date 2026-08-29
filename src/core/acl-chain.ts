// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// The epoch chain: ONE structure that carries both the ACL journal and the key
// material (D31). There is no separate op log, no DAG and no distinct finality
// checkpoint — the consensus linearises, so a chain is enough (D7).
//
// An op that is in no epoch has NO EFFECT. It circulates, that is all. The
// pending/committed distinction is structural rather than a status to manage.
//
// Epoch N validates against the arbiter set defined by epoch N−1, and so on down
// to the root — so nobody can retroactively invalidate history by changing who
// the arbiters are.
//
// See docs/Architecture/edgesync-acl-arbitrage-spec.md.
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { concat } from './envelope'
import { toHex } from './codec'
import {
  Access, ROOT_GROUP, principalId, decodeAclOp, encodeAclOp, verifyAclOp,
  type AclOp, type Principal,
} from './acl-ops'

const PUB = 32
const SIG = 64
const ID = 32

/** Domain separator (D31): an epoch signature is only ever an epoch signature. */
const EPOCH_TAG = new TextEncoder().encode('edgesync-epoch-v1')

export const GENESIS_PREV = new Uint8Array(ID)

export interface Epoch {
  /** epochId of the predecessor; 32 zero bytes at the root. */
  prev: Uint8Array
  height: number
  /** D38 — present from the start, unused at k=1. A round lets a stalled height
   *  be retried; without it two concurrent proposers can split the signatures
   *  and wedge the chain at that height forever. */
  round: number
  ops: AclOp[]
  /**
   * D11 — present IF AND ONLY IF the batch contains a `remove`. Rotating for
   * anything else is waste, and an unjustified rotation must be detectable.
   *
   * This is a COMMITMENT — sha256(K_vault) — never the key itself. The chain is
   * public (Q2: the ACL is in clear, the only thing that breaks the "you need
   * the key to validate the key" circularity), so a key travelling in it would
   * be a key handed to everyone. The key itself moves sealed, per recipient, in
   * a KEY message; the commitment is what lets the recipient verify that what
   * they were handed is what the chain committed to.
   */
  keyCommit?: Uint8Array
  /** D31 — the certificate. */
  sigs: { signer: Uint8Array; sig: Uint8Array }[]
}

// ── Encoding ────────────────────────────────────────────────────────────────
//   body  [prev:32][height:u32][round:u32][hasKey:1]([keyCommit:32])[opCount:u32][ops…]
//   wire  [body][sigCount:u32]([signer:32][sig:64])*

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

/** The bytes an epochId is taken over: everything except the signatures. */
export function epochBody(e: Omit<Epoch, 'sigs'>): Uint8Array {
  const head = concat(
    e.prev, u32(e.height), u32(e.round),
    e.keyCommit ? concat(new Uint8Array([1]), e.keyCommit) : new Uint8Array([0]),
    u32(e.ops.length),
  )
  return concat(head, ...e.ops.map(encodeAclOp))
}

export function epochId(e: Omit<Epoch, 'sigs'>): Uint8Array {
  return sha256(epochBody(e))
}

export function encodeEpoch(e: Epoch): Uint8Array {
  const sigs = e.sigs.map((s) => concat(s.signer, s.sig))
  return concat(epochBody(e), u32(e.sigs.length), ...sigs)
}

export function decodeEpoch(b: Uint8Array): Epoch {
  let o = 0
  const take = (n: number): Uint8Array => {
    if (o + n > b.length) throw new Error('epoch truncated')
    const out = b.subarray(o, o + n)
    o += n
    return out
  }
  const readU32 = (): number => {
    const v = take(4)
    return new DataView(v.buffer, v.byteOffset, 4).getUint32(0, false)
  }

  const prev = take(ID)
  const height = readU32()
  const round = readU32()
  const keyCommit = take(1)[0] === 1 ? take(32) : undefined
  const opCount = readU32()
  const ops: AclOp[] = []
  for (let i = 0; i < opCount; i++) {
    const { op, read } = decodeAclOp(b.subarray(o))
    ops.push(op)
    o += read
  }
  const sigCount = readU32()
  const sigs: Epoch['sigs'] = []
  for (let i = 0; i < sigCount; i++) sigs.push({ signer: take(PUB), sig: take(SIG) })
  if (o !== b.length) throw new Error('epoch: trailing bytes')
  return { prev, height, round, ops, keyCommit, sigs }
}

// ── Signing (D31) ───────────────────────────────────────────────────────────

/** tag ‖ vaultId ‖ epochId — the prefix and the vaultId forbid any replay. */
export function epochSignRegion(vaultId: Uint8Array, id: Uint8Array): Uint8Array {
  return concat(EPOCH_TAG, vaultId, id)
}

export function signEpoch(
  vaultId: Uint8Array,
  draft: Omit<Epoch, 'sigs'>,
  signer: Uint8Array,
  sign: (msg: Uint8Array) => Uint8Array,
): Epoch {
  return { ...draft, sigs: [{ signer, sig: sign(epochSignRegion(vaultId, epochId(draft))) }] }
}

// ── State ───────────────────────────────────────────────────────────────────

export interface GroupState {
  /** principalId → level. */
  members: Map<string, Access>
  /** principalIds declared as arbiters (D23: they are admins in v1). */
  arbiters: Set<string>
}

export interface AclState {
  /** hex(groupId) → its list. ROOT_GROUP is the vault itself. */
  groups: Map<string, GroupState>
}

export function emptyState(): AclState {
  return { groups: new Map() }
}

function cloneState(s: AclState): AclState {
  const groups = new Map<string, GroupState>()
  for (const [g, st] of s.groups) {
    groups.set(g, { members: new Map(st.members), arbiters: new Set(st.arbiters) })
  }
  return { groups }
}

function groupOf(s: AclState, groupId: Uint8Array): GroupState | undefined {
  return s.groups.get(toHex(groupId))
}

function ensureGroup(s: AclState, groupId: Uint8Array): GroupState {
  const k = toHex(groupId)
  let g = s.groups.get(k)
  if (!g) {
    g = { members: new Map(), arbiters: new Set() }
    s.groups.set(k, g)
  }
  return g
}

/**
 * Effective level of a key inside one group.
 *
 * `min` going DOWN (D4/D5 attenuation): a group holding `read` on the vault
 * cannot hand `manage` to its members — without this, nesting would be a
 * privilege escalation. `max` ACROSS paths: reachable twice, you keep the best.
 *
 * Pass 1 is flat, so this is ONE level of indirection, not a recursion. The
 * shape is the same one recursion will take.
 */
export function effectiveAccess(state: AclState, signPub: Uint8Array, groupId: Uint8Array): Access | undefined {
  const g = groupOf(state, groupId)
  if (!g) return undefined
  const me = principalId({ kind: 'key', signPub })
  let best = g.members.get(me)

  for (const [pid, viaAccess] of g.members) {
    if (!pid.startsWith('g:')) continue
    const inner = state.groups.get(pid.slice(2))
    const mine = inner?.members.get(me)
    if (mine === undefined) continue
    const through = Math.min(viaAccess, mine) as Access
    if (best === undefined || through > best) best = through
  }
  return best
}

/** The level a key holds on the vault. Replaces the old isAuthorized boolean. */
export function resolveAccess(state: AclState, signPub: Uint8Array): Access | undefined {
  return effectiveAccess(state, signPub, ROOT_GROUP)
}

/**
 * An owner is a member of a GROUP that holds `manage` on the vault — the group
 * the root delegates to (D19). Owners are the only ones who may mint a `manage`
 * (D20) and the only ones who may use the emergency path (D26).
 */
export function isOwner(state: AclState, signPub: Uint8Array): boolean {
  const root = groupOf(state, ROOT_GROUP)
  if (!root) return false
  const me = principalId({ kind: 'key', signPub })
  for (const [pid, acc] of root.members) {
    if (!pid.startsWith('g:') || acc < Access.Manage) continue
    if (state.groups.get(pid.slice(2))?.members.get(me) === Access.Manage) return true
  }
  return false
}

function managersOf(state: AclState, groupId: Uint8Array): string[] {
  const g = groupOf(state, groupId)
  if (!g) return []
  return [...g.members.entries()].filter(([, a]) => a >= Access.Manage).map(([p]) => p)
}

/**
 * The arbiter set (D37). Always at least one; k is always ODD — with an even k a
 * 50/50 partition freezes both halves.
 *
 * Declared candidates first (D23). Failing that, the most senior, computed from
 * the ACL and NEVER from presence (D28): presence is precisely what differs on
 * either side of a partition, so drawing on it would let both halves reach a
 * quorum and advance — the divergence arbiters exist to prevent.
 */
export function arbiterSet(state: AclState): Uint8Array[] {
  const root = groupOf(state, ROOT_GROUP)
  if (!root) return []

  const rank = (pid: string): [number, number, string] => {
    const hex = pid.slice(2)
    const signPub = fromHex(hex)
    return [isOwner(state, signPub) ? 0 : 1, -(resolveAccess(state, signPub) ?? 0), hex]
  }
  const byRank = (a: string, b: string) => {
    const [ao, aa, ah] = rank(a)
    const [bo, ba, bh] = rank(b)
    return ao - bo || aa - ba || ah.localeCompare(bh)
  }

  let pool = [...root.arbiters].filter((p) => p.startsWith('k:'))
  if (pool.length === 0) {
    // No declaration: fall back to the managers, most senior first.
    const seen = new Set<string>()
    for (const [gid, g] of state.groups) {
      void gid
      for (const [pid, acc] of g.members) {
        if (pid.startsWith('k:') && acc >= Access.Manage) seen.add(pid)
      }
    }
    pool = [...seen].filter((p) => (resolveAccess(state, fromHex(p.slice(2))) ?? -1) >= Access.Manage)
  }
  pool.sort(byRank)

  // k must be odd: drop the least senior rather than sit on an even set.
  if (pool.length % 2 === 0 && pool.length > 0) pool = pool.slice(0, pool.length - 1)
  return pool.map((p) => fromHex(p.slice(2)))
}

export function quorumSize(k: number): number {
  return Math.floor(k / 2) + 1
}

// ── Applying ops ────────────────────────────────────────────────────────────

/** Does this op batch contain a member removal? Drives D11. */
export function hasRemoval(ops: AclOp[]): boolean {
  return ops.some((o) => o.changes.some((c) => c.t === 'remove'))
}

/**
 * Apply one op, all-or-nothing. Returns undefined when the op is refused.
 *
 * All-or-nothing rather than change-by-change because the total order removes
 * concurrency: an op is a single deliberate intent, so "remove A and B, which
 * would empty the group" is a request that is simply invalid — not something to
 * partially apply. (D17's canonical re-admission was designed for the concurrent
 * case, which no longer exists.)
 */
export function applyOp(state: AclState, op: AclOp, bootstrap = false): AclState | undefined {
  // D20 — only admins edit the ACL. A read or a write never grants anything.
  //
  // Creating a group is the one case where the target list does not exist yet,
  // so there is nothing to be `manage` OF: authority then comes from the vault.
  // Any vault admin may create a group, and D17 below forces the creating op to
  // leave at least one manager inside it.
  if (!bootstrap) {
    const scope = groupOf(state, op.group) ? op.group : ROOT_GROUP
    const issuerAccess = effectiveAccess(state, op.issuer, scope)
    if (issuerAccess === undefined || issuerAccess < Access.Manage) return undefined
  }
  const owner = bootstrap || isOwner(state, op.issuer)
  const onRoot = eqBytes(op.group, ROOT_GROUP)

  const next = cloneState(state)
  const g = ensureGroup(next, op.group)

  for (const c of op.changes) {
    const pid = principalId(c.principal)
    if (c.t === 'set') {
      // D20 — a manage never mints another VAULT manage; only the owners group
      // can. Scoped to the root on purpose: naming a manager INSIDE a team is
      // ordinary group administration, not an escalation — the team's own level
      // still caps what its members get, by attenuation.
      if (c.access >= Access.Manage && onRoot && !owner) return undefined
      g.members.set(pid, c.access)
    } else if (c.t === 'remove') {
      g.members.delete(pid)
      g.arbiters.delete(pid)
    } else {
      // D23 — arbiter is a flag on an existing admin, not a new kind of
      // principal. Checked on EFFECTIVE access, so someone who is manage through
      // their owners group qualifies without being listed twice. Keys only in
      // v1: a group cannot hold the availability commitment a role like this is.
      if (c.principal.kind !== 'key') return undefined
      const acc = effectiveAccess(next, c.principal.signPub, op.group)
      if (acc === undefined || acc < Access.Manage) return undefined
      if (c.on) g.arbiters.add(pid)
      else g.arbiters.delete(pid)
    }
  }

  // D17 — a group can never be emptied of its managers. Checked AFTER the whole
  // batch: two removals that each leave one manager leave none applied together.
  if (managersOf(next, op.group).length === 0) return undefined
  return next
}

/** Replay a chain into its state. Pure: same epochs in, same state out. */
export function fold(epochs: Epoch[]): AclState {
  let state = emptyState()
  for (const e of epochs) {
    for (const op of e.ops) {
      // Height 0 bootstraps: there is no prior state to authorise against. This
      // is where the self-certifying vault id (C5) will attach — until then the
      // root is trusted on first use.
      const next = applyOp(state, op, e.height === 0)
      if (next) state = next
    }
  }
  return state
}

// ── Validation (D31) ────────────────────────────────────────────────────────

export interface ChainHead {
  id: Uint8Array
  height: number
  state: AclState
}

/**
 * The five-point check of D31, plus D11. Returns a reason string when invalid,
 * undefined when the epoch is acceptable.
 */
export function validateEpoch(vaultId: Uint8Array, e: Epoch, prev: ChainHead): string | undefined {
  if (!eqBytes(e.prev, prev.id)) return 'prev mismatch'
  if (e.height !== prev.height + 1) return 'height mismatch'

  // D11 — key material if and only if the batch removes someone. Height 0 is the
  // one exemption: a vault has to start with a key, and there is nobody to
  // remove yet.
  if (e.height > 0 && hasRemoval(e.ops) !== (e.keyCommit !== undefined)) {
    return 'key commitment does not match removals'
  }
  if (e.keyCommit && e.keyCommit.length !== 32) return 'key commitment size'

  // D39 — every peer checks the INITIATOR's signature, not just the certificate.
  for (const op of e.ops) if (!verifyAclOp(vaultId, op)) return 'op signature'

  // The certificate is checked against the arbiters in force at prev — never
  // today's set, or a reconfiguration would invalidate history retroactively.
  const arbiters = arbiterSet(prev.state)
  if (arbiters.length === 0) return 'no arbiter'
  const allowed = new Set(arbiters.map(toHex))
  const id = epochId(e)
  const region = epochSignRegion(vaultId, id)

  const seen = new Set<string>()
  for (const s of e.sigs) {
    const h = toHex(s.signer)
    if (!allowed.has(h) || seen.has(h)) continue // unknown or duplicate signer
    try {
      if (ed25519.verify(s.sig, region, s.signer)) seen.add(h)
    } catch {
      /* invalid signature: ignore this one */
    }
  }
  if (seen.size < quorumSize(arbiters.length)) return 'quorum not met'
  return undefined
}

// ── The chain ───────────────────────────────────────────────────────────────

export class AclChain {
  private readonly epochs: Epoch[] = []
  private readonly ids: Uint8Array[] = []
  /** states[i] is the state AFTER epochs[i] — kept incrementally, never refolded. */
  private readonly states: AclState[] = []

  constructor(readonly vaultId: Uint8Array) {}

  /**
   * Bootstrap: the founder writes epoch 0, granting itself `manage` through an
   * owners GROUP — never as an individual (D19). sk_vault being destroyed at
   * genesis (Q1) would otherwise freeze the founder in place for the life of the
   * vault; a group stays mutable, so succession is an ordinary membership change.
   */
  static genesis(
    vaultId: Uint8Array,
    founder: { signPub: Uint8Array; sign: (m: Uint8Array) => Uint8Array },
    ops: AclOp[],
    keyCommit: Uint8Array,
  ): AclChain {
    const chain = new AclChain(vaultId)
    const draft = { prev: GENESIS_PREV, height: 0, round: 0, ops, keyCommit }
    chain.push(signEpoch(vaultId, draft, founder.signPub, founder.sign))
    return chain
  }

  private push(e: Epoch): void {
    const id = epochId(e)
    const base = this.states.length ? this.states[this.states.length - 1] : emptyState()
    let state = base
    for (const op of e.ops) {
      const next = applyOp(state, op, e.height === 0)
      if (next) state = next
    }
    this.epochs.push(e)
    this.ids.push(id)
    this.states.push(state)
  }

  /** Validate then adopt. Throws with a reason — callers drop silently. */
  append(e: Epoch): void {
    const why = validateEpoch(this.vaultId, e, this.headRef())
    if (why) throw new Error(`epoch rejected: ${why}`)
    this.push(e)
  }

  /** Adopt an epoch built locally by the arbiter itself (already signed by it). */
  appendLocal(e: Epoch): void {
    this.push(e)
  }

  /**
   * Adopt an epoch received from a peer or from disk. Height 0 cannot be
   * certified — there is no prior arbiter set to certify it against — so the
   * root is trusted on first use. This is exactly where the self-certifying
   * vault id (C5) attaches: once `vaultId` IS a public key, the root op verifies
   * against the identifier itself and this exemption disappears.
   */
  adoptEpoch(e: Epoch): void {
    if (e.height === 0 && this.ids.length === 0) return this.appendLocal(e)
    this.append(e)
  }

  private headRef(): ChainHead {
    return { id: this.head(), height: this.height(), state: this.state() }
  }

  head(): Uint8Array {
    return this.ids.length ? this.ids[this.ids.length - 1] : GENESIS_PREV
  }

  height(): number {
    return this.ids.length - 1
  }

  state(): AclState {
    return this.states.length ? this.states[this.states.length - 1] : emptyState()
  }

  /** The state as of a POSITION — this is what authorises an op (D40). */
  stateAt(id: Uint8Array): AclState | undefined {
    const i = this.indexOf(id)
    return i < 0 ? undefined : this.states[i]
  }

  /**
   * D40 — the epochId in an envelope is a POSITION, not a key. Most epochs carry
   * no key material (D11), so decryption walks back from that position to the
   * last epoch that did.
   */
  keyEpochAt(id: Uint8Array): Uint8Array | undefined {
    for (let i = this.indexOf(id); i >= 0; i--) {
      if (this.epochs[i].keyCommit) return this.ids[i]
    }
    return undefined
  }

  keyCommitOf(id: Uint8Array): Uint8Array | undefined {
    const i = this.indexOf(id)
    return i < 0 ? undefined : this.epochs[i].keyCommit
  }

  /** Everything after `id`. Linear interval — that is the whole sync protocol. */
  since(id: Uint8Array): Epoch[] {
    const i = this.indexOf(id)
    return i < 0 ? this.epochs.slice() : this.epochs.slice(i + 1)
  }

  all(): Epoch[] {
    return this.epochs.slice()
  }

  has(id: Uint8Array): boolean {
    return this.indexOf(id) >= 0
  }

  private indexOf(id: Uint8Array): number {
    const h = toHex(id)
    for (let i = this.ids.length - 1; i >= 0; i--) if (toHex(this.ids[i]) === h) return i
    return -1
  }
}

// ── local helpers ───────────────────────────────────────────────────────────

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  return out
}

export type { Principal }
