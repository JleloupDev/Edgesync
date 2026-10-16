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
  Access, ROOT_GROUP, principalId, decodeAclOp, encodeAclOp, verifyAclOp, aclOpId, touchedBy,
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
   * D11 — present IF AND ONLY IF the batch takes the right to READ away from
   * someone: a removal, but also a demotion below `read`, or a group losing its
   * read. Rotating for anything else is waste, and an unjustified rotation must
   * be detectable.
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

/** Does this op batch contain a member removal? Kept for callers that only need
 *  the syntactic question; the rotation rule is `losesRead`. */
export function hasRemoval(ops: AclOp[]): boolean {
  return ops.some((o) => o.changes.some((c) => c.t === 'remove'))
}

/**
 * D11 — did any key that could READ before stop being able to? That, and only
 * that, forces a key rotation. Judged on the RESOLVED state, not on the verbs:
 * a demotion from read to pull, or a group dropped below read, takes the key
 * away just as surely as a removal — and used to leave it in place.
 */
export function losesRead(before: AclState, after: AclState): boolean {
  for (const g of before.groups.values()) {
    for (const pid of g.members.keys()) {
      if (!pid.startsWith('k:')) continue
      const signPub = fromHex(pid.slice(2))
      const was = resolveAccess(before, signPub)
      if (was === undefined || was < Access.Read) continue
      const now = resolveAccess(after, signPub)
      if (now === undefined || now < Access.Read) return true
    }
  }
  return false
}

// ── Freshness: base, history, backlink (ADR-0019) ──────────────────────────
//
// An op is signed outside time, so on its own it is valid forever: replaying an
// old admission after a revocation used to put the revoked member back. Three
// rules anchor it, all judged on the chain alone so every peer reaches the same
// verdict:
//
//   base      the head the initiator saw. No key rotation may lie between it and
//             now: a rotation means someone lost the right to read, and every
//             decision taken before it has to be taken again, knowingly.
//   history   the ids of the ops applied since the last rotation. The same op
//             never applies twice.
//   backlink  `prev` = the initiator's previous op. An initiator's ops apply in
//             the order it signed them, whatever order the network delivers.
//
// An op that fails them is INERT, exactly like an unauthorised one: it can sit
// in an epoch and do nothing. So even a faulty arbiter cannot push it through.

/** What one applied op left behind, for replay checks and conflict detection. */
export interface OpRecord {
  issuer: string
  /** Height of the epoch that applied it. */
  height: number
  touched: Set<string>
}

/** Everything applied since the last key rotation. Reset by every rotation. */
export interface KeyEpochHistory {
  /** Height of the epoch that opened this key epoch. */
  since: number
  /** hex(opId) → record. */
  ops: Map<string, OpRecord>
  /** hex(issuer) → hex(opId) of its latest applied op. */
  latest: Map<string, string>
}

export function emptyHistory(since = 0): KeyEpochHistory {
  return { since, ops: new Map(), latest: new Map() }
}

function cloneHistory(h: KeyEpochHistory): KeyEpochHistory {
  return { since: h.since, ops: new Map(h.ops), latest: new Map(h.latest) }
}

/**
 * The verdict on one op, at one point of the chain:
 *   ok            applies
 *   wait          its predecessor (backlink) has not applied yet — hold it
 *   stale         no base, unknown base, or a key rotation since its base
 *   replay        already applied in this key epoch
 *   fork          two ops behind the same predecessor — or two that both claim
 *                 to be the initiator's first since the rotation: a signed
 *                 equivocation, and the second one never applies
 *   unauthorised  the initiator may not make this change
 */
export type Admission = 'ok' | 'wait' | 'stale' | 'replay' | 'fork' | 'unauthorised'

export interface ChainHead {
  id: Uint8Array
  height: number
  state: AclState
  /** Omitted: nothing applied yet, as at the genesis. */
  history?: KeyEpochHistory
  /** Height of an epoch by id, -1 when unknown. Omitted: no base resolves. */
  heightOf?: (id: Uint8Array) => number
}

export function admit(head: ChainHead, op: AclOp): Admission {
  const history = head.history ?? emptyHistory()
  if (!op.base) return 'stale'
  const baseHeight = head.heightOf ? head.heightOf(op.base) : -1
  if (baseHeight < 0 || baseHeight < history.since) return 'stale'
  if (history.ops.has(toHex(aclOpId(op)))) return 'replay'

  const latest = history.latest.get(toHex(op.issuer))
  if (op.prev) {
    const prev = toHex(op.prev)
    if (latest !== prev) return history.ops.has(prev) ? 'fork' : 'wait'
  } else if (latest !== undefined) {
    return 'fork'
  }
  return applyOp(head.state, op) ? 'ok' : 'unauthorised'
}

/** Record an op that just applied. */
function remember(history: KeyEpochHistory, op: AclOp, height: number): void {
  const id = toHex(aclOpId(op))
  const issuer = toHex(op.issuer)
  history.ops.set(id, { issuer, height, touched: touchedBy(op) })
  history.latest.set(issuer, id)
}

/** The result of applying one epoch on top of a head. */
interface Applied {
  state: AclState
  history: KeyEpochHistory
  /** The ops that took effect, in order. */
  effective: AclOp[]
  rotates: boolean
}

function applyEpoch(head: ChainHead, e: Omit<Epoch, 'sigs'>): Applied {
  if (e.height === 0) {
    // Bootstrap: no prior state to authorise against, no base to anchor on.
    let state = head.state
    for (const op of e.ops) state = applyOp(state, op, true) ?? state
    return { state, history: emptyHistory(0), effective: e.ops.slice(), rotates: false }
  }
  let state = head.state
  const history = cloneHistory(head.history ?? emptyHistory())
  const effective: AclOp[] = []
  for (const op of e.ops) {
    if (admit({ ...head, state, history }, op) !== 'ok') continue
    state = applyOp(state, op)!
    remember(history, op, e.height)
    effective.push(op)
  }
  const rotates = losesRead(head.state, state)
  return { state, history: e.keyCommit ? emptyHistory(e.height) : history, effective, rotates }
}

/**
 * Committed decisions on the same members, by someone else, that the initiator
 * had not seen (applied after its base). Not a reason to refuse: two people
 * deciding at once is legitimate, and who is right is not ours to say (D21,
 * D34). But it is the one case where the order the arbiter picks silently
 * decides the outcome, so it deserves to be seen.
 */
export function conflictsOf(head: ChainHead, op: AclOp): string[] {
  const history = head.history ?? emptyHistory()
  const baseHeight = op.base && head.heightOf ? head.heightOf(op.base) : -1
  const mine = touchedBy(op)
  const issuer = toHex(op.issuer)
  const out: string[] = []
  for (const [id, r] of history.ops) {
    if (r.height <= baseHeight || r.issuer === issuer) continue
    for (const p of r.touched) if (mine.has(p)) { out.push(id); break }
  }
  return out
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
  // Same admission rules as the live chain (ADR-0019), so a replay from disk can
  // never reach a different state than the one the network agreed on. Height 0
  // bootstraps: there is no prior state to authorise against. This is where the
  // self-certifying vault id (C5) will attach — until then the root is trusted
  // on first use.
  const heights = new Map<string, number>()
  let head: ChainHead = { id: GENESIS_PREV, height: -1, state: emptyState(), history: emptyHistory() }
  for (const e of epochs) {
    const applied = applyEpoch({ ...head, heightOf: (id) => heights.get(toHex(id)) ?? -1 }, e)
    const id = epochId(e)
    heights.set(toHex(id), e.height)
    head = { id, height: e.height, state: applied.state, history: applied.history }
  }
  return head.state
}

// ── Validation (D31) ────────────────────────────────────────────────────────

/**
 * The five-point check of D31, plus D11. Returns a reason string when invalid,
 * undefined when the epoch is acceptable.
 */
export function validateEpoch(vaultId: Uint8Array, e: Epoch, prev: ChainHead): string | undefined {
  return checkEpoch(vaultId, e, prev).why
}

function checkEpoch(vaultId: Uint8Array, e: Epoch, prev: ChainHead): { why?: string; applied?: Applied } {
  if (!eqBytes(e.prev, prev.id)) return { why: 'prev mismatch' }
  if (e.height !== prev.height + 1) return { why: 'height mismatch' }

  // D39 — every peer checks the INITIATOR's signature, not just the certificate.
  for (const op of e.ops) if (!verifyAclOp(vaultId, op)) return { why: 'op signature' }

  // D11 — key material if and only if someone loses the right to read. Height 0
  // is the one exemption: a vault has to start with a key.
  const applied = applyEpoch(prev, e)
  if (e.height > 0 && applied.rotates !== (e.keyCommit !== undefined)) {
    return { why: 'key commitment does not match removals' }
  }
  if (e.keyCommit && e.keyCommit.length !== 32) return { why: 'key commitment size' }

  // The certificate is checked against the arbiters in force at prev — never
  // today's set, or a reconfiguration would invalidate history retroactively.
  const arbiters = arbiterSet(prev.state)
  if (arbiters.length === 0) return { why: 'no arbiter' }
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
  if (seen.size < quorumSize(arbiters.length)) return { why: 'quorum not met' }
  return { applied }
}

// ── The chain ───────────────────────────────────────────────────────────────

export class AclChain {
  private readonly epochs: Epoch[] = []
  private readonly ids: Uint8Array[] = []
  /** states[i] is the state AFTER epochs[i] — kept incrementally, never refolded. */
  private readonly states: AclState[] = []
  /** hex(epochId) → height: positions resolve in O(1). */
  private readonly heights = new Map<string, number>()
  /** What applied since the last key rotation, at the head (ADR-0019). Derived
   *  from the epochs alone, so every peer holds the same one. */
  private history: KeyEpochHistory = emptyHistory()

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
    chain.appendLocal(signEpoch(vaultId, draft, founder.signPub, founder.sign))
    return chain
  }

  private push(e: Epoch, applied: Applied): void {
    const id = epochId(e)
    this.epochs.push(e)
    this.ids.push(id)
    this.states.push(applied.state)
    this.heights.set(toHex(id), e.height)
    this.history = applied.history
  }

  /** Validate then adopt. Throws with a reason — callers drop silently. */
  append(e: Epoch): void {
    const { why, applied } = checkEpoch(this.vaultId, e, this.headRef())
    if (why || !applied) throw new Error(`epoch rejected: ${why}`)
    this.push(e, applied)
  }

  /**
   * Adopt an epoch built locally — by the arbiter that just signed it, or the
   * genesis. The certificate cannot be checked here (we ARE the signer), but the
   * ops still can, and must: an op whose initiator signature does not verify has
   * no business entering anyone's state, least of all the arbiter's.
   */
  appendLocal(e: Epoch): void {
    for (const op of e.ops) {
      if (!verifyAclOp(this.vaultId, op)) throw new Error('epoch rejected: op signature')
    }
    this.push(e, applyEpoch(this.headRef(), e))
  }

  // ── Freshness, for whoever builds or relays requests (ADR-0019) ───────────

  /** The verdict on one op if it were committed now. */
  admit(op: AclOp): Admission {
    return admit(this.headRef(), op)
  }

  /**
   * Sort a batch the way the next epoch would: what applies, in an order that
   * honours every backlink (an op waits for its predecessor even inside one
   * batch), what has to wait, what will never apply. Plus whether the result
   * takes the right to read from anyone — D11's rotation.
   */
  preview(ops: AclOp[]): { applicable: AclOp[]; waiting: AclOp[]; refused: AclOp[]; rotates: boolean } {
    const head = this.headRef()
    let state = head.state
    const history = cloneHistory(this.history)
    const applicable: AclOp[] = []
    const refused: AclOp[] = []
    let pending = ops.slice()
    for (let progress = true; progress && pending.length;) {
      progress = false
      const again: AclOp[] = []
      for (const op of pending) {
        const verdict = verifyAclOp(this.vaultId, op) ? admit({ ...head, state, history }, op) : 'unauthorised'
        if (verdict === 'ok') {
          state = applyOp(state, op)!
          remember(history, op, head.height + 1)
          applicable.push(op)
          progress = true
        } else if (verdict === 'wait') {
          again.push(op)
        } else {
          refused.push(op)
        }
      }
      pending = again
    }
    return { applicable, waiting: pending, refused, rotates: losesRead(head.state, state) }
  }

  /** The initiator's latest applied op since the last rotation: what its next
   *  op names as `prev`. */
  latestOf(issuer: Uint8Array): Uint8Array | undefined {
    const id = this.history.latest.get(toHex(issuer))
    return id ? fromHex(id) : undefined
  }

  /** Has this op applied since the last rotation? */
  applied(opId: Uint8Array): boolean {
    return this.history.ops.has(toHex(opId))
  }

  /** See `conflictsOf`. */
  conflicts(op: AclOp): string[] {
    return conflictsOf(this.headRef(), op)
  }

  /** Height of the epoch that opened the current key epoch. */
  keyEpochHeight(): number {
    return this.history.since
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
    return {
      id: this.head(), height: this.height(), state: this.state(), history: this.history,
      heightOf: (id) => this.heights.get(toHex(id)) ?? -1,
    }
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
    return this.heights.get(toHex(id)) ?? -1
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
