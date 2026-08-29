// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Shared setup for the integration tests: bootstrap a vault, join a peer, grant
// and revoke. Kept out of the .test.ts files so every one of them exercises the
// SAME founding sequence — the one an application will have to reproduce.
import { sha256 } from '@noble/hashes/sha2'
import { OwnIdentity } from '../src/core/identity'
import { resourceId, randomBytes } from '../src/core/envelope'
import { Keyring, keyCommitment } from '../src/core/keyring'
import { AclChain, type Epoch } from '../src/core/acl-chain'
import {
  Access, ROOT_GROUP, signAclOp, keyPrincipal, groupPrincipal, type AclChange, type AclOp,
} from '../src/core/acl-ops'

export const VAULT = 'vault-1'
export const VAULT_ID = resourceId(VAULT)
/** The group the root delegates to — never an individual (D19). */
export const OWNERS = sha256(new TextEncoder().encode('owners-group'))

export const idOf = (o: OwnIdentity) => ({ signPub: o.signPub, sign: (m: Uint8Array) => o.sign(m) })

export function aclOp(issuer: OwnIdentity, group: Uint8Array, changes: AclChange[]): AclOp {
  return signAclOp(VAULT_ID, { group, changes, issuer: issuer.signPub }, (m) => issuer.sign(m))
}

/**
 * Found a vault: the founder is `manage` INSIDE the owners group, the root
 * delegates to that group, and the founder declares itself arbiter (D37: there
 * is always at least one, k=1 here).
 *
 * The genesis epoch commits to sha256(K_vault) — never the key itself, since the
 * chain is public (Q2).
 */
export function foundVault(
  founder: OwnIdentity,
  extra: { signPub: Uint8Array; access: Access }[] = [],
): { chain: AclChain; keyring: Keyring; vaultKey: Uint8Array } {
  const vaultKey = randomBytes(32)
  const chain = AclChain.genesis(VAULT_ID, idOf(founder), [
    aclOp(founder, OWNERS, [{ t: 'set', principal: keyPrincipal(founder.signPub), access: Access.Manage }]),
    aclOp(founder, ROOT_GROUP, [
      { t: 'set', principal: groupPrincipal(OWNERS), access: Access.Manage },
      { t: 'arbiter', principal: keyPrincipal(founder.signPub), on: true },
      ...extra.map((m) => ({ t: 'set' as const, principal: keyPrincipal(m.signPub), access: m.access })),
    ]),
  ], keyCommitment(vaultKey))

  const keyring = Keyring.empty()
  keyring.adopt(chain.head(), vaultKey, keyCommitment(vaultKey))
  return { chain, keyring, vaultKey }
}

/** A peer that has not been founded into anything yet: empty chain, no keys. */
export function joiner(): { chain: AclChain; keyring: Keyring } {
  return { chain: new AclChain(VAULT_ID), keyring: Keyring.empty() }
}

/** Copy a chain (a second peer's view), without sharing the array by reference. */
export function mirror(source: AclChain): AclChain {
  const c = new AclChain(source.vaultId)
  for (const e of source.all()) c.adoptEpoch(e)
  return c
}

export type { Epoch }

/**
 * A fixed identity, so two OS processes can agree on who the dialer is without a
 * handshake. Test-only: it lets the e2e stay about transport and sync instead of
 * re-testing admission, which the in-process suite already covers.
 */
export const E2E_DIALER = OwnIdentity.fromSeeds(
  new Uint8Array(32).fill(7),
  new Uint8Array(32).fill(8),
)
