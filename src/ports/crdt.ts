// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// CRDT port. The protocol depends on this interface, never on Yjs directly.

export interface ICrdt {
  /** Subscribe to locally-produced updates (one per local mutation). */
  onLocalUpdate(cb: (update: Uint8Array) => void): () => void
  /** Apply a remote update. Must be idempotent and commutative. */
  applyRemote(update: Uint8Array): void
  /** The full state as a single update (snapshot). */
  snapshot(): Uint8Array
  /** A state vector describing what this replica already holds. */
  stateVector(): Uint8Array
  /** The update carrying everything the given state vector is missing. */
  diffSince(stateVector: Uint8Array): Uint8Array
}
