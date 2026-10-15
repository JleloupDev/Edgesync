// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// The simplest gossip: every message goes to every neighbour but the one it came
// from, once. One frame per link and per message — fine for a few hundred peers,
// and the baseline any smarter strategy has to beat behind the same port.
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/hashes/utils'
import type { IBroadcast } from '../ports/broadcast'
import type { ITransport } from '../ports/transport'

export class FloodBroadcast implements IBroadcast {
  /** Insertion-ordered, so the oldest entry is the first one evicted. Forgetting
   *  a message only means a late duplicate is relayed once more: CRDT updates
   *  are idempotent and epochs are deduplicated by the chain, so it is harmless. */
  private readonly memory = new Set<string>()

  constructor(
    private readonly transport: ITransport,
    private readonly capacity = 10_000,
  ) {}

  seen(bytes: Uint8Array): boolean {
    return this.memory.has(digest(bytes))
  }

  spread(bytes: Uint8Array, from?: string): void {
    this.remember(digest(bytes))
    for (const peer of this.transport.peers()) {
      if (peer !== from) this.transport.send(peer, bytes)
    }
  }

  private remember(key: string): void {
    if (this.memory.has(key)) return
    this.memory.add(key)
    if (this.memory.size > this.capacity) {
      const oldest = this.memory.values().next().value
      if (oldest !== undefined) this.memory.delete(oldest)
    }
  }
}

function digest(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes))
}
