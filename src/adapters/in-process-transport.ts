// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// In-process transport for tests. A shared Bus wires several peers; delivery is
// async (microtask) to mimic a real link and avoid reentrancy. The Bus records
// every byte that crosses it so a test can prove the wire is opaque.
import type { ITransport, MessageHandler, PeerHandler } from '../ports/transport'

export class Bus {
  readonly nodes = new Map<string, InProcessTransport>()
  readonly wire: Uint8Array[] = []

  register(t: InProcessTransport): void {
    const existing = [...this.nodes.values()]
    this.nodes.set(t.localId, t)
    for (const other of existing) {
      queueMicrotask(() => other.firePeerUp(t.localId))
      queueMicrotask(() => t.firePeerUp(other.localId))
    }
  }

  deliver(from: string, to: string, bytes: Uint8Array): void {
    this.wire.push(bytes)
    const node = this.nodes.get(to)
    if (node) queueMicrotask(() => node.fireMessage(from, bytes))
  }

  disconnect(id: string): void {
    const t = this.nodes.get(id)
    if (!t) return
    this.nodes.delete(id)
    for (const other of this.nodes.values()) {
      queueMicrotask(() => other.firePeerDown(id))
      queueMicrotask(() => t.firePeerDown(other.localId))
    }
  }
}

export class InProcessTransport implements ITransport {
  private msg: MessageHandler[] = []
  private up: PeerHandler[] = []
  private down: PeerHandler[] = []

  constructor(readonly localId: string, private readonly bus: Bus) {}

  /** Join the bus. Call after the Session has registered its handlers. */
  connect(): void {
    this.bus.register(this)
  }

  onMessage(cb: MessageHandler): () => void {
    this.msg.push(cb)
    return () => { this.msg = this.msg.filter((h) => h !== cb) }
  }

  onPeerUp(cb: PeerHandler): () => void {
    this.up.push(cb)
    return () => { this.up = this.up.filter((h) => h !== cb) }
  }

  onPeerDown(cb: PeerHandler): () => void {
    this.down.push(cb)
    return () => { this.down = this.down.filter((h) => h !== cb) }
  }

  send(to: string, bytes: Uint8Array): void {
    this.bus.deliver(this.localId, to, bytes)
  }

  peers(): string[] {
    return [...this.bus.nodes.keys()].filter((id) => id !== this.localId)
  }

  fireMessage(from: string, bytes: Uint8Array): void {
    for (const h of this.msg) h(from, bytes)
  }

  firePeerUp(id: string): void {
    for (const h of this.up) h(id)
  }

  firePeerDown(id: string): void {
    for (const h of this.down) h(id)
  }
}
