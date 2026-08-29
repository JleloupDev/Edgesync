// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Transport port. The protocol depends on this interface, never on a network
// library. Adapters: in-process (tests) and WebSocket (separate processes).

export type MessageHandler = (from: string, bytes: Uint8Array) => void
export type PeerHandler = (peerId: string) => void

export interface ITransport {
  readonly localId: string
  onMessage(cb: MessageHandler): () => void
  onPeerUp(cb: PeerHandler): () => void
  onPeerDown(cb: PeerHandler): () => void
  send(to: string, bytes: Uint8Array): void
  peers(): string[]
}
