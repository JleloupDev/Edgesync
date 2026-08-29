// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Public surface of the P2P collaboration protocol. Browser-safe: no Node
// builtins in this graph. Node-only adapters (WebSocket via 'ws', filesystem
// storage) live in './node'.

// Core (pure)
export * from './core/codec'
export * from './core/envelope'
export * from './core/identity'
export * from './core/keyring'
export * from './core/acl-ops'
export * from './core/acl-chain'

// Ports
export type { ICrdt } from './ports/crdt'
export type { ITransport, MessageHandler, PeerHandler } from './ports/transport'
export { PeerStore, PinnedKeyChangedError, type KnownPeer, type PeerStatus } from './ports/peer-store'
export type { IStorage } from './ports/storage'

// Adapters (browser-safe only)
export { YjsCrdt } from './adapters/yjs-crdt'
export { Bus, InProcessTransport } from './adapters/in-process-transport'
export { InMemoryStorage } from './adapters/in-memory-storage'

// Protocol
export * from './protocol/messages'
export { Session, type SessionOpts } from './protocol/session'
export { saveAll, loadIdentity, loadKeyring, loadPeers, loadChain, loadContent, type PersistableParts, type PersistableChannel } from './protocol/persistence'
