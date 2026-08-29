// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Point-to-point WebSocket transport for the POC: one peer listens, the other
// dials. The remote is a single logical peer ("remote"). Real deployments swap
// this adapter (WebRTC / libp2p); the protocol is unchanged.
import { WebSocketServer, WebSocket } from 'ws'
import type { ITransport, MessageHandler, PeerHandler } from '../ports/transport'

const REMOTE = 'remote'

export class WebSocketTransport implements ITransport {
  private ws?: WebSocket
  private server?: WebSocketServer
  private msg: MessageHandler[] = []
  private up: PeerHandler[] = []
  private down: PeerHandler[] = []

  constructor(readonly localId: string) {}

  listen(port: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = new WebSocketServer({ port })
      this.server = server
      server.on('connection', (ws) => this.bind(ws))
      server.on('listening', () => resolve())
      server.on('error', reject)
    })
  }

  dial(url: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url)
      ws.on('open', () => {
        this.bind(ws)
        resolve()
      })
      ws.on('error', reject)
    })
  }

  private bind(ws: WebSocket): void {
    this.ws = ws
    ws.on('message', (data: Buffer | ArrayBuffer | Buffer[]) => {
      const bytes = toBytes(data)
      for (const h of this.msg) h(REMOTE, bytes)
    })
    ws.on('close', () => {
      for (const h of this.down) h(REMOTE)
    })
    for (const h of this.up) h(REMOTE)
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

  send(_to: string, bytes: Uint8Array): void {
    this.ws?.send(bytes)
  }

  peers(): string[] {
    return this.ws && this.ws.readyState === WebSocket.OPEN ? [REMOTE] : []
  }

  close(): void {
    this.ws?.close()
    this.server?.close()
  }
}

function toBytes(data: Buffer | ArrayBuffer | Buffer[]): Uint8Array {
  if (Array.isArray(data)) return new Uint8Array(Buffer.concat(data))
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
}
