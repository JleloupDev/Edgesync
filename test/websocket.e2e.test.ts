// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// End-to-end over a REAL WebSocket between two separate OS processes. Proves the
// protocol is transport-agnostic and that "the server" is just a remote peer.
import { describe, it, expect, afterEach } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { YjsCrdt, WebSocketTransport, PeerStore, Session } from '../src/node'
import { joiner, E2E_DIALER } from './vault-fixture'

const here = dirname(fileURLToPath(import.meta.url))
const tsxBin = join(here, '..', 'node_modules', '.bin', 'tsx')
const peerScript = join(here, 'peer-process.ts')

function spawnRemotePeer(port: number, message: string): Promise<ChildProcess> {
  return new Promise((resolve, reject) => {
    const child = spawn(tsxBin, [peerScript, String(port), message], {
      cwd: join(here, '..'),
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString()
      if (out.includes('READY')) resolve(child)
    })
    child.stderr.on('data', (d: Buffer) => process.stderr.write(d))
    child.on('error', reject)
    const t = setTimeout(() => reject(new Error('remote peer did not become READY')), 15000)
    child.on('exit', () => clearTimeout(t))
  })
}

function makeDialer() {
  const crdt = new YjsCrdt()
  // A joiner starts with nothing: no chain, no key. It catches up on both.
  const joined = joiner()
  const transport = new WebSocketTransport('dialer')
  const session = new Session({
    identity: E2E_DIALER,
    crdt,
    keyring: joined.keyring,
    chain: joined.chain,
    transport,
    peers: new PeerStore(),
    resource: 'vault-1',
  })
  return { crdt, transport, session }
}

describe('e2e WebSocket — deux process separes', () => {
  let child: ChildProcess | undefined

  afterEach(() => {
    child?.kill('SIGTERM')
    child = undefined
  })

  it('e: un pair compose vers un pair-process distant et sync E2E', async () => {
    const port = 30000 + Math.floor(Math.random() * 20000)
    child = await spawnRemotePeer(port, 'hello over ws')

    const dialer = makeDialer()
    await dialer.transport.dial(`ws://127.0.0.1:${port}`)
    await new Promise((r) => setTimeout(r, 1000)) // handshake + grant + catch-up

    expect(dialer.crdt.text().toString()).toBe('hello over ws')
    dialer.transport.close()
  })
})
