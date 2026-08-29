// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// A headless peer in its own OS process (assertion e). It listens, holds the
// genesis keys, grants them to whoever connects, and seeds a message. This is a
// *peer*, not a server: it runs the exact same protocol code as any client.
import { OwnIdentity, YjsCrdt, WebSocketTransport, PeerStore, Session } from '../src/node'
import { foundVault, E2E_DIALER } from './vault-fixture'
import { Access } from '../src/index'

const port = Number(process.argv[2] ?? 0)
const message = process.argv[3] ?? 'hello over ws'

async function main(): Promise<void> {
  const identity = OwnIdentity.generate()
  const crdt = new YjsCrdt()
  const transport = new WebSocketTransport('founder')
  // The founder is owner, manage and sole arbiter (k=1) — see vault-fixture.
  const { chain, keyring } = foundVault(identity, [{ signPub: E2E_DIALER.signPub, access: Access.Write }])
  // eslint-disable-next-line no-new
  new Session({ identity, crdt, keyring, chain, transport, peers: new PeerStore(), resource: 'vault-1' })

  await transport.listen(port)
  crdt.text().insert(0, message)
  process.stdout.write('READY\n')

  const keepAlive = setInterval(() => {}, 1 << 30)
  process.on('SIGTERM', () => { clearInterval(keepAlive); transport.close(); process.exit(0) })
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
