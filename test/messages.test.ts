// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Wire messages are binary (C0). Two things must hold for every type: an exact
// roundtrip, and a THROW on anything malformed — Session.onMessage turns a throw
// into a silent drop, so a decoder that returned a short field instead of
// throwing would hand a garbage signature to the verifier.
import { describe, it, expect } from 'vitest'
import {
  MsgType, frame, unframe,
  encodeHello, decodeHello, encodeKey, decodeKey, encodeSyncReq, decodeSyncReq,
  type KeyMsg,
} from '../src/protocol/messages'
import { randomBytes } from '../src/core/envelope'

const hello = () => ({
  signPub: randomBytes(32), boxPub: randomBytes(32),
  nonce: randomBytes(24), sig: randomBytes(64),
})

const key = (): KeyMsg => ({
  resource: 'vault/e2e-été', // non-ASCII: the resource is UTF-8, not bytes
  keyEpochId: randomBytes(32),
  sealedVaultKey: randomBytes(88),
  grantorSignPub: randomBytes(32), recipientSignPub: randomBytes(32), sig: randomBytes(64),
})

describe('messages — encodage binaire', () => {
  it('HELLO fait un aller-retour exact, en 152 octets fixes', () => {
    const m = hello()
    const bytes = encodeHello(m)
    expect(bytes.length).toBe(32 + 32 + 24 + 64)
    expect(decodeHello(bytes)).toEqual(m)
  })

  it('SYNC_REQ fait un aller-retour, state vector vide compris', () => {
    for (const sv of [new Uint8Array(0), randomBytes(1), randomBytes(4096)]) {
      const m = { resourceId: randomBytes(32), stateVector: sv }
      expect(decodeSyncReq(encodeSyncReq(m))).toEqual(m)
    }
  })

  it('KEY fait un aller-retour — une seule cle scellee, plus de docWraps (D29)', () => {
    const m = key()
    const back = decodeKey(encodeKey(m))
    expect(back).toEqual(m)
    expect(back.resource).toBe(m.resource) // UTF-8 preserve
  })

  it('un payload tronque leve, il ne rend pas un champ court', () => {
    const full = encodeHello(hello())
    for (const cut of [0, 1, 31, 151]) {
      expect(() => decodeHello(full.subarray(0, cut))).toThrow()
    }
    const k = encodeKey(key())
    expect(() => decodeKey(k.subarray(0, k.length - 1))).toThrow()
  })

  it('des octets en trop a la fin levent (pas de bourrage silencieux)', () => {
    const withTail = new Uint8Array(encodeHello(hello()).length + 1)
    withTail.set(encodeHello(hello()))
    expect(() => decodeHello(withTail)).toThrow()
  })

  it('une longueur annoncee absurde leve au lieu d\'allouer', () => {
    // [resourceId:32][len:u32 = 0xFFFFFFFF] — rien derriere.
    const hostile = new Uint8Array(36)
    hostile.fill(0xff, 32)
    expect(() => decodeSyncReq(hostile)).toThrow()
  })

  it('frame/unframe preserve le type et la charge', () => {
    const payload = randomBytes(10)
    const { type, payload: back } = unframe(frame(MsgType.Op, payload))
    expect(type).toBe(MsgType.Op)
    expect(back).toEqual(payload)
    expect(() => unframe(new Uint8Array(0))).toThrow()
  })
})
