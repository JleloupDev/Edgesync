// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Portable codecs replace Buffer: they must match Node's own encoding exactly
// (persisted blobs written with Buffer must stay readable) and roundtrip for
// every padding case.
import { describe, it, expect } from 'vitest'
import { toBase64, fromBase64, toHex } from '../src/core/codec'
import { randomBytes } from '../src/core/envelope'

describe('codec — base64/hex portables', () => {
  it('matches Buffer base64 on known vectors', () => {
    for (const s of ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
      const bytes = new TextEncoder().encode(s)
      expect(toBase64(bytes)).toBe(Buffer.from(bytes).toString('base64'))
    }
  })

  it('roundtrips every length 0..64 (all padding cases)', () => {
    for (let n = 0; n <= 64; n++) {
      const bytes = randomBytes(n)
      expect(fromBase64(toBase64(bytes))).toEqual(bytes)
    }
  })

  it('fromBase64 rejects invalid input', () => {
    expect(() => fromBase64('a!b')).toThrow()
  })

  it('matches Buffer hex', () => {
    const bytes = randomBytes(32)
    expect(toHex(bytes)).toBe(Buffer.from(bytes).toString('hex'))
  })
})
