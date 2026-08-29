// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
import { describe, it, expect } from 'vitest'
import {
  encrypt, decrypt, encodeEnvelope, decodeEnvelope, signedRegion, resourceId, randomBytes,
} from '../src/core/envelope'
import { OwnIdentity, verify, sealTo } from '../src/core/identity'

const enc = new TextEncoder()

describe('envelope — primitives pures', () => {
  it('encrypt/decrypt roundtrip', () => {
    const key = randomBytes(32)
    const msg = enc.encode('contenu secret')
    const { nonce, ciphertext } = encrypt(key, msg)
    expect(decrypt(key, nonce, ciphertext)).toEqual(msg)
  })

  it('decrypt avec une mauvaise cle echoue (AEAD)', () => {
    const msg = enc.encode('x')
    const { nonce, ciphertext } = encrypt(randomBytes(32), msg)
    expect(() => decrypt(randomBytes(32), nonce, ciphertext)).toThrow()
  })

  it('ciphertext altere echoue (integrite AEAD)', () => {
    const key = randomBytes(32)
    const { nonce, ciphertext } = encrypt(key, enc.encode('hello'))
    ciphertext[0] ^= 0xff
    expect(() => decrypt(key, nonce, ciphertext)).toThrow()
  })

  it('seal/unseal vers une cle publique (hybride X25519)', () => {
    const bob = OwnIdentity.generate()
    const secret = randomBytes(32)
    const sealed = sealTo(bob.public, secret)
    expect(bob.unseal(sealed)).toEqual(secret)
  })

  it('fromSignSeed : deterministe, cles distinctes, seal+sign fonctionnels', () => {
    const seed = randomBytes(32)
    const a = OwnIdentity.fromSignSeed(seed)
    const b = OwnIdentity.fromSignSeed(seed)
    // meme seed → meme identite (multi-appareils)
    expect(a.signPub).toEqual(b.signPub)
    expect(a.boxPub).toEqual(b.boxPub)
    // les deux cles ne coincident pas (derivation one-way separee)
    expect(a.signPub).not.toEqual(a.boxPub)
    // signature et boite marchent comme pour generate()
    const msg = randomBytes(16)
    expect(verify(a.sign(msg), msg, a.signPub)).toBe(true)
    const sealed = sealTo(a.public, msg)
    expect(b.unseal(sealed)).toEqual(msg) // b = meme identite, peut ouvrir
    expect(() => OwnIdentity.fromSignSeed(randomBytes(16))).toThrow()
  })

  it('enveloppe : encode/decode roundtrip et region signee', () => {
    const rid = resourceId('vault-1')
    const epochId = resourceId('epoque-7')
    const nonce = randomBytes(24)
    const ciphertext = randomBytes(40)
    const signerPub = randomBytes(32)
    const sig = randomBytes(64)
    const bytes = encodeEnvelope({ resourceId: rid, epochId, nonce, ciphertext, sig, signerPub })
    const back = decodeEnvelope(bytes)
    expect(back.resourceId).toEqual(rid)
    expect(back.epochId).toEqual(epochId)
    expect(back.nonce).toEqual(nonce)
    expect(back.ciphertext).toEqual(ciphertext)
    expect(back.sig).toEqual(sig)
    expect(back.signerPub).toEqual(signerPub)
  })

  it('signature couvre resourceId||epochId||nonce||ciphertext et se verifie', () => {
    const alice = OwnIdentity.generate()
    const rid = resourceId('vault-1')
    const epochId = resourceId('epoque-3')
    const nonce = randomBytes(24)
    const ciphertext = randomBytes(16)
    const region = signedRegion(rid, epochId, nonce, ciphertext)
    const sig = alice.sign(region)
    expect(verify(sig, region, alice.signPub)).toBe(true)
    // une epoque differente invalide la signature
    expect(verify(sig, signedRegion(rid, resourceId('epoque-4'), nonce, ciphertext), alice.signPub)).toBe(false)
    // une autre ressource invalide aussi la signature (anti-confusion de canal)
    expect(verify(sig, signedRegion(resourceId('vault-2'), epochId, nonce, ciphertext), alice.signPub)).toBe(false)
  })
})
