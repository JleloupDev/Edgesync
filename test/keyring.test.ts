// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Key material indexed by the epoch that introduced it, and channel keys DERIVED
// rather than minted (D29). The derivation is what deletes a whole family of
// problems instead of solving them: nothing to carry on the wire, nothing to
// reconcile, nothing to grind.
import { describe, it, expect } from 'vitest'
import { Keyring, keyCommitment } from '../src/core/keyring'
import { encrypt, decrypt, randomBytes, resourceId } from '../src/core/envelope'

const E1 = resourceId('epoch-1')
const E2 = resourceId('epoch-2')
const RID_DIR = resourceId('vault-1/dir')
const RID_DOC1 = resourceId('vault-1/doc/1')

describe('keyring — cles derivees, indexees par epoque', () => {
  it('adopte une cle et derive les canaux a la demande', () => {
    const kr = Keyring.empty()
    const vk = randomBytes(32)
    expect(kr.has(E1)).toBe(false)

    kr.adopt(E1, vk, keyCommitment(vk))
    expect(kr.has(E1)).toBe(true)
    expect(kr.vaultKey(E1)).toEqual(vk)
    expect(kr.docKey(E1, RID_DIR)).toBeInstanceOf(Uint8Array)
  })

  it('refuse une cle qui ne correspond pas a l\'engagement de la chaine', () => {
    const kr = Keyring.empty()
    const vraie = randomBytes(32)
    const fausse = randomBytes(32)
    expect(() => kr.adopt(E1, fausse, keyCommitment(vraie))).toThrow(/commitment/)
    expect(kr.has(E1)).toBe(false)
  })

  it('D29 : deux pairs derivent LA MEME cle de canal — pas de fork possible', () => {
    const vk = randomBytes(32)
    const a = Keyring.empty()
    const b = Keyring.empty()
    a.adopt(E1, vk)
    b.adopt(E1, vk)
    expect(a.docKey(E1, RID_DOC1)).toEqual(b.docKey(E1, RID_DOC1))
  })

  it('des canaux distincts, et des epoques distinctes, donnent des cles distinctes', () => {
    const kr = Keyring.empty()
    kr.adopt(E1, randomBytes(32))
    kr.adopt(E2, randomBytes(32))
    expect(kr.docKey(E1, RID_DIR)).not.toEqual(kr.docKey(E1, RID_DOC1))
    expect(kr.docKey(E1, RID_DIR)).not.toEqual(kr.docKey(E2, RID_DIR))
  })

  it('sans la cle de vault, aucun canal ne se derive', () => {
    const kr = Keyring.empty()
    expect(kr.docKey(E1, RID_DIR)).toBeUndefined()
  })

  it('un canal partage seul se lit sans jamais detenir K_vault', () => {
    const owner = Keyring.empty()
    owner.adopt(E1, randomBytes(32))
    const shared = owner.docKey(E1, RID_DOC1)!

    const outsider = Keyring.empty()
    outsider.importDocKey(E1, RID_DOC1, shared)

    // il lit CE canal…
    const { nonce, ciphertext } = encrypt(shared, new TextEncoder().encode('secret'))
    expect(decrypt(outsider.docKey(E1, RID_DOC1)!, nonce, ciphertext)).toEqual(new TextEncoder().encode('secret'))
    // …et rien d'autre : le KDF est a sens unique.
    expect(outsider.vaultKey(E1)).toBeUndefined()
    expect(outsider.docKey(E1, RID_DIR)).toBeUndefined()
  })

  it('serialise et relit tout le materiel detenu', () => {
    const kr = Keyring.empty()
    kr.adopt(E1, randomBytes(32))
    kr.adopt(E2, randomBytes(32))
    kr.importDocKey(E1, RID_DOC1, randomBytes(32))

    const back = Keyring.deserialize(kr.serialize())
    expect(back.vaultKey(E1)).toEqual(kr.vaultKey(E1))
    expect(back.vaultKey(E2)).toEqual(kr.vaultKey(E2))
    expect(back.docKey(E1, RID_DOC1)).toEqual(kr.docKey(E1, RID_DOC1))
    expect(back.knownEpochs()).toHaveLength(2)
  })
})
