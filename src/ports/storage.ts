// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Storage port. The protocol persists its state through this interface and knows
// NOTHING about at-rest encryption — that is the application's concern (ADR-0011).
// Keys are namespaced by sensitivity so an app-provided adapter can decide what to
// protect:
//   secret/…  values an encrypting adapter MUST protect (identity, keyring)
//   open/…    values safe in clear (public keys; protocol-produced ciphertext)

export interface IStorage {
  get(key: string): Promise<Uint8Array | undefined>
  set(key: string, value: Uint8Array): Promise<void>
  delete(key: string): Promise<void>
}
