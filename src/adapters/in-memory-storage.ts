// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// In-memory IStorage for tests. No at-rest protection (none needed: it never
// touches a disk).
import type { IStorage } from '../ports/storage'

export class InMemoryStorage implements IStorage {
  private readonly map = new Map<string, Uint8Array>()

  async get(key: string): Promise<Uint8Array | undefined> {
    return this.map.get(key)
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    this.map.set(key, value.slice())
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key)
  }
}
