// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Filesystem IStorage for the headless POC. Stores values **in clear**. In
// production the application supplies an adapter that encrypts `secret/…` values
// at rest (ADR-0011) — the protocol never does that itself.
import { mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import type { IStorage } from '../ports/storage'

export class FileSystemStorage implements IStorage {
  constructor(private readonly dir: string) {}

  private path(key: string): string {
    return join(this.dir, key.replace(/\//g, '__'))
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    try {
      return new Uint8Array(await readFile(this.path(key)))
    } catch {
      return undefined
    }
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    await mkdir(this.dir, { recursive: true })
    await writeFile(this.path(key), value)
  }

  async delete(key: string): Promise<void> {
    try {
      await rm(this.path(key))
    } catch {
      // already absent
    }
  }
}
