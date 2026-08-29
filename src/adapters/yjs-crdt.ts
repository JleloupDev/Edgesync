// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Yjs adapter for the ICrdt port. The protocol core never imports Yjs.
import * as Y from 'yjs'
import type { ICrdt } from '../ports/crdt'

// TypeScript 5.9 + moduleResolution:bundler fails to follow Yjs's .js→.d.ts
// re-export chain when this file is typechecked from a consumer package (same
// workaround as YMapVaultDirectory in the app). Runtime behaviour is validated
// by tests.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const Y_ = Y as Record<string, any>

const REMOTE = 'remote'

export class YjsCrdt implements ICrdt {
  readonly doc: Y.Doc

  constructor(doc: Y.Doc = new Y_.Doc()) {
    this.doc = doc
  }

  /** The shared text field used by the POC. */
  text(): Y.Text {
    return this.doc.getText('message')
  }

  onLocalUpdate(cb: (update: Uint8Array) => void): () => void {
    const handler = (update: Uint8Array, origin: unknown) => {
      if (origin === REMOTE) return // do not re-broadcast remote updates
      cb(update)
    }
    // on/off live on lib0's Observable base class, whose types are lost through
    // the same broken re-export chain (see Y_ above).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const doc = this.doc as any
    doc.on('update', handler)
    return () => doc.off('update', handler)
  }

  applyRemote(update: Uint8Array): void {
    Y_.applyUpdate(this.doc, update, REMOTE)
  }

  snapshot(): Uint8Array {
    return Y_.encodeStateAsUpdate(this.doc) as Uint8Array
  }

  stateVector(): Uint8Array {
    return Y_.encodeStateVector(this.doc) as Uint8Array
  }

  diffSince(stateVector: Uint8Array): Uint8Array {
    return Y_.encodeStateAsUpdate(this.doc, stateVector) as Uint8Array
  }
}
