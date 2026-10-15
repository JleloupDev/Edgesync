// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Jean Leloup
//
// Broadcast port. HOW a message reaches the rest of the network is a strategy,
// not a protocol rule. The Session decides WHAT may spread — it validates first,
// and only ever spreads bytes exactly as their author signed them. The strategy
// decides WHERE they go. Flooding today; Plumtree, a partial view or an external
// gossip library tomorrow — each one a new adapter, never a change to the Session.

export interface IBroadcast {
  /** Already spread or relayed? Such a message is neither applied nor spread
   *  again: that is what stops a message from circling forever. Pure query —
   *  only `spread` remembers, so a message we could not validate yet is not
   *  burnt and a later copy still gets its chance. */
  seen(bytes: Uint8Array): boolean
  /** Send to the network, and remember it. `from` is the neighbour it came from
   *  (absent when we originate it): it never gets it back. */
  spread(bytes: Uint8Array, from?: string): void
}
