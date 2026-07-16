// The headline mechanism: snapshot one machine's DRBG state, restore it onto two
// machines, and watch every subsequent output match byte-for-byte forever.
//
// IMPORTANT (scope honesty): there is no real hypervisor here. `snapshot()` copies the
// DRBG's (K, V, reseed_counter) working state — a MODEL of a VM snapshot/restore or a
// forked/cloned image. That model is exact for the one thing this lab teaches: the
// generator's output depends only on that state, so two machines that share it share
// every secret. The DRBG itself is the real SP 800-90A implementation, unmodified.

import { HmacDrbg, type DrbgState } from '../crypto/hmac_drbg'
import { bytesEqual } from '../crypto/hex'

export interface StreamStep {
  readonly label: string
  readonly bytes: number
}

/** Default script both restored machines execute: a public nonce, then a secret key. */
export const DEFAULT_SCRIPT: readonly StreamStep[] = [
  { label: 'Session nonce (public)', bytes: 16 },
  { label: 'Session key (secret)', bytes: 32 },
  { label: 'Next nonce (public)', bytes: 16 },
  { label: 'Next key (secret)', bytes: 32 },
]

export interface ComparedItem {
  readonly label: string
  readonly a: Uint8Array
  readonly b: Uint8Array
  readonly identical: boolean
}

export interface CloneComparison {
  readonly items: ComparedItem[]
  readonly allIdentical: boolean
}

/** Restore two independent DRBGs from one snapshot: Server A and Server B. */
export function cloneFromSnapshot(state: DrbgState): { a: HmacDrbg; b: HmacDrbg } {
  return { a: HmacDrbg.fromSnapshot(state), b: HmacDrbg.fromSnapshot(state) }
}

/** Run both restored machines through the script and compare each output. */
export function runClonedStreams(
  state: DrbgState,
  script: readonly StreamStep[] = DEFAULT_SCRIPT,
): CloneComparison {
  const { a, b } = cloneFromSnapshot(state)
  const items: ComparedItem[] = script.map((step) => {
    const outA = a.generate(step.bytes)
    const outB = b.generate(step.bytes)
    return { label: step.label, a: outA, b: outB, identical: bytesEqual(outA, outB) }
  })
  return { items, allIdentical: items.every((i) => i.identical) }
}

/**
 * The remedy, made visible: if Server B mixes in even one machine-unique fresh entropy
 * input before generating, the streams diverge immediately. Returns the two first
 * outputs and whether they differ (they should).
 */
export function divergeAfterReseed(
  state: DrbgState,
  serverBFreshEntropy: Uint8Array,
  bytes = 16,
): { a: Uint8Array; b: Uint8Array; diverged: boolean } {
  const { a, b } = cloneFromSnapshot(state)
  b.reseed(serverBFreshEntropy)
  const outA = a.generate(bytes)
  const outB = b.generate(bytes)
  return { a: outA, b: outB, diverged: !bytesEqual(outA, outB) }
}
