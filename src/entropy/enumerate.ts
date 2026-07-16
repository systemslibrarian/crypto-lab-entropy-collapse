// Seed recovery by brute force. This runs the REAL DRBG for each candidate seed and
// compares its real output to the observed public nonce. There is no shortcut and no
// simulation: when the search space is small, the attacker simply tries every seed
// the booting machine could have had until the generator's output matches.

import { bytesEqual } from '../crypto/hex'
import { bootMaterial, candidateNonce, seedFromMaterial, sessionKeyFromSeed, type BootModel } from './boot'

export interface RecoveryResult {
  found: boolean
  secretIndex: number
  tried: number
  seed: Uint8Array | null
  sessionKey: Uint8Array | null
}

export interface RecoverOptions {
  /** Hard cap on candidates tried; recovery reports found=false if exceeded. */
  maxCandidates?: number
  /** Optional start index (for chunked/resumable enumeration from the UI). */
  from?: number
}

/**
 * Try candidate seeds in order until the real DRBG reproduces `observedNonce`.
 * Synchronous and self-contained so unit tests can assert exact recovery.
 */
export function recoverSeed(
  observedNonce: Uint8Array,
  model: BootModel,
  opts: RecoverOptions = {},
): RecoveryResult {
  const space = model.unknownBits >= 31 ? Number.MAX_SAFE_INTEGER : 1 << model.unknownBits
  const from = opts.from ?? 0
  const limit = Math.min(space, from + (opts.maxCandidates ?? space))

  for (let i = from; i < limit; i++) {
    const seed = seedFromMaterial(bootMaterial(model, i))
    if (bytesEqual(candidateNonce(seed), observedNonce)) {
      return {
        found: true,
        secretIndex: i,
        tried: i - from + 1,
        seed,
        sessionKey: sessionKeyFromSeed(seed),
      }
    }
  }
  return { found: false, secretIndex: -1, tried: limit - from, seed: null, sessionKey: null }
}

/**
 * A resumable single step over `batch` candidates, for driving live enumeration from
 * the UI without freezing the main thread. Returns a partial result; call again with
 * `from = result.tried + previousFrom` until `found` or the space is exhausted.
 */
export function recoverBatch(
  observedNonce: Uint8Array,
  model: BootModel,
  from: number,
  batch: number,
): RecoveryResult {
  return recoverSeed(observedNonce, model, { from, maxCandidates: batch })
}
