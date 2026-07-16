// The failed reseed: a long-lived generator, a reseed that adds no fresh entropy, and
// a reseed counter that resets to look healthy while the output stays fully predictable.
//
// Subtlety this teaches precisely: an "empty" reseed is NOT a no-op inside HMAC_DRBG —
// the Update step still stirs (K, V) deterministically and resets reseed_counter to 1,
// so a health monitor watching the counter sees a fresh, recently-reseeded generator.
// But because nothing UNPREDICTABLE went in, an attacker who knew the earlier state
// simply replays the same deterministic stir and keeps predicting every output. The
// counter says "healthy"; the entropy says otherwise. Nobody checks the entropy.

import { HmacDrbg, type DrbgState } from '../crypto/hmac_drbg'
import { bytesEqual } from '../crypto/hex'

export interface ReseedOutcome {
  /** The generator's real output after the (attempted) reseed and some generates. */
  readonly actual: Uint8Array
  /** What an attacker who captured the earlier state predicts, knowing no fresh entropy. */
  readonly attackerPredicted: Uint8Array
  /** True when the attacker's prediction matches — i.e. the reseed protected nothing. */
  readonly predictable: boolean
  /** The reseed counter a health monitor would read afterward. */
  readonly reseedCounter: number
}

function runFrom(
  state: DrbgState,
  reseedEntropy: Uint8Array | null,
  generates: number,
  bytes: number,
): { out: Uint8Array; counter: number } {
  const drbg = HmacDrbg.fromSnapshot(state)
  if (reseedEntropy !== null) drbg.reseed(reseedEntropy)
  let out: Uint8Array = new Uint8Array(0)
  for (let i = 0; i < generates; i++) out = drbg.generate(bytes)
  return { out, counter: drbg.getReseedCounter() }
}

/**
 * A proper reseed injects fresh, attacker-unknown entropy. The attacker, replaying from
 * the captured state with no such entropy, predicts wrongly: predictable === false.
 */
export function afterProperReseed(
  capturedState: DrbgState,
  freshEntropy: Uint8Array,
  generates = 1,
  bytes = 32,
): ReseedOutcome {
  const victim = runFrom(capturedState, freshEntropy, generates, bytes)
  const attacker = runFrom(capturedState, null, generates, bytes) // attacker guesses "no reseed"
  return {
    actual: victim.out,
    attackerPredicted: attacker.out,
    predictable: bytesEqual(victim.out, attacker.out),
    reseedCounter: victim.counter,
  }
}

/**
 * A silent no-op reseed adds an EMPTY entropy input. HMAC_DRBG still stirs and the
 * counter resets to 1 (looks healthy), but the stir is deterministic — the attacker
 * replays it and keeps predicting: predictable === true.
 */
export function afterNoOpReseed(
  capturedState: DrbgState,
  generates = 1,
  bytes = 32,
): ReseedOutcome {
  const empty = new Uint8Array(0)
  const victim = runFrom(capturedState, empty, generates, bytes)
  const attacker = runFrom(capturedState, empty, generates, bytes)
  return {
    actual: victim.out,
    attackerPredicted: attacker.out,
    predictable: bytesEqual(victim.out, attacker.out),
    reseedCounter: victim.counter,
  }
}
