// fork() safety as a cryptographic property.
//
// A parent process seeds the real DRBG, then fork()s. Both children inherit an exact
// copy of the parent's DRBG state (this is what fork() does — the address space is
// duplicated). The child that pulls fresh entropy before generating is safe; the child
// that does not will emit exactly what the parent would have emitted next — the same
// "random" values, in a different process, with no shared code path and no attacker.

import { HmacDrbg, type DrbgState } from '../crypto/hmac_drbg'
import { bytesEqual } from '../crypto/hex'

export interface ForkResult {
  /** What the parent's DRBG produces next, continuing from the fork point. */
  readonly parentNext: Uint8Array
  /** The child that reseeded with machine-unique fresh entropy. */
  readonly childReseeded: Uint8Array
  /** The child that inherited the state and did NOT reseed. */
  readonly childInherited: Uint8Array
  /** True — the un-reseeded child collides with the parent. This is the hazard. */
  readonly inheritedCollidesWithParent: boolean
  /** False — reseeding breaks the collision. This is the fix. */
  readonly reseededCollidesWithParent: boolean
}

/**
 * Snapshot the parent at the fork point, spawn two children from that snapshot, and
 * compare each child's next output against the parent's next output.
 */
export function forkAndGenerate(
  parentStateAtFork: DrbgState,
  childFreshEntropy: Uint8Array,
  numBytes = 32,
): ForkResult {
  const parent = HmacDrbg.fromSnapshot(parentStateAtFork)
  const reseeded = HmacDrbg.fromSnapshot(parentStateAtFork)
  const inherited = HmacDrbg.fromSnapshot(parentStateAtFork)

  const parentNext = parent.generate(numBytes)

  reseeded.reseed(childFreshEntropy)
  const childReseeded = reseeded.generate(numBytes)

  const childInherited = inherited.generate(numBytes)

  return {
    parentNext,
    childReseeded,
    childInherited,
    inheritedCollidesWithParent: bytesEqual(childInherited, parentNext),
    reseededCollidesWithParent: bytesEqual(childReseeded, parentNext),
  }
}
