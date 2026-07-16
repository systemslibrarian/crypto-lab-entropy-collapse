import { describe, expect, it } from 'vitest'
import { bytesToHex } from '../crypto/hex'
import {
  bootMaterial,
  seedFromMaterial,
  publicNonceFromSeed,
  sessionKeyFromSeed,
  keyspaceSize,
  isEnumerable,
  type BootModel,
} from './boot'
import { recoverSeed } from './enumerate'

const model: BootModel = {
  mac: new Uint8Array([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
  baseTimeSec: 1_600_000_000,
  unknownBits: 14,
}

describe('entropy panel — low-entropy seed enumeration against the real DRBG', () => {
  it('recovers the exact seed and session key from an observed public nonce', () => {
    const secret = 9001 // the victim machine’s actual (timeOffset, pid)
    const seed = seedFromMaterial(bootMaterial(model, secret))
    const observedNonce = publicNonceFromSeed(seed)

    const result = recoverSeed(observedNonce, model)
    expect(result.found).toBe(true)
    expect(result.secretIndex).toBe(secret)
    expect(bytesToHex(result.seed!)).toBe(bytesToHex(seed))
    expect(bytesToHex(result.sessionKey!)).toBe(bytesToHex(sessionKeyFromSeed(seed)))
  })

  it('recovers a seed at the very top of the search space', () => {
    const secret = (1 << model.unknownBits) - 1
    const seed = seedFromMaterial(bootMaterial(model, secret))
    const result = recoverSeed(publicNonceFromSeed(seed), model)
    expect(result.found).toBe(true)
    expect(result.secretIndex).toBe(secret)
  })

  it('reports failure (not a false match) when the seed is outside the searched space', () => {
    const outOfRange: BootModel = { ...model, unknownBits: 8 }
    const seed = seedFromMaterial(bootMaterial(model, 12345)) // needs 14 bits
    const result = recoverSeed(publicNonceFromSeed(seed), outOfRange)
    expect(result.found).toBe(false)
    expect(result.seed).toBeNull()
  })

  it('the keyspace and enumerability gate match the entropy', () => {
    expect(keyspaceSize(256)).toBe(1n << 256n)
    expect(keyspaceSize(14)).toBe(16384n)
    expect(isEnumerable(14)).toBe(true)
    expect(isEnumerable(64)).toBe(false)
  })
})
