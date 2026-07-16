import { describe, expect, it } from 'vitest'
import { HmacDrbg, MAX_BYTES_PER_GENERATE } from './hmac_drbg'
import { NIST_HMAC_DRBG_SHA256 } from './nist_drbg_vectors'
import { bytesToHex, hexToBytes } from './hex'

describe('HMAC_DRBG SHA-256 — NIST CAVP known-answer tests', () => {
  for (const kat of NIST_HMAC_DRBG_SHA256) {
    it(`${kat.group} · COUNT ${kat.count}`, () => {
      const drbg = HmacDrbg.instantiate(
        hexToBytes(kat.entropy),
        hexToBytes(kat.nonce),
        hexToBytes(kat.personalization),
      )
      drbg.reseed(hexToBytes(kat.reseedEntropy), hexToBytes(kat.reseedAdditional))
      const returnedLen = kat.returned.length / 2
      // First generate is discarded per the DRBGVS flow.
      drbg.generate(returnedLen, hexToBytes(kat.additional[0]))
      const out = drbg.generate(returnedLen, hexToBytes(kat.additional[1]))
      expect(bytesToHex(out)).toBe(kat.returned)
    })
  }

  it('covers all four personalization x additional-input option groups', () => {
    const groups = new Set(NIST_HMAC_DRBG_SHA256.map((k) => k.group))
    expect(groups.size).toBe(4)
    expect(NIST_HMAC_DRBG_SHA256.length).toBe(8)
  })
})

describe('HMAC_DRBG behavioural invariants', () => {
  const seed = hexToBytes('06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d')

  it('is deterministic in its seed: same seed -> same stream', () => {
    const a = HmacDrbg.instantiate(seed)
    const b = HmacDrbg.instantiate(seed)
    expect(bytesToHex(a.generate(64))).toBe(bytesToHex(b.generate(64)))
  })

  it('different seeds -> different streams', () => {
    const a = HmacDrbg.instantiate(seed)
    const other = seed.slice()
    other[0] ^= 0x01
    const b = HmacDrbg.instantiate(other)
    expect(bytesToHex(a.generate(64))).not.toBe(bytesToHex(b.generate(64)))
  })

  it('the reseed counter advances once per generate', () => {
    const d = HmacDrbg.instantiate(seed)
    expect(d.getReseedCounter()).toBe(1)
    d.generate(16)
    d.generate(16)
    expect(d.getReseedCounter()).toBe(3)
  })

  it('rejects a generate larger than the SP 800-90A per-call ceiling', () => {
    const d = HmacDrbg.instantiate(seed)
    expect(() => d.generate(MAX_BYTES_PER_GENERATE + 1)).toThrow(/numBytes/)
  })

  it('produces the exact requested length across block boundaries', () => {
    const d = HmacDrbg.instantiate(seed)
    for (const n of [0, 1, 31, 32, 33, 64, 100]) {
      expect(d.generate(n).length).toBe(n)
    }
  })
})
