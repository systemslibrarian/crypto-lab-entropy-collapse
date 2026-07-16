import { describe, expect, it } from 'vitest'
import { hmacSha256 } from './hmac'
import { bytesToHex, hexToBytes } from './hex'

const enc = (s: string) => new TextEncoder().encode(s)
const rep = (byte: number, n: number) => new Uint8Array(n).fill(byte)

// RFC 4231 HMAC-SHA-256 test vectors.
describe('HMAC-SHA256 known-answer tests (RFC 4231)', () => {
  it('Test Case 1 — 20-byte 0x0b key, "Hi There"', () => {
    expect(bytesToHex(hmacSha256(rep(0x0b, 20), enc('Hi There')))).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    )
  })

  it('Test Case 2 — "Jefe" key', () => {
    expect(bytesToHex(hmacSha256(enc('Jefe'), enc('what do ya want for nothing?')))).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    )
  })

  it('Test Case 3 — 20-byte 0xaa key, 50 x 0xdd', () => {
    expect(bytesToHex(hmacSha256(rep(0xaa, 20), rep(0xdd, 50)))).toBe(
      '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    )
  })

  it('Test Case 4 — 25-byte incrementing key, 50 x 0xcd', () => {
    expect(bytesToHex(hmacSha256(hexToBytes('0102030405060708090a0b0c0d0e0f10111213141516171819'), rep(0xcd, 50)))).toBe(
      '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    )
  })
})
