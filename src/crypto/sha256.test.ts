import { describe, expect, it } from 'vitest'
import { sha256 } from './sha256'
import { bytesToHex } from './hex'

const enc = (s: string) => new TextEncoder().encode(s)

// FIPS 180-4 / NIST CAVS known-answer vectors.
describe('SHA-256 known-answer tests (FIPS 180-4)', () => {
  it('empty string', () => {
    expect(bytesToHex(sha256(enc('')))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })

  it('"abc" (one block)', () => {
    expect(bytesToHex(sha256(enc('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('56-byte message (two blocks)', () => {
    const msg = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    expect(bytesToHex(sha256(enc(msg)))).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    )
  })

  it('one million "a" (length/padding stress)', () => {
    const msg = new Uint8Array(1_000_000).fill(0x61)
    expect(bytesToHex(sha256(msg))).toBe(
      'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
    )
  })
})
