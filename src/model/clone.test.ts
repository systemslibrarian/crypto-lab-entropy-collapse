import { describe, expect, it } from 'vitest'
import { HmacDrbg } from '../crypto/hmac_drbg'
import { hexToBytes, bytesToHex } from '../crypto/hex'
import { runClonedStreams, divergeAfterReseed, cloneFromSnapshot } from './clone'

const seed = hexToBytes('06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d')

describe('clone panel — snapshot/restore produces identical streams', () => {
  it('two machines restored from one snapshot agree on every output', () => {
    const victim = HmacDrbg.instantiate(seed)
    victim.generate(8) // advance the machine before the snapshot is taken
    const cmp = runClonedStreams(victim.snapshot())
    expect(cmp.allIdentical).toBe(true)
    for (const item of cmp.items) expect(bytesToHex(item.a)).toBe(bytesToHex(item.b))
  })

  it('the shared session key is not merely similar — it is byte-identical', () => {
    const victim = HmacDrbg.instantiate(seed)
    const { a, b } = cloneFromSnapshot(victim.snapshot())
    a.generate(16) // nonce
    b.generate(16)
    const keyA = a.generate(32)
    const keyB = b.generate(32)
    expect(bytesToHex(keyA)).toBe(bytesToHex(keyB))
    expect(keyA.length).toBe(32)
  })

  it('reseeding Server B with unique entropy breaks the collision (the fix)', () => {
    const victim = HmacDrbg.instantiate(seed)
    const res = divergeAfterReseed(victim.snapshot(), hexToBytes('ff'.repeat(32)))
    expect(res.diverged).toBe(true)
    expect(bytesToHex(res.a)).not.toBe(bytesToHex(res.b))
  })
})
