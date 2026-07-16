import { describe, expect, it } from 'vitest'
import { HmacDrbg } from '../crypto/hmac_drbg'
import { hexToBytes, bytesToHex } from '../crypto/hex'
import { forkAndGenerate } from './fork'

const seed = hexToBytes('aadcf337788bb8ac01976640726bc51635d417777fe6939eded9ccc8a378c76a')

describe('fork panel — inherited DRBG state collides with the parent', () => {
  it('the child that does not reseed emits the parent’s next output exactly', () => {
    const parent = HmacDrbg.instantiate(seed)
    parent.generate(24) // parent does some work, then forks
    const res = forkAndGenerate(parent.snapshot(), hexToBytes('11'.repeat(32)))
    expect(res.inheritedCollidesWithParent).toBe(true)
    expect(bytesToHex(res.childInherited)).toBe(bytesToHex(res.parentNext))
  })

  it('the child that reseeds with fresh entropy does not collide', () => {
    const parent = HmacDrbg.instantiate(seed)
    const res = forkAndGenerate(parent.snapshot(), hexToBytes('11'.repeat(32)))
    expect(res.reseededCollidesWithParent).toBe(false)
    expect(bytesToHex(res.childReseeded)).not.toBe(bytesToHex(res.parentNext))
  })
})
