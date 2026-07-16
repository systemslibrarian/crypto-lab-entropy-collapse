import { describe, expect, it } from 'vitest'
import { HmacDrbg } from '../crypto/hmac_drbg'
import { hexToBytes, bytesToHex } from '../crypto/hex'
import { afterProperReseed, afterNoOpReseed } from './reseed'

const seed = hexToBytes('fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840')

describe('failed-reseed panel — the counter lies, the entropy tells the truth', () => {
  it('a proper reseed makes the output unpredictable to an attacker who knew the state', () => {
    const victim = HmacDrbg.instantiate(seed)
    victim.generate(32)
    const outcome = afterProperReseed(victim.snapshot(), hexToBytes('a1'.repeat(32)))
    expect(outcome.predictable).toBe(false)
    expect(bytesToHex(outcome.actual)).not.toBe(bytesToHex(outcome.attackerPredicted))
  })

  it('a silent no-op reseed leaves the output fully predictable', () => {
    const victim = HmacDrbg.instantiate(seed)
    victim.generate(32)
    const outcome = afterNoOpReseed(victim.snapshot())
    expect(outcome.predictable).toBe(true)
    expect(bytesToHex(outcome.actual)).toBe(bytesToHex(outcome.attackerPredicted))
  })

  it('the no-op reseed still resets the reseed counter to 1 — the health monitor is fooled', () => {
    const victim = HmacDrbg.instantiate(seed)
    victim.generate(32)
    const outcome = afterNoOpReseed(victim.snapshot())
    expect(outcome.reseedCounter).toBe(2) // reset to 1 by reseed, then +1 from one generate
  })
})
