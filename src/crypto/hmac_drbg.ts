// HMAC_DRBG — NIST SP 800-90A Rev. 1, §10.1.2, instantiated with SHA-256.
//
// This is the real, uncompromised DRBG. It is NEVER modified anywhere in this lab
// — that is the entire point: an honest generator is a deterministic function of
// its seed. Everything alarming in this demo comes from what is fed to it or from
// duplicating its state, never from a flaw in the algorithm below.
//
// Verified against the NIST CAVP HMAC_DRBG.rsp known-answer vectors (SHA-256,
// PredictionResistance=False) in hmac_drbg.test.ts.

import { hmacSha256 } from './hmac'
import { concatBytes } from './hex'
import { SHA256_OUTPUT_BYTES } from './sha256'

const OUTLEN = SHA256_OUTPUT_BYTES // 32
const SEEDLEN = SHA256_OUTPUT_BYTES // for HMAC_DRBG with SHA-256, seedlen = outlen
export const RESEED_INTERVAL = 0x1000000000000 // 2^48, the SP 800-90A limit
export const MAX_BYTES_PER_GENERATE = 65536 // 2^19 bits / 8; spec ceiling per request

/** The full internal working state — snapshot/restore models a VM snapshot/clone. */
export interface DrbgState {
  readonly K: Uint8Array
  readonly V: Uint8Array
  readonly reseedCounter: number
}

export class HmacDrbg {
  private K: Uint8Array
  private V: Uint8Array
  private reseedCounter: number

  private constructor(K: Uint8Array, V: Uint8Array, reseedCounter: number) {
    this.K = K
    this.V = V
    this.reseedCounter = reseedCounter
  }

  /** SP 800-90A §10.1.2.2 — HMAC_DRBG_Update. */
  private update(providedData: Uint8Array): void {
    // 1. K = HMAC(K, V || 0x00 || provided_data)
    this.K = hmacSha256(this.K, concatBytes(this.V, new Uint8Array([0x00]), providedData))
    // 2. V = HMAC(K, V)
    this.V = hmacSha256(this.K, this.V)
    // 3. If provided_data is empty, return here (do not run the second pass).
    if (providedData.length === 0) return
    // 4. K = HMAC(K, V || 0x01 || provided_data)
    this.K = hmacSha256(this.K, concatBytes(this.V, new Uint8Array([0x01]), providedData))
    // 5. V = HMAC(K, V)
    this.V = hmacSha256(this.K, this.V)
  }

  /** SP 800-90A §10.1.2.3 — Instantiate. seedMaterial = entropy || nonce || pers. */
  static instantiate(
    entropyInput: Uint8Array,
    nonce: Uint8Array = new Uint8Array(0),
    personalization: Uint8Array = new Uint8Array(0),
  ): HmacDrbg {
    const K = new Uint8Array(OUTLEN) // 0x00 ... 0x00
    const V = new Uint8Array(OUTLEN).fill(0x01) // 0x01 ... 0x01
    const drbg = new HmacDrbg(K, V, 1)
    drbg.update(concatBytes(entropyInput, nonce, personalization))
    drbg.reseedCounter = 1
    return drbg
  }

  /** SP 800-90A §10.1.2.4 — Reseed. seedMaterial = entropy || additionalInput. */
  reseed(entropyInput: Uint8Array, additionalInput: Uint8Array = new Uint8Array(0)): void {
    this.update(concatBytes(entropyInput, additionalInput))
    this.reseedCounter = 1
  }

  /** SP 800-90A §10.1.2.5 — Generate. Returns numBytes of output. */
  generate(numBytes: number, additionalInput: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (numBytes < 0 || numBytes > MAX_BYTES_PER_GENERATE) {
      throw new RangeError(`generate: numBytes must be within [0, ${MAX_BYTES_PER_GENERATE}]`)
    }
    if (this.reseedCounter > RESEED_INTERVAL) {
      // Fail closed: a correct consumer MUST reseed before continuing.
      throw new Error('HMAC_DRBG: reseed required (reseed_counter exceeded 2^48)')
    }

    if (additionalInput.length > 0) this.update(additionalInput)

    const out = new Uint8Array(numBytes)
    let produced = 0
    while (produced < numBytes) {
      this.V = hmacSha256(this.K, this.V)
      const take = Math.min(OUTLEN, numBytes - produced)
      out.set(this.V.subarray(0, take), produced)
      produced += take
    }

    // Final update mixes additionalInput back in (empty => single-pass update).
    this.update(additionalInput)
    this.reseedCounter += 1
    return out
  }

  /**
   * The first block that generate(numBytes) would emit, for numBytes <= 32, WITHOUT
   * performing the trailing state update. Equals generate(numBytes) sliced to numBytes
   * for a fresh instance. Used by seed enumeration to filter candidates quickly — the
   * attacker only needs to recognise the published nonce, not maintain DRBG bookkeeping.
   */
  firstOutputBlock(numBytes: number): Uint8Array {
    if (numBytes < 0 || numBytes > OUTLEN) {
      throw new RangeError(`firstOutputBlock: numBytes must be within [0, ${OUTLEN}]`)
    }
    return hmacSha256(this.K, this.V).subarray(0, numBytes)
  }

  /** Snapshot the working state. Models freezing a VM: everything needed to resume. */
  snapshot(): DrbgState {
    return {
      K: this.K.slice(),
      V: this.V.slice(),
      reseedCounter: this.reseedCounter,
    }
  }

  /** Restore a DRBG from a snapshot. Two restores of one snapshot are byte-identical. */
  static fromSnapshot(state: DrbgState): HmacDrbg {
    return new HmacDrbg(state.K.slice(), state.V.slice(), state.reseedCounter)
  }

  /** Read-only views for the inspector UI. Copies, so the caller can't mutate state. */
  get state(): DrbgState {
    return this.snapshot()
  }

  getReseedCounter(): number {
    return this.reseedCounter
  }

  get seedLength(): number {
    return SEEDLEN
  }
}
