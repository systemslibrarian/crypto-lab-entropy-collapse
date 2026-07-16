// A MODEL of low-entropy boot-time seeding. This is not a real /dev/random — it is
// an explicit, labelled reconstruction of the failure mode documented in the 2012
// "Mining Your Ps and Qs" survey: an embedded/headless machine boots, has almost no
// unpredictable input, and seeds its DRBG from little more than a coarse clock, a
// process id, and its own (public) MAC address.
//
// The DRBG that consumes this seed is the real, unmodified SP 800-90A HMAC_DRBG.
// Only the *entropy fed into it* is impoverished — which is exactly the point.

import { sha256 } from '../crypto/sha256'
import { HmacDrbg } from '../crypto/hmac_drbg'
import { concatBytes } from '../crypto/hex'

/** Linux default pid_max: process ids run 0..32767, i.e. 15 bits. */
export const PID_BITS = 15

/** Above this many unknown bits we refuse to enumerate live and say why (honest).
 *  At ~10k candidate DRBGs/second in a browser, 2^16 finishes in a few seconds; the
 *  larger stops are left un-run precisely so the slider shows where safety begins. */
export const ENUMERABLE_MAX_BITS = 16

/** Discrete slider stops, high entropy first. `full` seeds from the real CSPRNG. */
export interface EntropyStop {
  readonly bits: number
  readonly label: string
  readonly full: boolean
}

export const ENTROPY_STOPS: readonly EntropyStop[] = [
  { bits: 256, label: 'getrandom() — kernel CSPRNG, fully seeded', full: true },
  { bits: 64, label: '64-bit seed — strong PRNG, small seed', full: false },
  { bits: 40, label: 'millisecond clock + PID', full: false },
  { bits: 32, label: '32-bit seed — second-resolution clock + PID', full: false },
  { bits: 24, label: 'coarse clock + PID (headless server)', full: false },
  { bits: 16, label: 'boot-time: near-fixed clock, PID-dominated', full: false },
  { bits: 14, label: 'embedded boot: almost no clock jitter', full: false },
  { bits: 12, label: 'PID-only-class seed (illustrative)', full: false },
]

export interface BootModel {
  /** 6-byte hardware address — PUBLIC, known to any attacker on the wire. */
  readonly mac: Uint8Array
  /** Start of the plausible boot-time window the attacker searches from. */
  readonly baseTimeSec: number
  /** Effective unpredictable bits in the seed. This is the entropy the slider sets. */
  readonly unknownBits: number
}

/** 2^unknownBits as a BigInt so the UI can show the true (astronomical) size. */
export function keyspaceSize(unknownBits: number): bigint {
  return 1n << BigInt(unknownBits)
}

export function isEnumerable(unknownBits: number): boolean {
  return unknownBits <= ENUMERABLE_MAX_BITS
}

/** Split a secret index into a concrete (boot-time-offset, pid) pair. */
export function decodeSecret(secretIndex: number, unknownBits: number): { timeOffset: number; pid: number } {
  const pidBits = Math.min(PID_BITS, unknownBits)
  const pidMask = (1 << pidBits) - 1
  const pid = secretIndex & pidMask
  const timeOffset = pidBits >= 31 ? 0 : Math.floor(secretIndex / (pidMask + 1))
  return { timeOffset, pid }
}

/** Reconstruct the exact seed material bytes a booting machine would have hashed. */
export function bootMaterial(model: BootModel, secretIndex: number): Uint8Array {
  const { timeOffset, pid } = decodeSecret(secretIndex, model.unknownBits)
  const bootTime = (model.baseTimeSec + timeOffset) >>> 0
  const buf = new Uint8Array(4 + 2)
  const dv = new DataView(buf.buffer)
  dv.setUint32(0, bootTime) // 4-byte boot timestamp
  dv.setUint16(4, pid & 0xffff) // 2-byte process id
  // material = MAC (public) || timestamp || pid  — the classic weak seed.
  return concatBytes(model.mac, buf)
}

/** Derive the 32-byte DRBG seed from boot material (a real hash, not a placeholder). */
export function seedFromMaterial(material: Uint8Array): Uint8Array {
  return sha256(material)
}

/** Instantiate the real DRBG from a boot seed. No nonce/personalization: bare seed. */
export function drbgFromSeed(seed: Uint8Array): HmacDrbg {
  return HmacDrbg.instantiate(seed)
}

/** The public value a server would emit first (e.g. a handshake nonce). 16 bytes. */
export function publicNonceFromSeed(seed: Uint8Array): Uint8Array {
  return drbgFromSeed(seed).generate(16)
}

/**
 * Same 16-byte nonce as publicNonceFromSeed, computed on the fast path (no trailing
 * DRBG update). Used only to filter enumeration candidates at speed.
 */
export function candidateNonce(seed: Uint8Array): Uint8Array {
  return drbgFromSeed(seed).firstOutputBlock(16)
}

/** What the same server derives next and keeps secret: the session key. 32 bytes. */
export function sessionKeyFromSeed(seed: Uint8Array): Uint8Array {
  const drbg = drbgFromSeed(seed)
  drbg.generate(16) // the public nonce
  return drbg.generate(32) // the secret it never meant to reveal
}
