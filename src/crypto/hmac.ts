// HMAC-SHA256 (FIPS 198-1 / RFC 2104) built on the local SHA-256.
// Checked against the RFC 4231 test vectors in hmac.test.ts.

import { sha256, SHA256_BLOCK_BYTES } from './sha256'

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Keys longer than the block size are hashed first.
  let k = key
  if (k.length > SHA256_BLOCK_BYTES) k = sha256(k)

  const kPad = new Uint8Array(SHA256_BLOCK_BYTES)
  kPad.set(k)

  const ipad = new Uint8Array(SHA256_BLOCK_BYTES)
  const opad = new Uint8Array(SHA256_BLOCK_BYTES)
  for (let i = 0; i < SHA256_BLOCK_BYTES; i++) {
    ipad[i] = kPad[i] ^ 0x36
    opad[i] = kPad[i] ^ 0x5c
  }

  const inner = new Uint8Array(SHA256_BLOCK_BYTES + message.length)
  inner.set(ipad)
  inner.set(message, SHA256_BLOCK_BYTES)
  const innerHash = sha256(inner)

  const outer = new Uint8Array(SHA256_BLOCK_BYTES + innerHash.length)
  outer.set(opad)
  outer.set(innerHash, SHA256_BLOCK_BYTES)
  return sha256(outer)
}
