# Entropy Collapse

**Seed provenance & RNG state duplication · NIST SP 800-90A / 90B / 90C**

A browser demo about the failure mode where the cryptography is flawless and the system
is compromised anyway. It runs a real, standards-conformant **HMAC_DRBG** (NIST SP
800-90A) and never modifies it. Everything alarming comes from the *seed*: duplicate it
and two machines become one; starve it and its entire output becomes guessable.

> The generator did nothing wrong. Nobody attacked it.

## What It Is

- **Primitives (real, hand-rolled, inspectable):** SHA-256 (FIPS 180-4), HMAC-SHA256
  (FIPS 198-1 / RFC 2104), and **HMAC_DRBG** (NIST SP 800-90A Rev. 1, §10.1.2) with
  SHA-256. These are checked against **NIST CAVP and RFC known-answer vectors** — see
  _Build & Verify_.
- **The problem:** SP 800-90A's guarantees are *conditional on the entropy input*. A DRBG
  is a deterministic function of its seed. If two machines share a seed (VM clone, forked
  process, low-entropy boot), they share every nonce and every key they will ever produce.
- **Security model:** a teaching demo, **not production crypto**. All key material is
  generated per session, in memory, and never stored or transmitted. The recoveries you
  run are genuine brute force against the real generator — they are only feasible because
  the *seed space* is modelled as small, never because a primitive is weak.
- **Verdict separation:** every panel shows two independent indicators — the
  **cryptographic result** (the DRBG is correct) and the **security verdict** (the system
  is compromised). Color tracks system integrity, so a byte-identical "match" renders as an
  **alarm**, never as green success.

## Exhibits

1. **Clone the machine, clone every secret** *(the headline)* — snapshot one DRBG's state,
   restore it onto Server A and Server B, and watch every nonce and key come out
   byte-identical. Separates the two consequences precisely: the shared **session key**
   ends confidentiality outright, while the shared **nonce** lets an attacker recover the
   ECDSA **signing (authentication) key** by algebra on two signatures — handed off to the
   sibling [ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/), not
   rebuilt here.
2. **Starve the seed, enumerate the key** *(break-it-yourself)* — a slider drops the seed's
   entropy from a 256-bit CSPRNG down to a headless boot; the search space collapses from
   2^256 to something enumerable; below 2^16 you brute-force the seed **live** against the
   real DRBG and recover the session key it kept secret.
3. **fork() safety** — a parent seeds, forks, and the child that forgets to reseed emits the
   parent's next output exactly; the child that reseeds does not.
4. **The reseed that wasn't** — a silent no-op reseed resets the reseed counter to look
   healthy while an attacker keeps predicting the output, because no fresh entropy went in.
5. **This already happened** — the Debian OpenSSL PRNG (CVE-2008-0166) and the 2012 "Mining
   Your Ps and Qs" survey, stated with exact numbers.

## When to Use It

- **Use it** to teach why entropy/seed provenance is a first-class security property, and
  why "the RNG passed its statistical tests" proves nothing about seed uniqueness.
- **Do NOT use it** as a source of randomness, a production DRBG, or evidence that any
  specific deployment is safe. It is a teaching model; the VM snapshot and boot-entropy
  pieces are explicitly labelled as models.

## Live Demo

`https://crypto-lab.systemslibrarian.dev/crypto-lab-entropy-collapse/` (deployed from
`main` via GitHub Pages). You can: run the clone and watch both streams stay identical,
diverge Server B with fresh entropy, drag the entropy slider and brute-force a real seed,
fork a process, and toggle a proper vs. no-op reseed — each with its own crypto-result and
security-verdict indicators, in dark or light theme.

## What Can Go Wrong

The whole demo is a catalogue of what goes wrong when the seed is not unique or not
unpredictable: cloned VM images, forked processes without post-fork reseed, boot-time
entropy holes, and reseeds whose entropy source silently fails. In every case the DRBG is
correct and the system is broken — which is the entire lesson.

## Real-World Usage

- **Debian OpenSSL, 2006–2008 (CVE-2008-0166):** a Debian patch left essentially only the
  process ID seeding the PRNG. With Linux's default max PID of 32,768, at most **32,767**
  distinct keys were possible per architecture/key-size. Keys generated from September 2006
  to 13 May 2008 were affected.
- **"Mining Your Ps and Qs" (Heninger, Durumeric, Wustrow, Halderman, USENIX Security
  2012):** **0.75%** of TLS certificates shared keys from insufficient entropy; the authors
  computed private **RSA** keys for **0.50%** of TLS hosts (GCD of shared moduli) and
  **0.03%** of SSH hosts, and private **DSA** keys for **1.03%** of SSH hosts (repeated
  signature nonces). Root cause: a boot-time entropy hole, overwhelmingly on headless/
  embedded devices.

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173
npm test           # unit tests + KATs
npm run build      # type-check + production bundle
npm run test:a11y  # axe-core WCAG A/AA gate (both themes) against the built site
```

## Related Demos

- [ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — nonce reuse
  and nonce collision recovering ECDSA signing keys (the downstream of the clone panel).
- [drbg-arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/) — DRBG internals
  and the SP 800-22 statistical suite (out of scope here).
- [corrupted-oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) — a
  *deliberately sabotaged* generator (malice, where this lab is accident).
- [Time Trust](https://systemslibrarian.github.io/crypto-lab-time-trust/) — an
  unauthenticated clock feeding an authenticated check: the same shape as an unauthenticated
  seed.

## Build & Verify

- **34 unit tests (Vitest), all passing**, including:
  - **8 NIST CAVP HMAC_DRBG (SHA-256) known-answer vectors** — all four
    personalization × additional-input option groups, each with reseed
    (`src/crypto/nist_drbg_vectors.ts`, run by `src/crypto/hmac_drbg.test.ts`).
  - **4 SHA-256 KATs** (FIPS 180-4) and **4 HMAC-SHA256 KATs** (RFC 4231).
  - Behavioural invariants: deterministic-in-seed, clone byte-equality, fork inheritance,
    no-op-reseed predictability, and live seed recovery against the real DRBG.
- **Accessibility gate:** `@axe-core/playwright` scans the production build for zero WCAG
  2.1 A/AA violations in **both** themes; the GitHub Pages deploy is blocked if it fails.

```bash
npm test && npm run build && npm run test:a11y
```

## Performance

Seed enumeration runs the real DRBG per candidate at roughly 10,000 candidates/second in a
browser, chunked so the UI stays responsive. Live recovery is capped at a 2^16 search space
(a few seconds); larger spaces report their projected time and are deliberately left un-run
to show where safety begins.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
