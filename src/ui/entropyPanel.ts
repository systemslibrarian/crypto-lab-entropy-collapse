// The break-it-yourself panel. Drag the entropy down and, when the search space is
// small enough, brute-force the seed LIVE against the real DRBG and recover the key
// the machine kept secret. Nothing is faked: every candidate runs the real generator.

import { bytesToHex } from '../crypto/hex'
import {
  ENTROPY_STOPS,
  ENUMERABLE_MAX_BITS,
  bootMaterial,
  decodeSecret,
  isEnumerable,
  keyspaceSize,
  publicNonceFromSeed,
  seedFromMaterial,
  sessionKeyFromSeed,
  type BootModel,
} from '../entropy/boot'
import { recoverBatch } from '../entropy/enumerate'
import { clear, disclosure, el, hexBlock, indicatorPair, notThis, randomBytes } from './dom'

const MAC = new Uint8Array([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]) // locally-administered VM MAC
const BASE_TIME = 1_704_067_200 // 2024-01-01T00:00:00Z, a plausible boot window start
const GUESS_RATE = 10_000 // conservative candidate-DRBGs/second, for honest time estimates

const macStr = Array.from(MAC, (b) => b.toString(16).padStart(2, '0')).join(':')

function formatDuration(seconds: number): string {
  if (seconds < 1) return 'under a second'
  const units: [string, number][] = [
    ['year', 31_557_600],
    ['day', 86_400],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ]
  for (const [name, size] of units) {
    if (seconds >= size) {
      const n = seconds / size
      if (n >= 1e6) return `${n.toExponential(1)} ${name}s`
      return `${n >= 100 ? Math.round(n) : n.toFixed(1)} ${name}s`
    }
  }
  return `${seconds.toFixed(0)} seconds`
}

function keyspaceLabel(bits: number): string {
  if (bits <= 53) return `2^${bits} = ${keyspaceSize(bits).toLocaleString('en-US')}`
  const approx = Math.pow(2, bits)
  return `2^${bits} ≈ ${approx.toExponential(2)}`
}

interface Victim {
  bits: number
  full: boolean
  seed: Uint8Array
  material: Uint8Array | null
  secretIndex: number
  nonce: Uint8Array
  sessionKey: Uint8Array
}

function makeVictim(stopIndex: number): Victim {
  const stop = ENTROPY_STOPS[stopIndex]
  if (stop.full) {
    const seed = randomBytes(32)
    return {
      bits: stop.bits,
      full: true,
      seed,
      material: null,
      secretIndex: -1,
      nonce: publicNonceFromSeed(seed),
      sessionKey: sessionKeyFromSeed(seed),
    }
  }
  const space = stop.bits >= 31 ? 2 ** 31 : 1 << stop.bits
  // A uniform true secret within the (possibly tiny) space the machine actually had.
  const r = new DataView(randomBytes(4).buffer).getUint32(0)
  const secretIndex = r % space
  const material = bootMaterial({ mac: MAC, baseTimeSec: BASE_TIME, unknownBits: stop.bits }, secretIndex)
  const seed = seedFromMaterial(material)
  return {
    bits: stop.bits,
    full: false,
    seed,
    material,
    secretIndex,
    nonce: publicNonceFromSeed(seed),
    sessionKey: sessionKeyFromSeed(seed),
  }
}

export function entropyPanel(): HTMLElement {
  let stopIndex = ENTROPY_STOPS.findIndex((s) => s.bits === 14)
  let victim = makeVictim(stopIndex)
  let running = false
  let cancel = false

  const panel = el('section', { class: 'panel', id: 'entropy' }, [
    el('span', { class: 'panel-kicker' }, ['Break it yourself']),
    el('h2', {}, ['Starve the seed, enumerate the key']),
    el('p', { class: 'panel-lede' }, [
      'The DRBG is only as unpredictable as its seed. Slide the entropy from a fully-seeded ' +
        'kernel CSPRNG down to a headless machine that boots with almost nothing, watch the search ' +
        'space collapse, then — when it is small enough — try every seed the machine could have had ' +
        'until the real generator reproduces the nonce it published. That recovers everything after it.',
    ]),
  ])

  // --- entropy slider ---
  const slider = el('input', {
    type: 'range',
    min: '0',
    max: String(ENTROPY_STOPS.length - 1),
    value: String(stopIndex),
    step: '1',
    id: 'entropy-slider',
    'aria-describedby': 'entropy-readout',
  }) as HTMLInputElement
  const sliderLabel = el('label', { class: 'field', for: 'entropy-slider' }, [
    'Effective seed entropy (drag left to starve it)',
  ])
  panel.append(sliderLabel, slider)

  const readout = el('div', { class: 'keyspace', id: 'entropy-readout' }, [])
  panel.append(readout)

  // --- seed material + published nonce ---
  const material = el('div', { role: 'group', 'aria-label': 'Observed values' }, [])
  panel.append(material)

  // --- recover controls ---
  const controls = el('div', { class: 'controls' }, [])
  const recoverBtn = el('button', { class: 'action', type: 'button' }, ['Run seed recovery'])
  const regenBtn = el('button', { class: 'ghost', type: 'button' }, ['New victim machine'])
  controls.append(recoverBtn, regenBtn)
  panel.append(controls)

  const progressWrap = el('div', {}, [])
  panel.append(progressWrap)

  const result = el('div', { role: 'status', 'aria-live': 'polite' }, [])
  panel.append(result)

  function humanScale(bits: number): string {
    if (bits >= 200) return 'more seeds than there are atoms in the observable universe'
    if (bits >= 100) return 'unreachable by any computer that could ever be built'
    if (bits >= 64) return 'beyond practical brute force'
    if (bits >= 40) return 'years of dedicated compute to sweep'
    if (bits >= 24) return 'minutes to hours on one laptop'
    return 'a sweep you can watch finish in this browser tab'
  }

  function renderReadout(): void {
    clear(readout)
    const stop = ENTROPY_STOPS[stopIndex]
    const fill = Math.max(2, Math.round((stop.bits / 256) * 100))
    readout.append(
      el('p', {}, [
        el('span', { class: 'ks-figure' }, [keyspaceLabel(stop.bits)]),
        '  possible seeds',
      ]),
      el('div', { class: 'ks-meter', role: 'presentation' }, [
        el('span', { style: `width:${fill}%` }),
      ]),
      el('p', { style: 'margin:.3rem 0 0;color:var(--text-dim)' }, [
        stop.label,
        ' — ',
        el('em', {}, [humanScale(stop.bits)]),
        '.',
      ]),
    )
    if (stop.full) {
      readout.append(
        el('p', { class: 'result-line' }, [
          'Not enumerable: 2^256 candidates is more than the atoms in the observable universe. ',
          el('span', { class: 'flag-neutral' }, ['This is the entropy that protects you.']),
        ]),
      )
    } else if (!isEnumerable(stop.bits)) {
      const secs = Math.pow(2, stop.bits) / GUESS_RATE
      readout.append(
        el('p', { class: 'result-line' }, [
          `At ~${GUESS_RATE.toLocaleString('en-US')} candidate generators/second in this browser, ` +
            `a full sweep would take about ${formatDuration(secs)} — too long to watch here.`,
        ]),
      )
    } else {
      const secs = Math.pow(2, stop.bits) / GUESS_RATE
      readout.append(
        el('p', { class: 'result-line' }, [
          el('span', { class: 'flag-alarm' }, ['Small enough to enumerate live']),
          ` — about ${formatDuration(secs)} to sweep all ${keyspaceSize(stop.bits).toLocaleString('en-US')}.`,
        ]),
      )
    }
  }

  function renderMaterial(): void {
    clear(material)
    if (victim.full) {
      material.append(
        el('p', { class: 'stream-label' }, ['Seed source']),
        el('div', { class: 'hexblock' }, ['getrandom() — 256 bits from the kernel CSPRNG (not shown)']),
        el('p', { class: 'stream-label', style: 'margin-top:.7rem' }, [
          'Published nonce (public, on the wire)',
        ]),
        hexBlock(victim.nonce),
      )
      return
    }
    const { timeOffset, pid } = decodeSecret(victim.secretIndex, victim.bits)
    const bootDate = new Date((BASE_TIME + timeOffset) * 1000).toISOString().replace('.000Z', 'Z')
    material.append(
      el('p', { class: 'stream-label' }, ['Boot seed material = MAC ‖ boot-time ‖ PID (a real hash of these)']),
      el('table', { class: 'facts' }, [
        el('tbody', {}, [
          el('tr', {}, [el('th', {}, ['MAC address (public)']), el('td', {}, [macStr])]),
          el('tr', {}, [el('th', {}, ['Boot time']), el('td', {}, [bootDate])]),
          el('tr', {}, [el('th', {}, ['Process ID']), el('td', {}, [String(pid)])]),
          el('tr', {}, [
            el('th', {}, ['12-byte seed material']),
            el('td', { style: 'font-family:var(--mono);font-size:.8rem;word-break:break-all' }, [
              bytesToHex(victim.material!),
            ]),
          ]),
        ]),
      ]),
      el('p', { class: 'stream-label', style: 'margin-top:.7rem' }, [
        'Published nonce (public, on the wire) — what the attacker sees',
      ]),
      hexBlock(victim.nonce),
    )
  }

  function updateButtons(): void {
    const stop = ENTROPY_STOPS[stopIndex]
    const canRun = !victim.full && isEnumerable(stop.bits) && !running
    recoverBtn.disabled = !canRun
    if (victim.full || !isEnumerable(stop.bits)) {
      recoverBtn.title = `Search space too large to enumerate live (limit 2^${ENUMERABLE_MAX_BITS}).`
    } else {
      recoverBtn.title = ''
    }
  }

  function refresh(regenVictim: boolean): void {
    if (regenVictim) victim = makeVictim(stopIndex)
    clear(result)
    clear(progressWrap)
    renderReadout()
    renderMaterial()
    updateButtons()
  }

  async function recover(): Promise<void> {
    if (running) return
    running = true
    cancel = false
    updateButtons()
    clear(result)
    clear(progressWrap)

    const model: BootModel = { mac: MAC, baseTimeSec: BASE_TIME, unknownBits: victim.bits }
    const total = 1 << victim.bits
    const bar = el('span', {}) as HTMLElement
    const progress = el('div', { class: 'progress', role: 'presentation' }, [bar])
    const ticker = el('div', { class: 'ticker', 'aria-hidden': 'true' }, ['booting candidate machines…'])
    const pctLabel = el('p', { class: 'result-line', role: 'status', 'aria-live': 'polite' }, [
      'Enumerating candidate seeds…',
    ])
    progressWrap.append(pctLabel, progress, ticker)

    let from = 0
    const batch = 1024
    const t0 = performance.now()
    // Chunked sweep so the UI stays responsive; each batch runs the REAL DRBG.
    while (from < total && !cancel) {
      const res = recoverBatch(victim.nonce, model, from, batch)

      if (res.found) {
        const secs = (performance.now() - t0) / 1000
        bar.style.width = '100%'
        ticker.textContent = ''
        renderSuccess(res.seed!, res.sessionKey!, res.secretIndex, from + res.tried, secs)
        running = false
        updateButtons()
        return
      }

      from += res.tried
      const pct = Math.min(100, Math.round((from / total) * 100))
      const secs = (performance.now() - t0) / 1000
      const rate = secs > 0 ? Math.round(from / secs) : 0
      bar.style.width = pct + '%'
      // Show the actual (boot-time, PID) the attacker is currently trying — the sweep is
      // literally rebooting the machine with every possible clock/PID until one matches.
      const { timeOffset, pid } = decodeSecret(from, victim.bits)
      const t = new Date((BASE_TIME + timeOffset) * 1000).toISOString().slice(11, 19)
      ticker.textContent = `trying boot @ ${t}, PID ${pid}`
      pctLabel.textContent =
        `Tried ${from.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} seeds ` +
        `(${pct}%) · ~${rate.toLocaleString('en-US')} candidate generators/sec…`
      await new Promise((r) => setTimeout(r, 0))
    }

    running = false
    updateButtons()
    if (cancel) {
      pctLabel.textContent = 'Recovery cancelled.'
      ticker.textContent = ''
    }
  }

  function renderSuccess(
    seed: Uint8Array,
    sessionKey: Uint8Array,
    secretIndex: number,
    tried: number,
    secs: number,
  ): void {
    clear(result)
    const correct = bytesToHex(sessionKey) === bytesToHex(victim.sessionKey)
    const { timeOffset, pid } = decodeSecret(secretIndex, victim.bits)
    const bootDate = new Date((BASE_TIME + timeOffset) * 1000).toISOString().replace('.000Z', 'Z')
    result.append(
      el('div', { class: 'cracked' }, [
        el('span', { class: 'cracked-tag', 'aria-hidden': 'true' }, ['🔓 SEED CRACKED']),
        el('span', {}, [`This machine booted at ${bootDate} as PID ${pid}.`]),
      ]),
      el('p', { class: 'result-line' }, [
        `Recovered the seed after ${tried.toLocaleString('en-US')} guesses in ${secs.toFixed(2)}s. ` +
          'The real DRBG, re-seeded with it, reproduces the published nonce exactly.',
      ]),
      el('p', { class: 'stream-label', style: 'margin-top:.6rem' }, ['Recovered 32-byte seed']),
      hexBlock(seed),
      el('p', { class: 'stream-label', style: 'margin-top:.6rem' }, [
        'Recovered session key (the value the machine meant to keep secret)',
      ]),
      hexBlock(sessionKey, correct ? undefined : victim.sessionKey),
      indicatorPair(
        {
          label: 'Cryptographic result',
          icon: '✓',
          value: 'DRBG reproduced bit-for-bit',
          note: 'The generator behaved perfectly — that is exactly why replaying its seed reconstructs its whole output.',
        },
        {
          state: 'collapsed',
          label: 'Security verdict',
          icon: '✗',
          value: 'KEY RECOVERED',
          note: 'With the seed known, every value the generator ever produces from it is known — including this session key. Not one bit of the algorithm was broken.',
        },
      ),
      disclosure(
        'For the expert: what recovery does and does not prove',
        el('p', {}, [
          'This recovers the DRBG seed by brute force over a modelled low-entropy boot space, then ' +
            'derives forward. It does not attack SHA-256, HMAC, or HMAC_DRBG — SP 800-90A explicitly ' +
            'makes its guarantees conditional on the entropy input, and here that input is impoverished. ' +
            'The recovered value is the generator’s entire output stream, so any key derived from it ' +
            '(session, signing, encryption) is equally exposed.',
        ]),
      ),
    )
  }

  slider.addEventListener('input', () => {
    if (running) {
      cancel = true
      running = false
    }
    stopIndex = Number(slider.value)
    refresh(true)
  })
  recoverBtn.addEventListener('click', () => void recover())
  regenBtn.addEventListener('click', () => refresh(true))

  refresh(false)
  panel.append(
    notThis(
      'What this isn’t: an attack on the DRBG or its hash. The math is intact; only the seed is ' +
        'guessable. It is also not a statistical-quality test — see ' +
        'drbg-arena for SP 800-22.',
    ),
  )
  return panel
}
