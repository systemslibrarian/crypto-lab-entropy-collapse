// THE HEADLINE MECHANISM, shown — not asserted. Two machines are restored from one DRBG
// snapshot and stepped in lockstep. You watch their internal (K, V) state stay identical
// and their output blocks drop in perfect sync, because DRBG output is a deterministic
// function of that state. The security verdict is kept separate from the raw result.

import { HmacDrbg, type DrbgState } from '../crypto/hmac_drbg'
import { bytesToHex } from '../crypto/hex'
import { DEFAULT_SCRIPT } from '../model/clone'
import {
  abbrevHex,
  clear,
  compareHexBlock,
  disclosure,
  el,
  hexBlock,
  indicatorPair,
  notThis,
  randomBytes,
} from './dom'
import { SIBLINGS } from './links'

const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

export function clonePanel(): HTMLElement {
  // A correctly-seeded machine runs for a moment; then an image is taken. The DRBG is the
  // real, unmodified SP 800-90A implementation and does nothing wrong at any step.
  const origin = HmacDrbg.instantiate(randomBytes(32), randomBytes(16))
  origin.generate(8)
  const snap = origin.snapshot()

  let a: HmacDrbg | null = null
  let b: HmacDrbg | null = null
  let stepIdx = 0
  let diverged = false
  let autoRunning = false

  const panel = el('section', { class: 'panel', id: 'clone' }, [
    el('span', { class: 'panel-kicker' }, ['The headline']),
    el('h2', {}, ['Clone the machine, clone every secret']),
    el('p', { class: 'panel-lede' }, [
      'One virtual machine is running. Freeze it, restore the image onto two servers, and step ' +
        'them together. Watch the internal generator state (K, V) load identically, then watch every ' +
        'nonce and key drop in lockstep — not similar, identical, forever.',
    ]),
  ])

  // --- the two machines ---
  const machineA = machineCard('A')
  const machineB = machineCard('B')
  const stage = el('div', { class: 'machines' }, [machineA.root, machineB.root])
  panel.append(stage)

  // --- controls ---
  const setupBtn = el('button', { class: 'action', type: 'button' }, ['Snapshot & restore'])
  const stepBtn = el('button', { class: 'ghost', type: 'button' }, ['Step ▸'])
  const autoBtn = el('button', { class: 'ghost', type: 'button' }, ['Auto-run ▸▸'])
  const divergeBtn = el('button', { class: 'ghost', type: 'button' }, [
    'Give Server B its own entropy',
  ])
  panel.append(el('div', { class: 'controls' }, [setupBtn, stepBtn, autoBtn, divergeBtn]))

  const live = el('div', { role: 'status', 'aria-live': 'polite' }, [])
  panel.append(live)
  const verdictHost = el('div', {}, [])
  panel.append(verdictHost)

  function renderState(): void {
    if (!a || !b) return
    const sa = a.state
    const sb = b.state
    machineA.setState(sa)
    machineB.setState(sb, sa)
    const same = bytesToHex(sa.K) === bytesToHex(sb.K) && bytesToHex(sa.V) === bytesToHex(sb.V)
    machineA.setSync(same, 'A')
    machineB.setSync(same, 'B')
  }

  function setup(): void {
    a = HmacDrbg.fromSnapshot(snap)
    b = HmacDrbg.fromSnapshot(snap)
    stepIdx = 0
    diverged = false
    machineA.reset()
    machineB.reset()
    clear(live)
    clear(verdictHost)
    renderState()
    live.append(
      el('p', { class: 'result-line' }, [
        'Both servers restored from the same image. Internal state (K, V): ',
        el('span', { class: 'flag-alarm' }, ['IDENTICAL']),
        '. Nothing has been generated yet — press Step.',
      ]),
    )
    stepBtn.disabled = false
    autoBtn.disabled = false
    divergeBtn.disabled = false
  }

  function labelIsSecret(label: string): boolean {
    return /key/i.test(label)
  }

  function step(): boolean {
    if (!a || !b) setup()
    if (!a || !b || stepIdx >= DEFAULT_SCRIPT.length) return false
    const item = DEFAULT_SCRIPT[stepIdx]
    const outA = a.generate(item.bytes)
    const outB = b.generate(item.bytes)
    machineA.log(item.label, hexBlock(outA))
    // B is always compared to A: highlight the matches while they hold, the changes once
    // Server B has its own entropy — both in a calm tone, never alarm-red.
    machineB.log(item.label, compareHexBlock(outB, outA, diverged ? 'diff' : 'match'))
    stepIdx++
    renderState()

    if (!diverged && labelIsSecret(item.label)) showCollapseVerdict()
    if (diverged) showRestoredVerdict()

    const done = stepIdx >= DEFAULT_SCRIPT.length
    stepBtn.disabled = done
    autoBtn.disabled = done
    return !done
  }

  async function auto(): Promise<void> {
    if (autoRunning) return
    if (!a || !b) setup()
    autoRunning = true
    stepBtn.disabled = true
    autoBtn.disabled = true
    const delay = reducedMotion() ? 0 : 550
    while (step()) {
      if (delay) await new Promise((r) => setTimeout(r, delay))
    }
    autoRunning = false
  }

  function diverge(): void {
    // Restart from the identical snapshot, but give Server B one machine-unique input.
    a = HmacDrbg.fromSnapshot(snap)
    b = HmacDrbg.fromSnapshot(snap)
    b.reseed(randomBytes(32))
    stepIdx = 0
    diverged = true
    machineA.reset()
    machineB.reset()
    clear(live)
    clear(verdictHost)
    renderState()
    live.append(
      el('p', { class: 'result-line' }, [
        'Server B mixed in one unpredictable entropy input. Internal state now ',
        el('span', { class: 'flag-neutral' }, ['DIFFERS']),
        ' — step to watch the streams part ways.',
      ]),
    )
    void auto()
  }

  function showCollapseVerdict(): void {
    clear(verdictHost)
    verdictHost.append(
      el('p', { class: 'result-line' }, [
        'Byte-for-byte comparison of every field so far: ',
        el('span', { class: 'flag-alarm' }, ['IDENTICAL']),
        ' — the streams never diverge.',
      ]),
      indicatorPair(
        {
          label: 'Cryptographic result',
          icon: '✓',
          value: 'HMAC_DRBG operating correctly',
          note: 'Both machines ran the real SP 800-90A generator exactly as specified. No fault, no attacker.',
        },
        {
          state: 'collapsed',
          label: 'Security verdict',
          icon: '✗',
          value: 'INTEGRITY COLLAPSED',
          note: 'Two independent machines share every nonce and every key. The system is compromised even though the primitive is flawless.',
        },
      ),
      consequenceCallout(),
      disclosure(
        'For the expert: why they never diverge',
        el('p', {}, [
          'HMAC_DRBG output is a deterministic function of (K, V). Restoring the same (K, V) onto two ' +
            'instances makes them the same map from step index to output. Divergence requires new, ' +
            'machine-unique input to Update() — a reseed with fresh entropy. Absent that, the streams ' +
            'are equal at every index, and each stream passes every SP 800-22 statistical test on its ' +
            'own, because each is, individually, perfectly good randomness.',
        ]),
      ),
    )
  }

  function showRestoredVerdict(): void {
    clear(verdictHost)
    verdictHost.append(
      el('p', { class: 'result-line' }, [
        'Comparison after Server B’s fresh entropy: streams ',
        el('span', { class: 'flag-neutral' }, ['DIVERGE']),
        ' from the first block.',
      ]),
      indicatorPair(
        {
          label: 'Cryptographic result',
          icon: '✓',
          value: 'Same DRBG, same code',
          note: 'Nothing about the algorithm changed — only the input did.',
        },
        {
          state: 'intact',
          label: 'Security verdict',
          icon: '✓',
          value: 'INTEGRITY RESTORED',
          note: 'One unpredictable byte of reseed material breaks the shared future. That byte is the whole job of the entropy source.',
        },
      ),
    )
  }

  setupBtn.addEventListener('click', setup)
  stepBtn.addEventListener('click', () => void step())
  autoBtn.addEventListener('click', () => void auto())
  divergeBtn.addEventListener('click', diverge)

  panel.append(
    notThis(
      'What this isn’t: a real hypervisor. The snapshot is a modeled copy of the DRBG’s working ' +
        'state, labelled as a model — the duplication, not the virtualization, is the point.',
    ),
  )
  return panel
}

// --- precise, separated downstream consequences (confidentiality vs authentication) ---
function consequenceCallout(): HTMLElement {
  return el('div', { class: 'callout' }, [
    el('p', {}, [
      el('strong', {}, ['Same session key → confidentiality is already gone. ']),
      'Server A and Server B hold the identical 32-byte session key. Anything either encrypts, the ' +
        'other (or anyone who cloned the image) can decrypt. No further attack is needed.',
    ]),
    el('p', {}, [
      el('strong', {}, ['Same nonce → the ECDSA signing key falls out. ']),
      'If either machine signs two different messages with ECDSA using this repeated nonce, an ' +
        'attacker recovers the private ',
      el('em', {}, ['signing (authentication) key']),
      ' by simple algebra on the two signatures — ',
      el('strong', {}, ['not']),
      ' by breaking the curve. That recovery lives in the sibling lab: ',
      el('a', { href: SIBLINGS.ecdsaForge }, ['ecdsa-forge → nonce reuse']),
      '. A collision across two machines is the input to ',
      el('a', { href: SIBLINGS.ecdsaForge }, ['ecdsa-forge → nonce collision']),
      '.',
    ]),
  ])
}

// --- one machine card with a live state readout and an output log ---
interface MachineCard {
  root: HTMLElement
  setState: (s: DrbgState, compare?: DrbgState) => void
  setSync: (same: boolean, which: 'A' | 'B') => void
  log: (label: string, valueNode: HTMLElement) => void
  reset: () => void
}

function machineCard(which: 'A' | 'B'): MachineCard {
  const kChip = el('code', { class: 'state-hex' }, ['—'])
  const vChip = el('code', { class: 'state-hex' }, ['—'])
  const sync = el('span', { class: 'sync-badge', 'data-sync': 'idle' }, ['awaiting restore'])
  const logEl = el('div', {
    class: 'machine-log',
    role: 'log',
    'aria-label': `Server ${which} output`,
  })

  const root = el('div', { class: 'machine' }, [
    el('div', { class: 'machine-head' }, [
      el('span', { class: 'machine-glyph', 'aria-hidden': 'true' }, ['🖥']),
      el('h3', {}, [`Server ${which}`]),
      sync,
    ]),
    el('div', { class: 'machine-state' }, [
      el('div', {}, [el('span', { class: 'sk' }, ['K']), kChip]),
      el('div', {}, [el('span', { class: 'sk' }, ['V']), vChip]),
    ]),
    logEl,
  ])

  return {
    root,
    setState(s, compare) {
      const kDiff = compare && bytesToHex(compare.K) !== bytesToHex(s.K)
      const vDiff = compare && bytesToHex(compare.V) !== bytesToHex(s.V)
      kChip.textContent = abbrevHex(s.K)
      vChip.textContent = abbrevHex(s.V)
      kChip.className = 'state-hex' + (kDiff ? ' diverged' : '')
      vChip.className = 'state-hex' + (vDiff ? ' diverged' : '')
    },
    setSync(same, w) {
      sync.setAttribute('data-sync', same ? 'same' : 'diff')
      sync.textContent =
        w === 'A'
          ? same
            ? 'state loaded'
            : 'independent state'
          : same
            ? '≡ identical to A'
            : '≠ differs from A'
    },
    log(label, valueNode) {
      logEl.append(
        el('div', { class: 'log-row' }, [el('span', { class: 'log-label' }, [label]), valueNode]),
      )
    },
    reset() {
      clear(logEl)
      kChip.textContent = '—'
      vChip.textContent = '—'
      kChip.className = 'state-hex'
      vChip.className = 'state-hex'
      sync.setAttribute('data-sync', 'idle')
      sync.textContent = 'restored'
    },
  }
}
