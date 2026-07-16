// THE HEADLINE MECHANISM. One machine's DRBG state, snapshotted and restored onto two
// machines, produces byte-identical output forever. We SHOW it: compute both streams
// and compare, step by step, with the security verdict separated from the raw result.

import { HmacDrbg } from '../crypto/hmac_drbg'
import { bytesToHex } from '../crypto/hex'
import { DEFAULT_SCRIPT, runClonedStreams, divergeAfterReseed } from '../model/clone'
import { clear, disclosure, el, hexBlock, indicatorPair, notThis, randomBytes } from './dom'
import { SIBLINGS } from './links'

const prefersReducedMotion = () =>
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

export function clonePanel(): HTMLElement {
  // A fresh, correctly-seeded victim machine. The DRBG here is the real, unmodified
  // SP 800-90A implementation — it does nothing wrong at any point.
  let snapshotHex = ''
  const victim = HmacDrbg.instantiate(randomBytes(32), randomBytes(16))
  victim.generate(8) // the machine runs for a bit, then an image is taken
  const snap = victim.snapshot()
  snapshotHex = bytesToHex(snap.K).slice(0, 24) + '… / ' + bytesToHex(snap.V).slice(0, 24) + '…'

  const panel = el('section', { class: 'panel', id: 'clone' }, [
    el('span', { class: 'panel-kicker' }, ['The headline']),
    el('h2', {}, ['Clone the machine, clone every secret']),
    el('p', { class: 'panel-lede' }, [
      'One virtual machine is running. We freeze it and restore the image onto two servers, ' +
        'A and B. They now hold the same DRBG state — the same (K, V). Watch what they generate.',
    ]),
  ])

  const machineState = el('div', { class: 'hexblock', style: 'margin-bottom:1rem' }, [
    'Restored DRBG state (K / V): ' + snapshotHex,
  ])
  panel.append(machineState)

  const controls = el('div', { class: 'controls' }, [])
  const runBtn = el('button', { class: 'action', type: 'button' }, ['Run the restored machines'])
  const divergeBtn = el(
    'button',
    { class: 'ghost', type: 'button', disabled: true },
    ['Give Server B its own entropy'],
  )
  controls.append(runBtn, divergeBtn)
  panel.append(controls)

  const streams = el('div', { class: 'streams' }, [])
  const colA = el('div', { class: 'stream', role: 'group', 'aria-label': 'Server A output' }, [
    el('h3', {}, ['Server A']),
  ])
  const colB = el('div', { class: 'stream', role: 'group', 'aria-label': 'Server B output' }, [
    el('h3', {}, ['Server B']),
  ])
  streams.append(colA, colB)
  panel.append(streams)

  const live = el('div', { role: 'status', 'aria-live': 'polite' }, [])
  panel.append(live)

  const consequences = el('div', {}, [])
  panel.append(consequences)

  function reset(): void {
    clear(colA)
    clear(colB)
    colA.append(el('h3', {}, ['Server A']))
    colB.append(el('h3', {}, ['Server B']))
    clear(live)
    clear(consequences)
  }

  async function run(): Promise<void> {
    reset()
    runBtn.disabled = true
    divergeBtn.disabled = true
    const cmp = runClonedStreams(snap, DEFAULT_SCRIPT)
    const stepDelay = prefersReducedMotion() ? 0 : 260

    for (const item of cmp.items) {
      const rowA = el('div', { class: 'stream-row' }, [
        el('span', { class: 'stream-label' }, [item.label]),
        hexBlock(item.a),
      ])
      const rowB = el('div', { class: 'stream-row' }, [
        el('span', { class: 'stream-label' }, [item.label]),
        hexBlock(item.b, item.a),
      ])
      colA.append(rowA)
      if (stepDelay) await new Promise((r) => setTimeout(r, stepDelay))
      colB.append(rowB)
      if (stepDelay) await new Promise((r) => setTimeout(r, stepDelay))
    }

    // The raw result: the two streams are byte-identical. Shown NEUTRAL, not green —
    // "identical" here is the alarm, not a success.
    const rawLine = el('p', { class: 'result-line' }, [
      'Byte-for-byte comparison of every field: ',
      el('span', { class: 'flag-alarm' }, ['IDENTICAL']),
      ' — the streams never diverge.',
    ])
    live.append(rawLine)

    live.append(
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
    )

    // Precise, separated consequences — confidentiality vs authentication.
    consequences.append(
      el('div', { class: 'callout' }, [
        el('p', {}, [
          el('strong', {}, ['Same session key → confidentiality is already gone. ']),
          'Server A and Server B hold the identical 32-byte session key. Anything either encrypts, ' +
            'the other (or anyone who cloned the image) can decrypt. No further attack is needed.',
        ]),
        el('p', {}, [
          el('strong', {}, ['Same nonce → the ECDSA signing key falls out. ']),
          'If either machine signs two different messages with ECDSA using this repeated nonce, an ' +
            'attacker recovers the private ',
          el('em', {}, ['signing (authentication) key']),
          ' — by simple algebra on the two signatures, ',
          el('strong', {}, ['not']),
          ' by breaking the curve. That recovery lives in the sibling lab: ',
          el('a', { href: SIBLINGS.ecdsaForge }, ['ecdsa-forge → nonce reuse']),
          '. A separate collision across two machines is the input to ',
          el('a', { href: SIBLINGS.ecdsaForge }, ['ecdsa-forge → nonce collision']),
          '.',
        ]),
      ]),
      disclosure(
        'For the expert: why they never diverge',
        el('p', {}, [
          'HMAC_DRBG output is a deterministic function of (K, V). Restoring the same (K, V) onto ' +
            'two instances makes them the same map from step index to output. Divergence requires ' +
            'new, machine-unique input to Update() — i.e. a reseed with fresh entropy. Absent that, ' +
            'the streams are equal at every index, and pass every SP 800-22 statistical test ' +
            'individually, because each stream is, on its own, perfectly good randomness.',
        ]),
      ),
    )

    runBtn.disabled = false
    divergeBtn.disabled = false
  }

  function diverge(): void {
    const res = divergeAfterReseed(snap, randomBytes(32))
    clear(consequences)
    const rowA = el('div', { class: 'stream-row' }, [
      el('span', { class: 'stream-label' }, ['Next nonce, Server A (no reseed)']),
      hexBlock(res.a),
    ])
    const rowB = el('div', { class: 'stream-row' }, [
      el('span', { class: 'stream-label' }, ['Next nonce, Server B (fresh entropy mixed in)']),
      hexBlock(res.b, res.a),
    ])
    colA.append(rowA)
    colB.append(rowB)
    clear(live)
    live.append(
      el('p', { class: 'result-line' }, [
        'After Server B mixes in one machine-unique entropy input: streams now ',
        el('span', { class: 'flag-neutral' }, ['DIVERGE']),
        '.',
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
          note: 'A single unpredictable byte of reseed material breaks the shared future. That byte is the whole job of the entropy source.',
        },
      ),
    )
  }

  runBtn.addEventListener('click', () => void run())
  divergeBtn.addEventListener('click', diverge)

  panel.append(
    notThis(
      'What this isn’t: a real hypervisor. The snapshot is a modeled copy of the DRBG’s working ' +
        'state, labelled as a model — the duplication, not the virtualization, is the point.',
    ),
  )
  return panel
}
