// fork() safety, shown as a tree. A parent seeds the real DRBG and forks. Both children
// inherit an exact copy of its (K, V). Step them together: the child that reseeds diverges
// from the parent; the child that forgets emits the parent's next output, byte for byte.

import { HmacDrbg, type DrbgState } from '../crypto/hmac_drbg'
import { bytesToHex } from '../crypto/hex'
import { clear, compareHexBlock, consequenceStrip, el, hexBlock, indicatorPair, notThis, randomBytes } from './dom'
import { stateCard } from './machine'

const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

const SCRIPT = [
  { label: 'Next nonce (public)', bytes: 16 },
  { label: 'Next key (secret)', bytes: 32 },
]

function countMatching(a: Uint8Array, b: Uint8Array): number {
  let n = 0
  for (let i = 0; i < a.length; i++) if (a[i] === b[i]) n++
  return n
}

/**
 * A child's output, compared against the parent's. Both children highlight the bytes that
 * MATCH the parent, so the collision is the loud card and the reseeded child is the quiet
 * one — and both carry an explicit "N of M bytes match" tally, so identical-vs-different is
 * a number the reader can check rather than a colour density the eye has to integrate.
 */
function childOutput(out: Uint8Array, parentOut: Uint8Array): HTMLElement {
  const same = countMatching(out, parentOut)
  const identical = same === out.length
  return el('div', {}, [
    compareHexBlock(out, parentOut, 'match'),
    el('p', { class: 'byte-tally', 'data-tone': identical ? 'alarm' : 'ok' }, [
      `${same} of ${out.length} bytes match the parent`,
      identical ? ' — the parent’s secret, byte for byte' : '',
    ]),
  ])
}

export function forkPanel(): HTMLElement {
  let forkState: DrbgState | null = null
  let childFresh = randomBytes(32)
  let parent: HmacDrbg | null = null
  let inherited: HmacDrbg | null = null
  let reseeded: HmacDrbg | null = null
  let stepIdx = 0
  let running = false

  const panel = el('section', { class: 'panel', id: 'fork' }, [
    el('span', { class: 'panel-kicker' }, ['Chapter 2 · fork() safety']),
    el('h2', {}, ['A child inherits the parent’s next secret']),
    el('p', { class: 'panel-lede' }, [
      'fork() hands the child a byte-perfect copy of the parent’s DRBG state — so the child that ' +
        'forgets to reseed emits the parent’s next secret exactly.',
    ]),
  ])
  panel.append(
    consequenceStrip([['child skips reseed', 'it emits the parent’s next nonce and key']]),
  )

  const parentCard = stateCard('Parent process', '🌱', 'Parent process output')
  const inheritedCard = stateCard('Child — no reseed', '🧬', 'Inherited child output')
  const reseededCard = stateCard('Child — reseeded', '🎲', 'Reseeded child output')

  const tree = el('div', { class: 'fork-tree' }, [
    el('div', { class: 'fork-parent' }, [parentCard.root]),
    el('div', { class: 'fork-split', 'aria-hidden': 'true' }, [
      el('span', { class: 'fork-branch' }),
      el('span', { class: 'fork-node' }, ['fork()']),
      el('span', { class: 'fork-branch' }),
    ]),
    el('div', { class: 'fork-children' }, [inheritedCard.root, reseededCard.root]),
  ])
  panel.append(tree)
  panel.append(
    el('p', { class: 'fork-legend' }, [
      'In both child cards, highlighted bytes are the ones that ',
      el('em', {}, ['match']),
      ' the parent’s output, and each output carries a match tally. A child that did not reseed ' +
        'scores every byte. A child that reseeded scores 0 or near it — its bytes are independent ' +
        'of the parent’s, so each one still coincides by chance with probability 1 in 256, which ' +
        'makes an occasional 1 or 2 expected rather than a failure.',
    ]),
  )

  const forkBtn = el('button', { class: 'action', type: 'button' }, ['Fork the process'])
  const stepBtn = el('button', { class: 'ghost', type: 'button' }, ['Step ▸'])
  const autoBtn = el('button', { class: 'ghost', type: 'button' }, ['Run fork ▸▸'])
  panel.append(el('div', { class: 'controls' }, [forkBtn, stepBtn, autoBtn]))

  const live = el('div', { role: 'status', 'aria-live': 'polite' }, [])
  panel.append(live)
  const verdictHost = el('div', {}, [])
  panel.append(verdictHost)

  function renderState(): void {
    if (!parent || !inherited || !reseeded) return
    const p = parent.state
    parentCard.setState(p.K, p.V)
    parentCard.badge('parent state', 'muted')
    const inh = inherited.state
    const res = reseeded.state
    const inhSame = bytesToHex(inh.K) === bytesToHex(p.K) && bytesToHex(inh.V) === bytesToHex(p.V)
    const resSame = bytesToHex(res.K) === bytesToHex(p.K) && bytesToHex(res.V) === bytesToHex(p.V)
    inheritedCard.setState(inh.K, inh.V, { K: p.K, V: p.V })
    reseededCard.setState(res.K, res.V, { K: p.K, V: p.V })
    inheritedCard.badge(inhSame ? '≡ identical to parent' : '≠ differs', inhSame ? 'alarm' : 'ok')
    reseededCard.badge(resSame ? '≡ identical to parent' : '≠ differs', resSame ? 'alarm' : 'ok')
  }

  function fork(): void {
    // Parent runs a little, then forks. All three continue from the fork-point snapshot.
    const p = HmacDrbg.instantiate(randomBytes(32), randomBytes(16))
    p.generate(16)
    forkState = p.snapshot()
    childFresh = randomBytes(32)
    parent = HmacDrbg.fromSnapshot(forkState)
    inherited = HmacDrbg.fromSnapshot(forkState)
    reseeded = HmacDrbg.fromSnapshot(forkState)
    reseeded.reseed(childFresh) // the safe child mixes in machine-unique entropy
    stepIdx = 0
    parentCard.clearLog()
    inheritedCard.clearLog()
    reseededCard.clearLog()
    clear(live)
    clear(verdictHost)
    renderState()
    live.append(
      el('p', { class: 'result-line' }, [
        'Forked. Both children inherited the parent’s (K, V). The reseeded child already ',
        el('span', { class: 'flag-neutral' }, ['DIFFERS']),
        '; the un-reseeded child is still ',
        el('span', { class: 'flag-alarm' }, ['IDENTICAL']),
        '. Step to compare their output.',
      ]),
    )
  }

  function step(): boolean {
    if (!parent || !inherited || !reseeded) fork()
    if (!parent || !inherited || !reseeded || stepIdx >= SCRIPT.length) return false
    const item = SCRIPT[stepIdx]
    const outP = parent.generate(item.bytes)
    const outInh = inherited.generate(item.bytes)
    const outRes = reseeded.generate(item.bytes)
    parentCard.log(item.label, hexBlock(outP))
    inheritedCard.log(item.label, childOutput(outInh, outP))
    reseededCard.log(item.label, childOutput(outRes, outP))
    stepIdx++
    renderState()
    if (/key/i.test(item.label)) showVerdict(bytesToHex(outInh) === bytesToHex(outP), bytesToHex(outRes) === bytesToHex(outP))
    const done = stepIdx >= SCRIPT.length
    stepBtn.disabled = done
    autoBtn.disabled = done
    return !done
  }

  async function auto(): Promise<void> {
    if (running) return
    if (!parent) fork()
    running = true
    stepBtn.disabled = true
    autoBtn.disabled = true
    const delay = reducedMotion() ? 0 : 550
    while (step()) {
      if (delay) await new Promise((r) => setTimeout(r, delay))
    }
    running = false
  }

  function showVerdict(inheritedCollides: boolean, reseededCollides: boolean): void {
    clear(verdictHost)
    verdictHost.append(
      el('p', { class: 'result-line' }, [
        'Inherited child vs parent: ',
        inheritedCollides
          ? el('span', { class: 'flag-alarm' }, ['IDENTICAL'])
          : el('span', { class: 'flag-neutral' }, ['differs']),
        ' · reseeded child vs parent: ',
        reseededCollides
          ? el('span', { class: 'flag-alarm' }, ['identical'])
          : el('span', { class: 'flag-neutral' }, ['DIFFERENT']),
        '.',
      ]),
      indicatorPair(
        {
          label: 'Cryptographic result',
          icon: '✓',
          value: 'DRBG correct in every process',
          note: 'fork() copied a working generator faithfully. The duplication is the operating system’s, not the algorithm’s.',
        },
        // Read off the measured comparisons above, so a run in which the child did
        // NOT reproduce the parent reports that instead of the expected headline.
        inheritedCollides
          ? {
              state: 'collapsed',
              label: 'Security verdict',
              icon: '✗',
              value: 'CHILD SECRET PREDICTABLE',
              note: 'The un-reseeded child handed out the parent’s next nonce/key byte for byte. Post-fork reseeding is a hard cryptographic requirement, not hygiene.',
            }
          : {
              state: 'intact',
              label: 'Security verdict',
              icon: '✓',
              value: 'NO COLLISION OBSERVED',
              note: 'The un-reseeded child did not reproduce the parent’s output in this run — the inheritance failure this panel exists to show did not occur.',
            },
      ),
    )
  }

  forkBtn.addEventListener('click', fork)
  stepBtn.addEventListener('click', () => void step())
  autoBtn.addEventListener('click', () => void auto())

  panel.append(
    notThis(
      'What this isn’t: a bug in the DRBG. fork()-safety is a property the surrounding system must ' +
        'provide by reseeding the child; the generator cannot know it was cloned.',
    ),
  )
  return panel
}
