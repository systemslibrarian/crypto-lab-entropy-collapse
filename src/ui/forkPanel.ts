// fork() safety, shown as a tree. A parent seeds the real DRBG and forks. Both children
// inherit an exact copy of its (K, V). Step them together: the child that reseeds diverges
// from the parent; the child that forgets emits the parent's next output, byte for byte.

import { HmacDrbg, type DrbgState } from '../crypto/hmac_drbg'
import { bytesToHex } from '../crypto/hex'
import { clear, compareHexBlock, el, hexBlock, indicatorPair, notThis, randomBytes } from './dom'
import { stateCard } from './machine'

const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

const SCRIPT = [
  { label: 'Next nonce (public)', bytes: 16 },
  { label: 'Next key (secret)', bytes: 32 },
]

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
      'When a process forks, the child receives a byte-perfect copy of the parent’s memory — ' +
        'including the DRBG’s (K, V). Fork the parent, then step all three. The child that pulls ' +
        'fresh entropy is safe; the child that forgets tracks the parent exactly.',
    ]),
  ])

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
    inheritedCard.log(item.label, compareHexBlock(outInh, outP, 'diff'))
    reseededCard.log(item.label, compareHexBlock(outRes, outP, 'diff'))
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
        {
          state: 'collapsed',
          label: 'Security verdict',
          icon: '✗',
          value: 'CHILD SECRET PREDICTABLE',
          note: 'The un-reseeded child will hand out the parent’s next nonce/key. Post-fork reseeding is a hard cryptographic requirement, not hygiene.',
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
