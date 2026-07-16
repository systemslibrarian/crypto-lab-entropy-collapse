// fork() safety. A parent seeds the real DRBG, then fork()s. The child that does not
// reseed emits the parent's next output exactly — same "random" bytes, different
// process, no attacker. The child that reseeds is safe.

import { HmacDrbg } from '../crypto/hmac_drbg'
import { forkAndGenerate } from '../model/fork'
import { clear, el, hexBlock, indicatorPair, notThis, randomBytes } from './dom'

export function forkPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', id: 'fork' }, [
    el('span', { class: 'panel-kicker' }, ['fork() safety']),
    el('h2', {}, ['A child inherits the parent’s next secret']),
    el('p', { class: 'panel-lede' }, [
      'When a process forks, the child receives a byte-perfect copy of the parent’s memory — ' +
        'including the DRBG’s (K, V). The child that pulls fresh entropy before generating is fine. ' +
        'The child that forgets emits precisely what the parent would have emitted next.',
    ]),
  ])

  const controls = el('div', { class: 'controls' }, [])
  const runBtn = el('button', { class: 'action', type: 'button' }, ['Run fork()'])
  controls.append(runBtn)
  panel.append(controls)

  const result = el('div', { role: 'status', 'aria-live': 'polite' }, [])
  panel.append(result)

  function run(): void {
    clear(result)
    const parent = HmacDrbg.instantiate(randomBytes(32), randomBytes(16))
    parent.generate(16) // parent works, then forks
    const res = forkAndGenerate(parent.snapshot(), randomBytes(32))

    result.append(
      el('div', { class: 'streams' }, [
        el('div', { class: 'stream', role: 'group', 'aria-label': 'Parent next output' }, [
          el('h3', {}, ['Parent — next output']),
          hexBlock(res.parentNext),
        ]),
        el('div', { class: 'stream', role: 'group', 'aria-label': 'Inherited child output' }, [
          el('h3', {}, ['Child A — did not reseed']),
          hexBlock(res.childInherited, res.parentNext),
        ]),
      ]),
      el('div', { class: 'streams', style: 'margin-top:.7rem' }, [
        el('div', { class: 'stream', role: 'group', 'aria-label': 'Reseeded child output' }, [
          el('h3', {}, ['Child B — reseeded with fresh entropy']),
          hexBlock(res.childReseeded, res.parentNext),
        ]),
        el('div', { class: 'stream' }, [
          el('h3', {}, ['Comparison']),
          el('p', { class: 'result-line' }, [
            'Child A vs Parent: ',
            el('span', { class: 'flag-alarm' }, [
              res.inheritedCollidesWithParent ? 'IDENTICAL' : 'differs',
            ]),
          ]),
          el('p', { class: 'result-line' }, [
            'Child B vs Parent: ',
            el('span', { class: 'flag-neutral' }, [
              res.reseededCollidesWithParent ? 'identical' : 'DIFFERENT',
            ]),
          ]),
        ]),
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

  runBtn.addEventListener('click', run)
  panel.append(
    notThis(
      'What this isn’t: a bug in the DRBG. fork()-safety is a property the surrounding system must ' +
        'provide by reseeding the child; the generator cannot know it was cloned.',
    ),
  )
  return panel
}
