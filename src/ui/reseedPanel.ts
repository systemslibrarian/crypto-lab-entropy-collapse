// The failed reseed. A long-lived generator is "reseeded", the reseed counter resets
// to look healthy, and an attacker who captured the earlier state keeps predicting the
// output — because the reseed added no fresh entropy. The counter is the safety
// mechanism; nobody checks whether the entropy behind it was real.

import { HmacDrbg } from '../crypto/hmac_drbg'
import { afterNoOpReseed, afterProperReseed } from '../model/reseed'
import { clear, el, hexBlock, indicatorPair, notThis, randomBytes } from './dom'

export function reseedPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', id: 'reseed' }, [
    el('span', { class: 'panel-kicker' }, ['The reseed that wasn’t']),
    el('h2', {}, ['A healthy counter over a stale seed']),
    el('p', { class: 'panel-lede' }, [
      'A key server runs for months. An attacker snapshots its DRBG state once. Later the server ' +
        '“reseeds.” Pick which reseed it got: one that mixes in fresh, unpredictable entropy, or one ' +
        'whose entropy source silently returned nothing. Both reset the reseed counter to 1.',
    ]),
  ])

  const controls = el('div', { class: 'controls' }, [])
  const properBtn = el('button', { class: 'action', type: 'button' }, ['Simulate a proper reseed'])
  const noopBtn = el('button', { class: 'action', type: 'button' }, ['Simulate a silent no-op reseed'])
  controls.append(properBtn, noopBtn)
  panel.append(controls)

  const result = el('div', { role: 'status', 'aria-live': 'polite' }, [])
  panel.append(result)

  function show(kind: 'proper' | 'noop'): void {
    clear(result)
    // A server that has been running a while; the attacker captured this state earlier.
    const server = HmacDrbg.instantiate(randomBytes(32), randomBytes(16))
    server.generate(64)
    const captured = server.snapshot()
    const outcome =
      kind === 'proper' ? afterProperReseed(captured, randomBytes(32), 3) : afterNoOpReseed(captured, 3)

    result.append(
      el('div', { class: 'streams' }, [
        el('div', { class: 'stream', role: 'group', 'aria-label': 'Actual output' }, [
          el('h3', {}, ['Server output after reseed']),
          hexBlock(outcome.actual),
        ]),
        el('div', { class: 'stream', role: 'group', 'aria-label': 'Attacker prediction' }, [
          el('h3', {}, ['Attacker’s prediction from the old state']),
          hexBlock(outcome.attackerPredicted, outcome.actual),
        ]),
      ]),
      el('p', { class: 'result-line' }, [
        'Health monitor reads reseed_counter = ',
        el('span', { class: 'flag-neutral' }, [String(outcome.reseedCounter)]),
        ' (reset by the reseed — looks fresh). Attacker prediction vs actual: ',
        outcome.predictable
          ? el('span', { class: 'flag-alarm' }, ['MATCH'])
          : el('span', { class: 'flag-neutral' }, ['no match']),
        '.',
      ]),
      indicatorPair(
        {
          label: 'Cryptographic result',
          icon: '✓',
          value: 'Reseed executed, counter reset',
          note: 'HMAC_DRBG performed the reseed and Update() exactly as specified; the counter honestly reflects that a reseed call happened.',
        },
        kind === 'proper'
          ? {
              state: 'intact',
              label: 'Security verdict',
              icon: '✓',
              value: 'FORWARD SECRECY RESTORED',
              note: 'Fresh, attacker-unknown entropy entered the state. The old snapshot no longer predicts the output.',
            }
          : {
              state: 'collapsed',
              label: 'Security verdict',
              icon: '✗',
              value: 'STILL PREDICTABLE',
              note: 'An empty reseed still stirs (K, V) deterministically, so the attacker replays it. The counter says healthy; the entropy says otherwise, and nobody checks the entropy.',
            },
      ),
    )
  }

  properBtn.addEventListener('click', () => show('proper'))
  noopBtn.addEventListener('click', () => show('noop'))
  panel.append(
    notThis(
      'What this isn’t: a claim that reseeding is optional. The opposite — it shows that a reseed ' +
        'is only worth its counter increment if the entropy behind it was genuinely unpredictable.',
    ),
  )
  return panel
}
