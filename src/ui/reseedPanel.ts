// The failed reseed, shown as a timeline. An attacker captured the DRBG state earlier and
// predicts along the top lane; the server runs along... the same lane, block for block.
// At the reseed event the two lanes either split (a proper reseed mixed in fresh entropy)
// or stay locked (a silent no-op reseed added nothing). Either way the reseed counter
// resets to 1 and the health monitor reads "fresh" — the irony the panel exists to show.

import { HmacDrbg, type DrbgState } from '../crypto/hmac_drbg'
import { bytesEqual, bytesToHex } from '../crypto/hex'
import { clear, el, groupHex, indicatorPair, notThis, randomBytes } from './dom'

const PRE = 2 // blocks generated before the reseed
const POST = 2 // blocks generated after the reseed
const BLK = 16

export function reseedPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', id: 'reseed' }, [
    el('span', { class: 'panel-kicker' }, ['Chapter 4 · The reseed that wasn’t']),
    el('h2', {}, ['A healthy counter over a stale seed']),
    el('p', { class: 'panel-lede' }, [
      'A key server runs for months. An attacker snapshots its DRBG state once and predicts forward. ' +
        'Later the server “reseeds.” Choose which reseed it got — one that mixes in fresh, ' +
        'unpredictable entropy, or one whose entropy source silently returned nothing. Both reset the ' +
        'reseed counter to 1.',
    ]),
  ])

  const properBtn = el('button', { class: 'action', type: 'button' }, ['Simulate a proper reseed'])
  const noopBtn = el('button', { class: 'action', type: 'button' }, ['Simulate a silent no-op reseed'])
  panel.append(el('div', { class: 'controls' }, [properBtn, noopBtn]))

  const timeline = el('div', { class: 'timeline', role: 'group', 'aria-label': 'Reseed timeline' }, [])
  panel.append(timeline)

  const health = el('div', { class: 'health' }, [])
  panel.append(health)

  const live = el('div', { role: 'status', 'aria-live': 'polite' }, [])
  panel.append(live)
  const verdictHost = el('div', {}, [])
  panel.append(verdictHost)

  function block(bytes: Uint8Array, tone?: 'hit' | 'miss'): HTMLElement {
    const cell = el('div', { class: 'blk' + (tone ? ' ' + tone : '') }, [
      el('code', {}, [groupHex(bytesToHex(bytes.subarray(0, 6))) + ' …']),
    ])
    if (tone) {
      cell.append(
        el('span', { class: 'blk-tag' }, [
          el('span', { 'aria-hidden': 'true' }, [tone === 'hit' ? '⚠ ' : '✓ ']),
          tone === 'hit' ? 'attacker predicted' : 'attacker lost track',
        ]),
      )
    }
    return cell
  }

  function reseedRule(label: boolean): HTMLElement {
    return el('div', { class: 'tl-rule' }, [label ? el('span', { class: 'tl-rule-tag' }, ['reseed']) : null])
  }

  function lane(labelText: string, cells: HTMLElement[], showRuleLabel: boolean): HTMLElement {
    const row = el('div', { class: 'tl-lane' }, [el('span', { class: 'tl-lane-label' }, [labelText])])
    const track = el('div', { class: 'tl-track' }, [])
    cells.forEach((c, i) => {
      if (i === PRE) track.append(reseedRule(showRuleLabel))
      track.append(c)
    })
    row.append(track)
    return row
  }

  function run(kind: 'proper' | 'noop'): void {
    clear(timeline)
    clear(health)
    clear(live)
    clear(verdictHost)

    // A long-lived server; the attacker captured this state earlier.
    const server = HmacDrbg.instantiate(randomBytes(32), randomBytes(16))
    server.generate(64)
    const captured: DrbgState = server.snapshot()

    const srv = HmacDrbg.fromSnapshot(captured)
    const atk = HmacDrbg.fromSnapshot(captured) // attacker replays from the captured state

    const srvCells: HTMLElement[] = []
    const atkCells: HTMLElement[] = []

    // Pre-reseed: the attacker already tracks the server perfectly.
    for (let i = 0; i < PRE; i++) {
      const s = srv.generate(BLK)
      const a = atk.generate(BLK)
      srvCells.push(block(s))
      atkCells.push(block(a, bytesEqual(a, s) ? 'hit' : 'miss'))
    }

    // The reseed event. Proper: fresh, attacker-unknown entropy. No-op: empty input.
    // The attacker, not knowing any fresh entropy, replays an empty reseed either way.
    srv.reseed(kind === 'proper' ? randomBytes(32) : new Uint8Array(0))
    atk.reseed(new Uint8Array(0))

    for (let i = 0; i < POST; i++) {
      const s = srv.generate(BLK)
      const a = atk.generate(BLK)
      srvCells.push(block(s))
      atkCells.push(block(a, bytesEqual(a, s) ? 'hit' : 'miss'))
    }

    timeline.append(
      lane('Server output', srvCells, true),
      lane('Attacker prediction', atkCells, false),
    )

    const stillPredictable = kind === 'noop'
    health.append(
      el('span', { class: 'health-icon', 'aria-hidden': 'true' }, ['🩺']),
      el('span', {}, [
        'Health monitor: reseed_counter = ',
        el('b', {}, [String(srv.getReseedCounter())]),
        ' (reset to 1 by the reseed, +1 per block since) — reads ',
        el('span', { class: 'flag-neutral' }, ['fresh / healthy']),
        '.',
      ]),
    )

    live.append(
      el('p', { class: 'result-line' }, [
        kind === 'proper'
          ? 'After the reseed, the attacker’s prediction '
          : 'After the reseed, the attacker’s prediction ',
        stillPredictable
          ? el('span', { class: 'flag-alarm' }, ['STILL MATCHES'])
          : el('span', { class: 'flag-neutral' }, ['DIVERGES']),
        stillPredictable
          ? ' — nothing unpredictable went in, so replaying an empty reseed keeps tracking the server.'
          : ' — fresh entropy entered the state the attacker never saw.',
      ]),
      indicatorPair(
        {
          label: 'Cryptographic result',
          icon: '✓',
          value: 'Reseed executed, counter reset',
          note: 'HMAC_DRBG performed the reseed and Update() exactly as specified; the counter honestly reflects that a reseed call happened.',
        },
        stillPredictable
          ? {
              state: 'collapsed',
              label: 'Security verdict',
              icon: '✗',
              value: 'STILL PREDICTABLE',
              note: 'An empty reseed still stirs (K, V) deterministically, so the attacker replays it. The counter says healthy; the entropy says otherwise, and nobody checks the entropy.',
            }
          : {
              state: 'intact',
              label: 'Security verdict',
              icon: '✓',
              value: 'FORWARD SECRECY RESTORED',
              note: 'Fresh, attacker-unknown entropy entered the state. The old snapshot no longer predicts the output.',
            },
      ),
    )
  }

  properBtn.addEventListener('click', () => run('proper'))
  noopBtn.addEventListener('click', () => run('noop'))

  panel.append(
    notThis(
      'What this isn’t: a claim that reseeding is optional. The opposite — it shows that a reseed is ' +
        'only worth its counter increment if the entropy behind it was genuinely unpredictable.',
    ),
  )
  return panel
}
