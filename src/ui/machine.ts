// A reusable "machine" card: a glyph + title + tone badge, a live (K, V) state readout,
// and an output log. Shared by the clone, fork, and reseed panels so the whole demo
// speaks one visual language — every panel is the same generator viewed a different way.

import { bytesToHex } from '../crypto/hex'
import { abbrevHex, clear, el } from './dom'

export type Tone = 'idle' | 'alarm' | 'ok' | 'muted'

export interface StateCard {
  root: HTMLElement
  /** Set the K/V chips; if `compare` is given, chips that differ from it read "diverged". */
  setState(K: Uint8Array, V: Uint8Array, compare?: { K: Uint8Array; V: Uint8Array }): void
  clearState(): void
  badge(text: string, tone: Tone): void
  log(label: string, value: HTMLElement): void
  clearLog(): void
}

export function stateCard(title: string, glyph = '🖥', ariaLabel?: string): StateCard {
  const kChip = el('code', { class: 'state-hex' }, ['—'])
  const vChip = el('code', { class: 'state-hex' }, ['—'])
  const tag = el('span', { class: 'sync-badge', 'data-tone': 'idle' }, ['—'])
  const logEl = el('div', {
    class: 'machine-log',
    role: 'log',
    'aria-label': ariaLabel ?? `${title} output`,
  })

  const root = el('div', { class: 'machine' }, [
    el('div', { class: 'machine-head' }, [
      el('span', { class: 'machine-glyph', 'aria-hidden': 'true' }, [glyph]),
      el('h3', {}, [title]),
      tag,
    ]),
    el('div', { class: 'machine-state' }, [
      el('div', {}, [el('span', { class: 'sk' }, ['K']), kChip]),
      el('div', {}, [el('span', { class: 'sk' }, ['V']), vChip]),
    ]),
    logEl,
  ])

  return {
    root,
    setState(K, V, compare) {
      const kDiff = compare && bytesToHex(compare.K) !== bytesToHex(K)
      const vDiff = compare && bytesToHex(compare.V) !== bytesToHex(V)
      kChip.textContent = abbrevHex(K)
      vChip.textContent = abbrevHex(V)
      kChip.className = 'state-hex' + (kDiff ? ' diverged' : '')
      vChip.className = 'state-hex' + (vDiff ? ' diverged' : '')
    },
    clearState() {
      kChip.textContent = '—'
      vChip.textContent = '—'
      kChip.className = 'state-hex'
      vChip.className = 'state-hex'
    },
    badge(text, tone) {
      tag.textContent = text
      tag.setAttribute('data-tone', tone)
    },
    log(label, value) {
      logEl.append(
        el('div', { class: 'log-row' }, [el('span', { class: 'log-label' }, [label]), value]),
      )
    },
    clearLog() {
      clear(logEl)
    },
  }
}
