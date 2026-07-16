// Tiny DOM helpers — no framework. Keeps the panels declarative and readable.

import { bytesToHex } from '../crypto/hex'

type Attrs = Record<string, string | number | boolean | undefined>
type Child = Node | string | null | undefined

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue
    if (k === 'class') node.className = String(v)
    else if (k === 'text') node.textContent = String(v)
    else if (k === 'html') node.innerHTML = String(v)
    else node.setAttribute(k, String(v))
  }
  for (const c of children) {
    if (c == null) continue
    node.append(typeof c === 'string' ? document.createTextNode(c) : c)
  }
  return node
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild)
}

/** Group a hex string into space-separated byte pairs for legibility. */
export function groupHex(hex: string, perGroup = 2): string {
  const re = new RegExp(`.{1,${perGroup * 2}}`, 'g')
  return (hex.match(re) ?? []).join(' ')
}

/** Render bytes as a mono hex block; optionally highlight bytes differing from `other`. */
export function hexBlock(bytes: Uint8Array, other?: Uint8Array): HTMLElement {
  const box = el('div', { class: 'hexblock' })
  const hex = bytesToHex(bytes)
  if (!other) {
    box.textContent = groupHex(hex)
    return box
  }
  for (let i = 0; i < bytes.length; i++) {
    const pair = hex.slice(i * 2, i * 2 + 2)
    const differs = other[i] !== bytes[i]
    box.append(el('span', differs ? { class: 'byte-diff' } : {}, [pair]))
    box.append(document.createTextNode(' '))
  }
  return box
}

/** Compare bytes to `other`, highlighting either the matching or the changed bytes in a
 *  calm (non-alarm) tone. Used by the clone panel, where "same" is the teaching point and
 *  "diverged" is the desirable outcome — so neither should read as danger-red. */
export function compareHexBlock(
  bytes: Uint8Array,
  other: Uint8Array,
  mode: 'match' | 'diff',
): HTMLElement {
  const box = el('div', { class: 'hexblock' })
  const hex = bytesToHex(bytes)
  for (let i = 0; i < bytes.length; i++) {
    const pair = hex.slice(i * 2, i * 2 + 2)
    const equal = other[i] === bytes[i]
    const hit = mode === 'match' ? equal : !equal
    const cls = mode === 'match' ? 'byte-same' : 'byte-chg'
    box.append(el('span', hit ? { class: cls } : {}, [pair]))
    box.append(document.createTextNode(' '))
  }
  return box
}

/** Short "a1b2c3d4e5f6…" preview of a byte array, for state chips. */
export function abbrevHex(bytes: Uint8Array, headBytes = 6): string {
  const hex = bytesToHex(bytes.subarray(0, headBytes))
  return groupHex(hex) + (bytes.length > headBytes ? ' …' : '')
}

export interface IndicatorSpec {
  label: string
  icon: string
  value: string
  note?: string
}

/** The two-track indicator pair: the primitive's status and the security verdict,
 *  rendered as independent boxes. Color on the verdict tracks system integrity. */
export function indicatorPair(
  primitive: IndicatorSpec,
  verdict: IndicatorSpec & { state: 'intact' | 'collapsed' },
): HTMLElement {
  const wrap = el('div', { class: 'indicators' })

  const prim = el('div', { class: 'indicator primitive' }, [
    el('span', { class: 'ind-label' }, ['Cryptographic result']),
    el('span', { class: 'ind-value' }, [
      el('span', { 'aria-hidden': 'true' }, [primitive.icon]),
      el('span', {}, [primitive.value]),
    ]),
    primitive.note ? el('p', { class: 'ind-note' }, [primitive.note]) : null,
  ])

  const verd = el('div', { class: 'indicator verdict', 'data-state': verdict.state }, [
    el('span', { class: 'ind-label' }, ['Security verdict']),
    el('span', { class: 'ind-value' }, [
      el('span', { 'aria-hidden': 'true' }, [verdict.icon]),
      el('span', {}, [verdict.value]),
    ]),
    verdict.note ? el('p', { class: 'ind-note' }, [verdict.note]) : null,
  ])

  wrap.append(prim, verd)
  return wrap
}

/** A compact "cause → consequence" strip: the at-a-glance causal chain for a panel. */
export function consequenceStrip(items: [string, string][]): HTMLElement {
  return el(
    'div',
    { class: 'cons-strip', role: 'note', 'aria-label': 'What this causes' },
    items.map(([from, to]) =>
      el('span', { class: 'cons-item' }, [
        el('b', {}, [from]),
        el('span', { class: 'cons-arrow', 'aria-hidden': 'true' }, [' → ']),
        el('span', { class: 'visually-hidden' }, [' causes ']),
        to,
      ]),
    ),
  )
}

/** A collapsible "for the expert" disclosure block (progressive disclosure). */
export function disclosure(summary: string, ...body: Child[]): HTMLElement {
  return el('details', { class: 'disclosure' }, [el('summary', {}, [summary]), ...body])
}

/** The one-line "what this isn't" scope note required per non-goal. */
export function notThis(text: string): HTMLElement {
  return el('p', { class: 'not-this' }, [text])
}

const encoder = new TextEncoder()
export const utf8 = (s: string) => encoder.encode(s)

/** Cryptographically strong random bytes (per-session, never persisted). */
export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}
