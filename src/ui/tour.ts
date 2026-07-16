// A one-click, ~60-second guided tour for talks and first-time visitors. It drives the
// real panels the same way a user would — scrolling to each and clicking its button — so
// nothing here is a separate "demo mode" that could drift from the real behaviour.

import { el } from './dom'

const reduced = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

interface Step {
  id: string
  button: RegExp
  narration: string
  dwell: number
  prep?: () => void
}

const STEPS: Step[] = [
  {
    id: 'clone',
    button: /Auto-run/,
    narration:
      'Chapter 1 — Clone. One machine, snapshotted onto two servers. Their internal state loads identically and every nonce and key drops in lockstep.',
    dwell: 12000,
  },
  {
    id: 'fork',
    button: /Run fork/,
    narration:
      'Chapter 2 — Fork. A forked child that forgets to reseed emits the parent’s next secret, byte for byte. The reseeded child is safe.',
    dwell: 10000,
  },
  {
    id: 'entropy',
    button: /Run seed recovery/,
    prep: () => {
      const s = document.getElementById('entropy-slider') as HTMLInputElement | null
      if (s) {
        s.value = '6' // the 14-bit stop: small enough to crack live
        s.dispatchEvent(new Event('input', { bubbles: true }))
      }
    },
    narration:
      'Chapter 3 — Starve. Drop the seed’s entropy and the key becomes guessable. Watch the real generator get brute-forced live until the seed cracks.',
    dwell: 14000,
  },
  {
    id: 'reseed',
    button: /silent no-op reseed/,
    narration:
      'Chapter 4 — Stale. A “reseed” that adds no entropy. The health counter reads fresh; the attacker keeps predicting every block.',
    dwell: 10000,
  },
]

export function createGuidedTour(): { start: () => void } {
  let active = false
  let paused = false
  let skip = false
  let ended = false

  const text = el('p', { class: 'tour-text', role: 'status', 'aria-live': 'polite' }, [''])
  const dots = el('div', { class: 'tour-dots', 'aria-hidden': 'true' }, [])
  const pauseBtn = el('button', { class: 'ghost', type: 'button' }, ['Pause'])
  const nextBtn = el('button', { class: 'ghost', type: 'button' }, ['Next ▸'])
  const replayBtn = el('button', { class: 'ghost', type: 'button' }, ['Replay'])
  const exitBtn = el('button', { class: 'ghost', type: 'button', 'aria-label': 'Exit tour' }, ['Exit ✕'])
  const bar = el('div', { class: 'tour-bar', role: 'region', 'aria-label': 'Guided tour', hidden: true }, [
    dots,
    text,
    el('div', { class: 'tour-controls' }, [pauseBtn, nextBtn, replayBtn, exitBtn]),
  ])
  document.body.append(bar)

  function renderDots(activeIdx: number): void {
    dots.textContent = ''
    STEPS.forEach((_, i) => {
      dots.append(el('span', { class: 'tour-dot' + (i === activeIdx ? ' on' : '') }, ['●']))
    })
  }

  function scrollTo(id: string): void {
    document.getElementById(id)?.scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'start' })
  }

  function clickButton(id: string, match: RegExp): void {
    const panel = document.getElementById(id)
    if (!panel) return
    for (const b of Array.from(panel.querySelectorAll('button'))) {
      if (match.test(b.textContent || '') && !(b as HTMLButtonElement).disabled) {
        ;(b as HTMLButtonElement).click()
        return
      }
    }
  }

  async function dwell(ms: number): Promise<'done' | 'next' | 'exit'> {
    let elapsed = 0
    while (elapsed < ms) {
      if (!active) return 'exit'
      if (skip) {
        skip = false
        return 'next'
      }
      await sleep(150)
      if (!paused) elapsed += 150
    }
    return 'done'
  }

  function setPaused(p: boolean): void {
    paused = p
    pauseBtn.textContent = p ? 'Resume' : 'Pause'
    pauseBtn.setAttribute('aria-pressed', String(p))
  }

  async function run(): Promise<void> {
    active = true
    ended = false
    paused = false
    setPaused(false)
    nextBtn.hidden = false
    pauseBtn.hidden = false
    bar.hidden = false
    for (let i = 0; i < STEPS.length; i++) {
      if (!active) return
      const step = STEPS[i]
      renderDots(i)
      text.textContent = step.narration
      scrollTo(step.id)
      await sleep(reduced() ? 0 : 600) // let the scroll settle before acting
      step.prep?.()
      clickButton(step.id, step.button)
      const r = await dwell(step.dwell)
      if (r === 'exit') return
    }
    finish()
  }

  function finish(): void {
    ended = true
    renderDots(-1)
    text.textContent =
      'The generator did nothing wrong. Nobody attacked it. Every collapse came from the seed — not the math.'
    pauseBtn.hidden = true
    nextBtn.hidden = true
  }

  function exit(): void {
    active = false
    bar.hidden = true
  }

  pauseBtn.addEventListener('click', () => setPaused(!paused))
  nextBtn.addEventListener('click', () => {
    if (!ended) skip = true
  })
  replayBtn.addEventListener('click', () => {
    if (active && !ended) return
    void run()
  })
  exitBtn.addEventListener('click', exit)

  return {
    start(): void {
      if (active && !ended) return
      void run()
    },
  }
}
