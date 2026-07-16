// Plain-language on-ramp: what this is and why it matters, before any hex or slider.

import { el, disclosure } from './dom'
import { SIBLINGS } from './links'

const REPO = 'https://github.com/systemslibrarian/crypto-lab-entropy-collapse'

export function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title' }, ['Entropy Collapse']),
      el('p', { class: 'cl-hero-sub' }, ['Seed provenance & RNG state duplication · NIST SP 800-90B']),
      el('p', { class: 'cl-hero-desc' }, [
        'Snapshot one machine’s real HMAC_DRBG, restore it onto two, and watch both emit identical ' +
          'nonces and keys — then drain a seed’s entropy and brute-force the key the generator kept secret.',
      ]),
      el('div', { class: 'cl-hero-actions' }, [
        el('button', { id: 'start-tour', class: 'action cta', type: 'button' }, [
          '▶  Run the collapse',
          el('span', { class: 'cta-sub' }, ['60-second guided tour']),
        ]),
      ]),
      el('div', { class: 'trust-row', role: 'list', 'aria-label': 'Verification' }, [
        el('a', { class: 'trust-badge', role: 'listitem', href: `${REPO}#build--verify` }, [
          el('span', { 'aria-hidden': 'true' }, ['✓ ']),
          '34 tests passing',
        ]),
        el('a', { class: 'trust-badge', role: 'listitem', href: `${REPO}/blob/main/src/crypto/nist_drbg_vectors.ts` }, [
          el('span', { 'aria-hidden': 'true' }, ['✓ ']),
          'NIST + RFC vectors',
        ]),
        el('a', { class: 'trust-badge', role: 'listitem', href: `${REPO}#build--verify` }, [
          el('span', { 'aria-hidden': 'true' }, ['✓ ']),
          'WCAG AA checked',
        ]),
      ]),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label' }, ['WHY IT MATTERS']),
      el('p', { class: 'cl-hero-why-text' }, [
        'A correct generator is a deterministic function of its seed. When a VM is cloned, a process ' +
          'forks, or a device boots with no entropy, real TLS and SSH hosts have shipped duplicate, ' +
          'guessable keys — with no flaw in the crypto and no attacker in the loop.',
      ]),
    ]),
  ])
}

export function throughLine(): HTMLElement {
  const item = (href: string, label: string, rest: string) =>
    el('li', {}, [el('a', { class: 'chapter-link', href }, [el('b', {}, [label])]), ' — ' + rest])
  return el('section', { class: 'throughline' }, [
    el('h2', {}, ['One root cause, five ways to see it']),
    el('p', {}, [
      'Every panel below is the same real generator, unmodified. Nothing here attacks the DRBG — ' +
        'each chapter just changes what happens to its seed. Jump to any of them:',
    ]),
    el('ol', { class: 'chapter-nav' }, [
      item('#clone', 'Clone', 'one seed, copied onto two machines: identical secrets.'),
      item('#fork', 'Fork', 'one seed, inherited by a child that forgot to reseed.'),
      item('#entropy', 'Starve', 'one seed with almost no entropy, guessed by brute force.'),
      item('#reseed', 'Stale', 'one seed a “reseed” never actually refreshed.'),
      item('#history', 'History', 'the same failures, shipped to the real internet.'),
    ]),
  ])
}

export function intro(): HTMLElement {
  return el('section', { class: 'intro' }, [
    el('h2', {}, ['What is this?']),
    el('p', { class: 'lead' }, [
      'A “random number generator” on a computer is usually not random at all: it is a ',
      el('strong', {}, ['deterministic']),
      ' function that stretches one secret starting value — the ',
      el('em', {}, ['seed']),
      ' — into an endless stream of unpredictable-looking bytes. It is unpredictable to you only ' +
        'because you don’t know the seed.',
    ]),
    el('p', {}, [
      'This lab uses a real, standards-conformant generator (HMAC_DRBG, NIST SP 800-90A) and never ' +
        'touches its math. Every alarming thing you’ll see comes from the ',
      el('em', {}, ['seed']),
      ': duplicate it and two machines become the same machine; starve it and its whole output ' +
        'becomes guessable. The generator did nothing wrong. Nobody attacked it.',
    ]),
    disclosure(
      'New to the jargon? Start here',
      el('ul', {}, [
        el('li', {}, [
          el('strong', {}, ['DRBG']),
          ' — Deterministic Random Bit Generator. Same seed in, same bytes out, every time.',
        ]),
        el('li', {}, [
          el('strong', {}, ['Seed / entropy']),
          ' — the unpredictable input that makes the output unpredictable. Entropy is measured in ' +
            'bits: 256 bits of entropy means 2^256 equally-likely seeds.',
        ]),
        el('li', {}, [
          el('strong', {}, ['Nonce']),
          ' — a “number used once”, often published on the wire. Reusing one across two signatures ' +
            'is catastrophic (see ',
          el('a', { href: SIBLINGS.ecdsaForge }, ['ecdsa-forge']),
          ').',
        ]),
        el('li', {}, [
          el('strong', {}, ['Reseed']),
          ' — mixing new entropy into a running generator so past state stops predicting the future.',
        ]),
      ]),
    ),
  ])
}
