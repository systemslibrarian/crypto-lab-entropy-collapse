// Plain-language on-ramp: what this is and why it matters, before any hex or slider.

import { el, disclosure } from './dom'
import { SIBLINGS } from './links'

export function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title' }, ['Entropy Collapse']),
      el('p', { class: 'cl-hero-sub' }, ['Seed provenance & RNG state duplication · NIST SP 800-90B']),
      el('p', { class: 'cl-hero-desc' }, [
        'Snapshot one machine’s real HMAC_DRBG, restore it onto two, and watch both emit identical ' +
          'nonces and keys — then drain a seed’s entropy and brute-force the key the generator kept secret.',
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
