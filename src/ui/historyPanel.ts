// Historical panel. Two real incidents where the DRBG/PRNG was fine and the entropy
// was not. Numbers stated precisely, no embellishment.

import { el, disclosure, notThis } from './dom'
import { SIBLINGS } from './links'

export function historyPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', id: 'history' }, [
    el('span', { class: 'panel-kicker' }, ['Chapter 5 · This already happened']),
    el('h2', {}, ['Two real collapses, no attacker in either']),
    el('p', { class: 'panel-lede' }, [
      'These are not hypotheticals. In both cases the generator worked; the seed did not.',
    ]),
  ])

  const debian = el('div', {}, [
    el('h3', {}, ['Debian OpenSSL, 2006–2008 (CVE-2008-0166)']),
    el('div', { class: 'scroll-x', role: 'region', tabindex: '0', 'aria-label': 'Debian OpenSSL facts' }, [
      el('table', { class: 'facts' }, [
        el('caption', {}, ['What a single removed line did']),
        el('tbody', {}, [
          el('tr', {}, [
            el('th', { scope: 'row' }, ['The change']),
            el('td', {}, [
              'A Debian-specific patch removed code that mixed uninitialised/random data into the ' +
                'OpenSSL PRNG seed, leaving essentially only the process ID as the varying input.',
            ]),
          ]),
          el('tr', {}, [
            el('th', { scope: 'row' }, ['The keyspace']),
            el('td', {}, [
              'Linux’s default maximum PID is 32,768, so at most 32,767 distinct keys were possible ' +
                'for a given architecture and key size — trivially enumerable.',
            ]),
          ]),
          el('tr', {}, [
            el('th', { scope: 'row' }, ['The window']),
            el('td', {}, [
              'SSL/SSH keys generated on Debian-based systems from September 2006 until the fix on ' +
                '13 May 2008 were affected. Discovered by Luciano Bello.',
            ]),
          ]),
        ]),
      ]),
    ]),
  ])

  const psqs = el('div', { style: 'margin-top:1.2rem' }, [
    el('h3', {}, ['“Mining Your Ps and Qs”, 2012 — an internet-wide survey']),
    el('div', { class: 'scroll-x', role: 'region', tabindex: '0', 'aria-label': 'Ps and Qs survey facts' }, [
      el('table', { class: 'facts' }, [
        el('caption', {}, [
          'Heninger, Durumeric, Wustrow & Halderman scanned the whole IPv4 TLS/SSH surface.',
        ]),
        el('tbody', {}, [
          el('tr', {}, [
            el('th', { scope: 'row' }, ['Shared keys']),
            el('td', {}, ['0.75% of TLS certificates shared keys due to insufficient entropy.']),
          ]),
          el('tr', {}, [
            el('th', { scope: 'row' }, ['RSA keys computed']),
            el('td', {}, [
              'Private RSA keys were computed for 0.50% of TLS hosts (by taking GCDs of moduli that ' +
                'shared a prime) and 0.03% of SSH hosts.',
            ]),
          ]),
          el('tr', {}, [
            el('th', { scope: 'row' }, ['DSA keys computed']),
            el('td', {}, [
              'Private DSA keys were computed for 1.03% of SSH hosts, from repeated DSA signature ' +
                'nonces — the same nonce-reuse algebra as the clone panel above.',
            ]),
          ]),
          el('tr', {}, [
            el('th', { scope: 'row' }, ['Root cause']),
            el('td', {}, [
              'A boot-time entropy hole in the Linux RNG; the affected devices were overwhelmingly ' +
                'headless/embedded systems generating keys on first boot.',
            ]),
          ]),
        ]),
      ]),
    ]),
  ])

  panel.append(debian, psqs)

  panel.append(
    disclosure(
      'The frame, stated plainly',
      el('p', {}, [
        'SP 800-90A’s security guarantees are explicitly conditional on the entropy input — the ' +
          'standard says so. The seed is an unauthenticated input to an authenticated system: the ' +
          'generator will faithfully sign, encrypt and key-exchange with whatever it was given, ' +
          'including a guessable seed. That is the same shape as an unauthenticated clock feeding a ' +
          'signature-validity check — see ',
        el('a', { href: SIBLINGS.timeTrust }, ['Time Trust']),
        '. Deliberate sabotage of the generator is a different lab: ',
        el('a', { href: SIBLINGS.corruptedOracle }, ['corrupted-oracle']),
        ' (malice, not accident).',
      ]),
    ),
  )

  panel.append(
    notThis(
      'What this isn’t: a reproduction of either attack. These are the documented facts, cited so ' +
        'the live panels above are grounded in what actually shipped.',
    ),
  )
  return panel
}
