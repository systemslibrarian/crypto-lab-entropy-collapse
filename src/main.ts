import './style.css'
import { hero, intro, throughLine } from './ui/intro'
import { clonePanel } from './ui/clonePanel'
import { entropyPanel } from './ui/entropyPanel'
import { forkPanel } from './ui/forkPanel'
import { reseedPanel } from './ui/reseedPanel'
import { historyPanel } from './ui/historyPanel'
import { createGuidedTour } from './ui/tour'
import { el } from './ui/dom'

const app = document.getElementById('app')
if (!app) throw new Error('#app mount point missing')

// Render order matches the chapter numbering and the through-line: 1..5.
app.append(
  hero(),
  intro(),
  throughLine(),
  clonePanel(),
  forkPanel(),
  entropyPanel(),
  reseedPanel(),
  historyPanel(),
  el('p', { class: 'not-this', style: 'margin-top:1.5rem' }, [
    'Not production crypto — a teaching demo. All key material is generated per session, in memory, ' +
      'and is never stored or transmitted. What’s real: the SHA-256 / HMAC / HMAC_DRBG implementations ' +
      '(checked against NIST and RFC test vectors) and every recovery you run against them. What’s ' +
      'modelled: VM snapshots and boot-time entropy, both labelled where they appear.',
  ]),
)

const tour = createGuidedTour()
document.getElementById('start-tour')?.addEventListener('click', () => tour.start())

// Deep-link support: /#clone, /#fork, /#entropy, /#reseed, /#history.
if (location.hash.length > 1) {
  document.querySelector(location.hash)?.scrollIntoView()
}

const constructionNote = document.createElement('div');
constructionNote.innerHTML = `<section class="research-context" id="rbg-constructions" style="padding:1.25rem;margin-top:1.5rem;line-height:1.7"><h2>Connect source evidence to RBG construction</h2><p><a style="color:inherit;text-decoration:underline" href="https://systemslibrarian.github.io/crypto-lab-drbg-arena/#construction-context">DRBG Arena’s 90C class chooser</a> distinguishes RBG1 external one-time initialization, RBG2 entropy-backed DRBGs, RBG3 full-entropy constructions and same-platform RBGC trees. These names describe system requirements, not certification of this browser model. Preserve source-health and entropy-accounting evidence; conditioning or deterministic expansion cannot create entropy. See <a style="color:inherit;text-decoration:underline" href="https://csrc.nist.gov/pubs/sp/800/90/c/final" target="_blank" rel="noopener noreferrer">SP 800-90C final (25 September 2025)</a>. Reviewed 12 October 2026.</p></section>`;
app.append(constructionNote.firstElementChild!);
