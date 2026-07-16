import './style.css'
import { hero, intro } from './ui/intro'
import { clonePanel } from './ui/clonePanel'
import { entropyPanel } from './ui/entropyPanel'
import { forkPanel } from './ui/forkPanel'
import { reseedPanel } from './ui/reseedPanel'
import { historyPanel } from './ui/historyPanel'
import { el } from './ui/dom'

const app = document.getElementById('app')
if (!app) throw new Error('#app mount point missing')

app.append(
  hero(),
  intro(),
  clonePanel(),
  entropyPanel(),
  forkPanel(),
  reseedPanel(),
  historyPanel(),
  el('p', { class: 'not-this', style: 'margin-top:1.5rem' }, [
    'Not production crypto — a teaching demo. All key material is generated per session, in memory, ' +
      'and is never stored or transmitted. What’s real: the SHA-256 / HMAC / HMAC_DRBG implementations ' +
      '(checked against NIST and RFC test vectors) and every recovery you run against them. What’s ' +
      'modelled: VM snapshots and boot-time entropy, both labelled where they appear.',
  ]),
)
