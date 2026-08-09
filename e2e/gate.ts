import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old `prepare()`
 *     pushed `animation:none!important; transition:none!important` through
 *     `addStyleTag` before every scan. On this page that injection was not just
 *     a bypass, it was measuring a rendering that does not exist: `style.css`
 *     declares no `transition`, no `animation`, no `@keyframes` and — checked
 *     separately — not one `opacity`. There was nothing to neutralise.
 *
 *     What the preference actually governs here is JAVASCRIPT. Three call sites
 *     read `matchMedia('(prefers-reduced-motion: reduce)')` directly —
 *     `clonePanel`, `forkPanel` and `tour` — and use it to drop a 550ms
 *     per-step delay to zero and a smooth `scrollIntoView` to an instant one. An
 *     injected stylesheet cannot reach any of that. `boot` asks for the
 *     preference and ASSERTS it took effect, which makes the auto-runs
 *     deterministic instead of a race against a wall clock, and it asserts
 *     separately that nothing inside `#app` is running a named animation — so
 *     the day one arrives without a reduced-motion block, the gate says so
 *     rather than silently painting over it.
 *
 *  2. IT FORCE-REVEALED EVERYTHING, AND CLICKED BUTTONS BY REGEX. `prepare()`
 *     set `.open = true` on every `<details>`, stripped `[hidden]` from every
 *     element that had one — which on this page is the guided-tour narration
 *     bar, a `position: fixed` overlay that is only supposed to exist during a
 *     tour — and then added `active`, `is-active` and `open` classes to every
 *     `[role="tabpanel"]`, of which this lab has none. It then clicked every
 *     button whose label matched `/run|compute|sign|verify|encrypt|simulate|
 *     start/` with `.catch(() => {})`, so a click that failed was silently
 *     discarded, and waited a fixed 600ms. The document it scanned was one no
 *     reader can load: an empty tour bar floating over five panels in whatever
 *     state a regex happened to leave them. This gate never touches `.open`,
 *     `hidden`, `display` or `class`; every disclosure is opened by clicking its
 *     own `<summary>` and every panel is driven by the control that drives it.
 *
 *  3. IT SCANNED ONCE, AT ONE VIEWPORT. Two scans total, both at 1280px, both
 *     after that same blind sweep. The 380px column had never been scanned at
 *     all, and neither had: the arrival state of any panel, the clone panel's
 *     divergence branch, the fork tree, any entropy stop other than whichever
 *     one the slider happened to hold, the seed-recovery result, either reseed
 *     outcome, or any tour state. This drive scans after every single step, in
 *     {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: fifteen
 *     text-bearing surfaces are `color-mix(in oklab, …, transparent)` over
 *     whatever panel is behind them, which axe files under `incomplete`; and an
 *     `aria-label` on a role-less element is PROHIBITED and lands in
 *     `incomplete` too, never in `violations` — which is one attribute from
 *     live here, since `.trust-row`, `.cons-strip`, the observed-values block,
 *     the reseed timeline and both `.scroll-x` wrappers are all plain `<div>`s
 *     carrying an `aria-label` made legal by a role typed beside it.
 *
 *  5. IT HAD NO REFLOW, NO KEYBOARD-SCROLLER AND NO NON-TEXT-CONTRAST ORACLE,
 *     and this page needs all three. Chapter 5's two incident tables live in
 *     `.scroll-x` wrappers that do not overflow until phone width; and every
 *     secondary control on the page is a `button.ghost` — transparent fill,
 *     `--border` edge — which is the shape SC 1.4.11 exists to catch and which
 *     nothing here had ever measured.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: `style.css` contains no
 * `@keyframes`, no `animation` property and not a single `opacity`
 * declaration anywhere in it — its header states the rule ("Muted text lowers
 * lightness, never opacity") and `boot` asserts the outcome, that no element
 * inside `#app` is running a named animation. The check runs in every state
 * regardless, because all three of those are properties of the current
 * stylesheet rather than of the page, and this is the cheapest place to catch
 * the first exception — a lab with no reduced-motion block at all, as this one
 * is, has nothing to restore an end state if an animation ever arrives.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here — which on this page means the `.ticker` line in Chapter
 * 3, whose ratio is measured by hand instead (see `driveAllStates`).
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * `ui/intro.ts` renders its hero as a `<header class="cl-hero">` and `main.ts`
 * appends it to `<main id="app">`, which scopes that `<header>` out of the
 * banner role on its own — and `index.html`'s `dedupeBanner()` explicitly skips
 * it for that reason (`el.closest('main, …')` returns early). So nothing here
 * demotes anything; the single banner is a property of where `main.ts` mounts.
 * Asserting the OUTCOME rather than either mechanism means a change to the mount
 * point is caught too — and this lab appends one element to `document.body`
 * directly already (the guided-tour bar), so that is not a hypothetical route.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/** The five chapters `main.ts` mounts, in the order it mounts them. */
export const CHAPTERS = ['clone', 'fork', 'entropy', 'reseed', 'history'] as const;

/**
 * The controls, by the exact label each renders.
 *
 * "Step ▸" exists in BOTH the clone and fork panels, which is why every locator
 * in the drive is scoped to its chapter rather than taken from the page. A
 * page-wide `getByRole('button', { name: /Step/ })` matches two elements and
 * fails as a strict-mode violation — the gate this replaces sidestepped that by
 * clicking every button whose label matched a regex and swallowing the errors.
 */
export const BUTTONS = {
  snapshot: 'Snapshot & restore',
  step: 'Step ▸',
  cloneAuto: 'Auto-run ▸▸',
  diverge: 'Give Server B its own entropy',
  fork: 'Fork the process',
  forkAuto: 'Run fork ▸▸',
  recover: 'Run seed recovery',
  newVictim: 'New victim machine',
  properReseed: 'Simulate a proper reseed',
  noopReseed: 'Simulate a silent no-op reseed',
} as const;

/**
 * The entropy slider's stops, by index, from `entropy/boot.ts`.
 *
 * Three boundaries here are reachable only by moving the slider, and each
 * renders prose no other stop does: index 0 is the only `full` stop and the only
 * one whose "seed source" block says `getrandom()` instead of drawing a
 * MAC/boot-time/PID table; index 1 is `MODEL_MAX_BITS` and the only stop that
 * appends the paragraph explaining why the starved ladder stops there; and index
 * 5 is exactly `ENUMERABLE_MAX_BITS`, the boundary at which "Run seed recovery"
 * stops being disabled. A gate that scans one slider position scans one of eight
 * renderings, and which one depends on a default.
 */
export const ENTROPY_STOPS = [
  { index: 0, bits: 256, enumerable: false, full: true },
  { index: 1, bits: 31, enumerable: false, full: false },
  { index: 2, bits: 28, enumerable: false, full: false },
  { index: 3, bits: 24, enumerable: false, full: false },
  { index: 4, bits: 20, enumerable: false, full: false },
  { index: 5, bits: 16, enumerable: true, full: false },
  { index: 6, bits: 14, enumerable: true, full: false },
  { index: 7, bits: 12, enumerable: true, full: false },
] as const;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Here the preference does not change one CSS
 * declaration — there are none to change — but it changes the LAB: `clonePanel`,
 * `forkPanel` and `tour` each read the media query directly and use it to drop
 * a 550ms per-step delay to zero. An emulation that silently did nothing would
 * turn every auto-run in the drive into a race against a wall clock, and a
 * flake there would look like a defect.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice. (They agree today — both are `'theme'` — which
 * was checked, not assumed.) The gate this replaces did not even use the toggle:
 * it called `setAttribute('data-theme', 'light')` from script when the toggle
 * was absent, so a broken toggle and a broken key would both have scanned green.
 *
 * The defaults are asserted at length because three of the five chapters ship
 * COMPLETELY EMPTY — no snapshot, no fork, no timeline — and the fourth ships
 * parked at one of eight slider stops, which decides on its own whether "Run
 * seed recovery" is enabled and whether the panel draws a MAC/boot-time/PID
 * table or a `getrandom()` note. A gate that scans one arrival state and never
 * asserts it is scanning one eighth of one chapter and calling it the page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // `src/main.ts` builds the whole document into an empty `<main id="app">`, so
  // a navigation that resolves proves nothing.
  await expect(page.locator('.cl-hero-title')).toHaveText('Entropy Collapse');
  for (const id of CHAPTERS) await expect(page.locator(`#${id}`)).toBeVisible();

  // This lab has NO `@media (prefers-reduced-motion: reduce)` block, because it
  // has no CSS motion to cancel — asserted here rather than read off the
  // stylesheet, so the day an animation arrives without a block to answer for
  // it, this fails instead of `expectNotBlank` silently staying green because
  // the element happened to end visible. Scoped to what this lab owns: the
  // shared top bar carries its own `transition` declarations and is not this
  // repo's to change.
  expect(
    await page.evaluate(() =>
      Array.from(document.querySelectorAll('#app, #app *, .tour-bar, .tour-bar *'))
        .filter((el) => getComputedStyle(el).animationName !== 'none')
        .map((el) => `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`)
    ),
    'no element this lab owns may run an animation without a reduced-motion answer'
  ).toEqual([]);

  // ── Three chapters ship completely empty ────────────────────────────────
  await expect(page.locator('#clone .log-row')).toHaveCount(0);
  await expect(page.locator('#clone .state-hex')).toHaveCount(4);
  await expect(page.locator('#clone .state-hex').first()).toHaveText('—');
  await expect(page.locator('#fork .log-row')).toHaveCount(0);
  await expect(page.locator('#fork .machine')).toHaveCount(3);
  await expect(page.locator('#reseed .timeline')).toBeEmpty();
  await expect(page.locator('#reseed .health')).toBeEmpty();

  // ── Chapter 3 ships parked at the 14-bit stop, and that decides its UI ──
  await expect(page.locator('#entropy-slider')).toHaveValue('6');
  await expect(page.locator('#entropy .ks-figure')).toContainText('2^14');
  await expect(page.locator('#entropy .facts')).toBeVisible();
  await expect(
    page.getByRole('button', { name: BUTTONS.recover }),
    '14 bits is under the live-enumeration limit, so recovery ships ENABLED'
  ).toBeEnabled();

  // ── The guided tour has not started ─────────────────────────────────────
  await expect(page.locator('.tour-bar')).toBeHidden();
  await expect(page.locator('#start-tour')).toBeEnabled();

  // Two disclosures ship with the page; two more only exist once a run has
  // produced a verdict. All shut.
  await expect(page.locator('details.disclosure')).toHaveCount(2);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page has
 * four shapes that break it. Chapter 5's two incident tables are wide prose
 * tables, meant to scroll inside their own `.scroll-x`. Chapter 4's timeline
 * puts a fixed `flex: 0 0 9rem` lane label beside a track of `min-width: 7.5rem`
 * blocks. `.machines`, `.fork-children`, `.indicators` and `.streams` are all
 * bare-`1fr` grid tracks, whose automatic minimum is min-content, not zero. And
 * every generated value on the page lands in a `.hexblock` as an unbroken hex
 * run. The assertion here is that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That cost
    // a run elsewhere in this fleet, and this page has a decoy behind every
    // `.scroller`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab has two, both in Chapter 5, and both are hand-built at their call
 * site rather than produced by a helper: the `.scroll-x` wrappers around the
 * Debian OpenSSL and "Mining Your Ps and Qs" tables, each carrying
 * `role="region"`, `tabindex="0"` and an `aria-label`. Both are correct today.
 * The assertion stays because each is three attributes typed by hand with
 * nothing enforcing them, because neither overflows at all until phone width —
 * so the question only exists in one of this gate's four configurations — and
 * because what is inside them is the entire evidentiary basis for the live
 * panels above: the two real incidents where the generator was fine and the
 * seed was not.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * The gate this replaces had no such check at all — not a narrow one, none —
 * which is how every secondary control on this page came to be a
 * `button.ghost`: `background-color: transparent` with a `1px solid var(--border)`
 * edge, on `.panel`. A transparent fill cannot delineate anything, so the
 * border is the entire boundary, and `--border` is the token this stylesheet
 * uses for SURFACE dividers — the panel edge, the table cell rules, the
 * `.machine` card, the `.not-this` rail. It was never measured against
 * anything.
 *
 * A control passes if EITHER
 *   - its fill differs from the surface behind it (how `.btn` works: a
 *     transparent border over an `--accent` fill), or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill (how a `<select>` works: a near-panel fill with a drawn edge).
 * so the score is `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 * Taking the max of the two mechanisms is what keeps this from failing a
 * perfectly delineated solid button for having no border.
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page
 *    disables "Run seed recovery" at five of the eight entropy stops, and both
 *    Step buttons once their script is exhausted.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a byte-identical copy — and neither is the
 *    guided-tour bar excluded for convenience: `.tour-bar` is appended to
 *    `document.body`, so its four `button.ghost` controls fall outside `#app`
 *    and outside this walk. They are the SAME class, measured by the same rule
 *    in every in-`#app` state, so a fix that lands on `.ghost` lands on them
 *    too; that equivalence is the reason the exclusion is safe here and it is
 *    written down so it stays a decision rather than an oversight.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette is full of
    // `color-mix()`, which `getComputedStyle` reports unchanged and which a
    // regex reads as null — landing the walk on the wrong backdrop.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i], out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0) {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since fifteen
 *    text-bearing surfaces are `color-mix(in oklab, …, transparent)` that axe
 *    declines to resolve, including both security verdicts and all three byte
 *    highlights. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides, a defect that never reaches the
 *    violations array at all. That one is one attribute from live here: six
 *    plain `<div>`s on this page carry an `aria-label` made legal only by a
 *    `role` typed on the line beside it.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for interactive controls — SC 1.4.11, which axe has no
 *    rule for; see `auditControlBoundaries`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page })
    .withTags(TAGS)
    // These four are axe "best-practice" rules rather than WCAG-tagged ones, so
    // `withTags` alone does not run them. This page is exactly the shape they
    // catch: a shared sticky <header role="banner"> above a <main id="app"> that
    // `main.ts` fills with a second <header class="cl-hero"> containing an
    // <aside class="cl-hero-why">, plus a third landmark — the guided tour's
    // <div role="region" aria-label="Guided tour"> — appended straight to
    // <body>. None of the four was enabled before.
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}


// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Open one `<details class="disclosure">` by clicking its summary.
 *
 * Never `.open = true`. The gate this replaces set that property on every
 * `<details>` on the page before its only scan, so the SHUT rendering — which is
 * the one every reader arrives at, and the one in which the recoloured
 * `summary::marker` is the entire open/shut affordance — was never measured, and
 * the click path a keyboard reader actually uses was never exercised.
 */
async function openDisclosure(page: Page, summaryText: RegExp): Promise<void> {
  const d = page.locator('details.disclosure').filter({ has: page.locator('summary') }).filter({
    hasText: summaryText,
  });
  const first = d.first();
  await expect(first).not.toHaveAttribute('open', '');
  await first.locator('summary').first().click();
  await expect(first).toHaveAttribute('open', '');
}

/** A button inside one chapter. "Step ▸" exists in two of them. */
function inChapter(page: Page, id: string, name: string) {
  return page.locator(`#${id}`).getByRole('button', { name, exact: true });
}

/**
 * Move the entropy slider to one stop and wait for the panel to re-render.
 *
 * The slider is an `<input type="range">` whose handler regenerates the victim
 * machine, so `fill()` (which dispatches `input`) is the reader's own route.
 * The readout's `2^N` figure is the completion signal the code itself writes.
 */
async function setEntropyStop(page: Page, index: number, bits: number): Promise<void> {
  await page.locator('#entropy-slider').fill(String(index));
  await expect(page.locator('#entropy-slider')).toHaveValue(String(index));
  await expect(page.locator('#entropy .ks-figure')).toContainText(`2^${bits}`);
  await settle(page);
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Seven things shape this drive:
 *
 *  - THREE CHAPTERS START EMPTY, AND EMPTY IS SCANNED FIRST. Clone, fork and
 *    reseed render nothing until a button is pressed: no machine state, no
 *    output log, no timeline, no verdict. That is the state every reader
 *    arrives at, and it is the only state in which `.sync-badge` is painted in
 *    its `idle` tone and `.state-hex` holds an em dash instead of hex. The gate
 *    this replaces could not reach it — it clicked every matching button before
 *    its only scan.
 *
 *  - THE CLONE PANEL IS DRIVEN THROUGH BOTH OUTCOMES, ONE STEP AT A TIME. The
 *    four scripted fields are not interchangeable: the verdict block only
 *    renders on a field whose label matches `/key/i`, so steps 2 and 4 produce a
 *    rendering steps 1 and 3 do not, and the consequence callout renders only
 *    when every compared field came out identical. Then "Give Server B its own
 *    entropy" rewinds to the same snapshot and replays it diverged — which
 *    repaints every byte from `.byte-same` to `.byte-chg`, flips both
 *    `.sync-badge`s from `alarm` to `ok`, turns the state chips
 *    `.state-hex.diverged`, and swaps INTEGRITY COLLAPSED for INTEGRITY
 *    RESTORED. That is a second full palette, and nothing had ever scanned it.
 *
 *  - THE LAZY-INIT BRANCH IS DRIVEN DELIBERATELY. Both `step()` and `auto()`
 *    call `setup()`/`fork()` themselves when no machines exist yet, so pressing
 *    "Step ▸" before "Snapshot & restore" is a real path a reader takes and a
 *    real rendering. It is driven in the fork panel, where the button order on
 *    screen invites it.
 *
 *  - EVERY SLIDER STOP THAT CHANGES THE UI IS VISITED. Chapter 3 has eight, and
 *    four of them render prose or an enabled/disabled state no other stop does:
 *    index 0 is the only `full` stop (a `getrandom()` note instead of the
 *    MAC/boot-time/PID table, and "Not enumerable" instead of a sweep estimate);
 *    index 1 is `MODEL_MAX_BITS` and the only stop appending the paragraph
 *    explaining why the ladder stops there; index 3 sits between the two
 *    thresholds; index 5 is exactly `ENUMERABLE_MAX_BITS`, the boundary where
 *    "Run seed recovery" stops being disabled. Driving the extremes of a slider
 *    rather than its default is the whole point.
 *
 *  - THE RECOVERY IS RUN TO COMPLETION, AT THE SMALLEST STOP. 2^12 candidates is
 *    four batches of real HMAC_DRBG instantiations — fast enough to run in every
 *    one of the four configurations, and the only route to `.cracked`,
 *    `.cracked-tag`, the recovered-seed and recovered-key hex blocks, the KEY
 *    RECOVERED verdict, and a fourth disclosure that does not exist until then.
 *
 *  - THE GUIDED TOUR IS A STATE, NOT A FEATURE TO SKIP. `.tour-bar` is a
 *    `position: fixed` overlay appended to `<body>` with its own landmark, its
 *    own four `button.ghost` controls and a `role="status"` narration line. The
 *    gate this replaces stripped its `hidden` attribute and scanned it EMPTY,
 *    floating over the page, which is a document no reader can produce. Here it
 *    is started by its own button and driven through pause, resume, skip, the
 *    finished state and exit.
 *
 *  - NO FIXED TIMEOUTS. The auto-runs drop their delay to zero under the reduced
 *    motion this gate asserts, and every step has a DOM completion signal: a log
 *    row count, a badge string, a verdict class, a control returning from
 *    `disabled`. The drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);
  const recoverBtn = page.getByRole('button', { name: BUTTONS.recover, exact: true });

  await scanAt('first paint: three chapters empty, slider parked at 14 bits, no tour');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── The two shipped disclosures, opened through their own summaries ──────
  await openDisclosure(page, /New to the jargon/);
  await scanAt('jargon primer disclosure open');
  await openDisclosure(page, /The frame, stated plainly/);
  await scanAt('Chapter 5 framing disclosure open');

  // ── Chapter 1: clone ────────────────────────────────────────────────────
  await inChapter(page, 'clone', BUTTONS.snapshot).click();
  await expect(page.locator('#clone .result-line')).toContainText('IDENTICAL');
  await expect(page.locator('#clone .sync-badge').nth(1)).toHaveText('≡ identical to A');
  await expect(page.locator('#clone .sync-badge').nth(1)).toHaveAttribute('data-tone', 'alarm');
  await expect(page.locator('#clone .state-hex').first()).not.toHaveText('—');
  await expect(page.locator('#clone .log-row')).toHaveCount(0);
  await settle(page);
  await scanAt('clone: restored from one snapshot, state identical, nothing generated yet');

  // Field 1 is a nonce — no verdict block renders for it.
  await inChapter(page, 'clone', BUTTONS.step).click();
  await expect(page.locator('#clone .log-row')).toHaveCount(2);
  await expect(page.locator('#clone .log-label').first()).toHaveText('Session nonce (public)');
  await expect(page.locator('#clone .indicator')).toHaveCount(0);
  await settle(page);
  await scanAt('clone step 1: the public nonce, byte-identical, no verdict yet');

  // Field 2 is a key — the verdict, the two-track indicators and the
  // consequence callout all render for the first time here.
  await inChapter(page, 'clone', BUTTONS.step).click();
  await expect(page.locator('#clone .log-row')).toHaveCount(4);
  await expect(page.locator('#clone .indicator.verdict')).toHaveAttribute(
    'data-state',
    'collapsed'
  );
  await expect(page.locator('#clone .indicator.verdict')).toContainText('INTEGRITY COLLAPSED');
  await expect(page.locator('#clone .callout')).toBeVisible();
  await settle(page);
  await scanAt('clone step 2: the session key collides, INTEGRITY COLLAPSED, callout shown');

  await openDisclosure(page, /why they never diverge/);
  await scanAt('clone: the expert disclosure that only exists once a verdict exists');

  await inChapter(page, 'clone', BUTTONS.step).click();
  await expect(page.locator('#clone .log-row')).toHaveCount(6);
  await inChapter(page, 'clone', BUTTONS.step).click();
  await expect(page.locator('#clone .log-row')).toHaveCount(8);
  await expect(inChapter(page, 'clone', BUTTONS.step)).toBeDisabled();
  await expect(inChapter(page, 'clone', BUTTONS.cloneAuto)).toBeDisabled();
  await settle(page);
  await scanAt('clone: script exhausted, both step controls disabled');

  // The divergence branch: same snapshot, one machine-unique input. Every byte
  // repaints, both badges flip tone, the state chips go `.diverged`, and the
  // verdict swaps to INTEGRITY RESTORED. `auto()` runs it to the end with a zero
  // delay because reduced motion is in effect.
  await inChapter(page, 'clone', BUTTONS.diverge).click();
  await expect(page.locator('#clone .log-row')).toHaveCount(8);
  await expect(page.locator('#clone .indicator.verdict')).toHaveAttribute('data-state', 'intact');
  await expect(page.locator('#clone .indicator.verdict')).toContainText('INTEGRITY RESTORED');
  await expect(page.locator('#clone .sync-badge').nth(1)).toHaveAttribute('data-tone', 'ok');
  await expect(page.locator('#clone .state-hex.diverged').first()).toBeVisible();
  await expect(page.locator('#clone .byte-chg').first()).toBeVisible();
  await settle(page);
  await scanAt('clone: Server B given its own entropy — the whole panel in its restored palette');

  // Re-arm and run the collapse again through the auto-run control, so the
  // control itself is driven and the panel is left in its headline state.
  await inChapter(page, 'clone', BUTTONS.snapshot).click();
  await expect(page.locator('#clone .log-row')).toHaveCount(0);
  await inChapter(page, 'clone', BUTTONS.cloneAuto).click();
  await expect(page.locator('#clone .log-row')).toHaveCount(8);
  await expect(page.locator('#clone .indicator.verdict')).toHaveAttribute(
    'data-state',
    'collapsed'
  );
  await settle(page);
  await scanAt('clone: auto-run replays the collapse end to end');

  // ── Chapter 2: fork ─────────────────────────────────────────────────────
  // Deliberately pressing Step before "Fork the process": `step()` calls
  // `fork()` itself when no processes exist, which is a real reader path.
  await inChapter(page, 'fork', BUTTONS.step).click();
  await expect(page.locator('#fork .log-row')).toHaveCount(3);
  await expect(page.locator('#fork .result-line')).toContainText('IDENTICAL');
  await expect(page.locator('#fork .byte-tally')).toHaveCount(2);
  await settle(page);
  await scanAt('fork: Step before Fork — the lazy-init path, one field compared');

  await inChapter(page, 'fork', BUTTONS.step).click();
  await expect(page.locator('#fork .log-row')).toHaveCount(6);
  await expect(page.locator('#fork .indicator.verdict')).toHaveAttribute('data-state', 'collapsed');
  await expect(page.locator('#fork .indicator.verdict')).toContainText('CHILD SECRET PREDICTABLE');
  // Both tally tones are on screen at once here, which is the comparison the
  // panel exists to make: the un-reseeded child scores every byte, the reseeded
  // one scores near zero.
  await expect(page.locator('#fork .byte-tally[data-tone="alarm"]').first()).toBeVisible();
  await expect(page.locator('#fork .byte-tally[data-tone="ok"]').first()).toBeVisible();
  await expect(inChapter(page, 'fork', BUTTONS.step)).toBeDisabled();
  await settle(page);
  await scanAt('fork: the child emits the parent’s next key, both tally tones on screen');

  await inChapter(page, 'fork', BUTTONS.fork).click();
  await expect(page.locator('#fork .log-row')).toHaveCount(0);
  await expect(inChapter(page, 'fork', BUTTONS.step)).toBeEnabled();
  await settle(page);
  await scanAt('fork: re-forked, logs cleared, controls re-armed');

  await inChapter(page, 'fork', BUTTONS.forkAuto).click();
  await expect(page.locator('#fork .log-row')).toHaveCount(6);
  await expect(page.locator('#fork .indicator.verdict')).toHaveAttribute('data-state', 'collapsed');
  await settle(page);
  await scanAt('fork: auto-run replays the inheritance end to end');

  // ── Chapter 3: the entropy slider, at every stop that changes the UI ────
  await setEntropyStop(page, 0, 256);
  await expect(page.locator('#entropy .hexblock').first()).toContainText('getrandom()');
  await expect(page.locator('#entropy .facts')).toHaveCount(0);
  await expect(page.locator('#entropy .result-line')).toContainText('Not enumerable');
  await expect(recoverBtn, '2^256 must not offer a live sweep').toBeDisabled();
  await scanAt('entropy: the fully-seeded stop — no victim table, recovery disabled');

  await setEntropyStop(page, 1, 31);
  await expect(page.locator('#entropy .facts')).toBeVisible();
  await expect(page.locator('#entropy .result-line')).toContainText('too long to watch here');
  await expect(page.locator('#entropy .keyspace')).toContainText('The starved ladder stops at 2^31');
  await expect(recoverBtn).toBeDisabled();
  await scanAt('entropy: 2^31, the ladder ceiling — the only stop that explains itself');

  await setEntropyStop(page, 3, 24);
  await expect(page.locator('#entropy .result-line')).toContainText('too long to watch here');
  await expect(recoverBtn).toBeDisabled();
  await scanAt('entropy: 2^24 — weak but past what a browser tab can sweep');

  await setEntropyStop(page, 5, 16);
  await expect(page.locator('#entropy .result-line')).toContainText('Small enough to enumerate live');
  await expect(recoverBtn, '2^16 is exactly the enumerable limit, so recovery unlocks here').toBeEnabled();
  await scanAt('entropy: 2^16, exactly the enumeration boundary — recovery unlocks');

  await setEntropyStop(page, 7, 12);
  await expect(recoverBtn).toBeEnabled();
  await scanAt('entropy: 2^12, the smallest modelled space');

  // The real sweep: 4096 candidate seeds, each one a real HMAC_DRBG.
  await recoverBtn.click();
  await expect(page.locator('#entropy .cracked')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#entropy .cracked-tag')).toContainText('SEED CRACKED');
  await expect(page.locator('#entropy .indicator.verdict')).toHaveAttribute(
    'data-state',
    'collapsed'
  );
  await expect(page.locator('#entropy .indicator.verdict')).toContainText('KEY RECOVERED');
  await expect(page.locator('#entropy .progress')).toBeVisible();
  await expect(recoverBtn).toBeEnabled();
  await settle(page);
  await scanAt('entropy: seed recovered, session key reconstructed, KEY RECOVERED');

  await openDisclosure(page, /what recovery does and does not prove/);
  await scanAt('entropy: the recovery-scope disclosure open');

  await inChapter(page, 'entropy', BUTTONS.newVictim).click();
  await expect(page.locator('#entropy .cracked')).toHaveCount(0);
  await expect(page.locator('#entropy .progress')).toHaveCount(0);
  await settle(page);
  await scanAt('entropy: a fresh victim machine — the result cleared back to nothing');

  // ── Chapter 4: both reseed outcomes ─────────────────────────────────────
  await inChapter(page, 'reseed', BUTTONS.properReseed).click();
  await expect(page.locator('#reseed .blk.miss')).toHaveCount(2);
  await expect(page.locator('#reseed .blk.hit')).toHaveCount(2);
  await expect(page.locator('#reseed .health')).toContainText('reseed_counter');
  await expect(page.locator('#reseed .indicator.verdict')).toHaveAttribute('data-state', 'intact');
  await expect(page.locator('#reseed .indicator.verdict')).toContainText(
    'FORWARD SECRECY RESTORED'
  );
  await settle(page);
  await scanAt('reseed: a proper reseed — the attacker loses track, both block tones on screen');

  await inChapter(page, 'reseed', BUTTONS.noopReseed).click();
  await expect(page.locator('#reseed .blk.hit')).toHaveCount(4);
  await expect(page.locator('#reseed .blk.miss')).toHaveCount(0);
  await expect(page.locator('#reseed .indicator.verdict')).toHaveAttribute(
    'data-state',
    'collapsed'
  );
  await expect(page.locator('#reseed .indicator.verdict')).toContainText('STILL PREDICTABLE');
  await expect(page.locator('#reseed .health')).toContainText('fresh / healthy');
  await settle(page);
  await scanAt('reseed: a silent no-op — every block still predicted, counter still reads healthy');

  // ── The guided tour: a fixed overlay with its own landmark ──────────────
  await page.locator('#start-tour').click();
  await expect(page.locator('.tour-bar')).toBeVisible();
  await expect(page.locator('.tour-text')).toContainText('Chapter 1 — Clone');
  await expect(page.locator('.tour-dot')).toHaveCount(4);
  await settle(page);
  await scanAt('tour: running, the narration bar over Chapter 1');

  const pause = page.locator('.tour-bar').getByRole('button', { name: 'Pause', exact: true });
  await pause.click();
  await expect(page.locator('.tour-bar').getByRole('button', { name: 'Resume' })).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  await settle(page);
  await scanAt('tour: paused — the toggle in its pressed state');

  await page.locator('.tour-bar').getByRole('button', { name: 'Resume', exact: true }).click();
  await expect(pause).toHaveAttribute('aria-pressed', 'false');

  const next = page.locator('.tour-bar').getByRole('button', { name: 'Next ▸', exact: true });
  for (const chapter of ['Chapter 2 — Fork', 'Chapter 3 — Starve', 'Chapter 4 — Stale']) {
    await next.click();
    await expect(page.locator('.tour-text')).toContainText(chapter);
  }
  await scanAt('tour: skipped to Chapter 4');

  // Past the last step the tour finishes: the closing line replaces the
  // narration and both transport controls hide themselves.
  await next.click();
  await expect(page.locator('.tour-text')).toContainText('The generator did nothing wrong');
  await expect(next).toBeHidden();
  await expect(page.locator('.tour-bar').getByRole('button', { name: /Pause|Resume/ })).toBeHidden();
  // Chapter 3's tour step set the slider to 14 bits and started a real sweep;
  // let it finish rather than scanning a page that is still mutating.
  await expect(recoverBtn).toBeEnabled({ timeout: 60_000 });
  await settle(page);
  await scanAt('tour: finished — the closing line, transport controls gone');

  // `aria-label="Exit tour"` overrides the button's "Exit ✕" text content, so
  // the accessible name — which is what a reader is offered — is neither string
  // that appears in the source.
  await page.locator('.tour-bar').getByRole('button', { name: 'Exit tour', exact: true }).click();
  await expect(page.locator('.tour-bar')).toBeHidden();
  await settle(page);
  await scanAt('tour: exited — the overlay gone, every chapter left populated');
}
