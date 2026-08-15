import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and every state is scanned as
 * it is reached: the arrival page, where three of the five chapters render
 * nothing at all and the entropy slider is parked at one of eight stops; the
 * skip link focused; both shipped disclosures opened through their own
 * summaries; Chapter 1 restored from a snapshot and stepped one field at a time,
 * because only a field whose label says "key" renders a verdict, then rewound
 * and replayed DIVERGED, which repaints every byte and swaps INTEGRITY COLLAPSED
 * for INTEGRITY RESTORED; Chapter 2 driven through its lazy-init path (Step
 * before Fork) to the state where both byte-tally tones sit on screen at once;
 * Chapter 3 at five slider stops — the fully-seeded one, the ladder ceiling, the
 * enumeration boundary and the smallest space — then a real 4096-candidate sweep
 * run to completion for the cracked-seed rendering; Chapter 4 in both outcomes,
 * proper and silent no-op; and the guided tour started, paused, resumed, skipped
 * to its end and exited, because its `position: fixed` narration bar is a
 * landmark with four controls of its own. All of that in both themes, at desktop
 * and phone width.
 *
 * No permissions are granted because this lab touches no permissioned API — the
 * only `navigator`/`crypto` call is `crypto.getRandomValues`.
 *
 * See `gate.ts` for why nothing is injected into the page, why no disclosure is
 * force-opened and no `[hidden]` attribute stripped, why the lab's defaults are
 * asserted rather than assumed, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });
}
