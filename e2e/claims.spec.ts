// Functional gate: the claims this page makes, asserted against the page it actually
// renders. The a11y spec next door proves the markup is reachable; this one proves the
// headline verdict, every failure/tamper path, and every counter are true.
//
// House rule for this file: never assert a number the page merely printed. Assert that
// the page's numbers agree with each other and with the bytes on screen — tallies against
// the hex they summarise, the recovered seed against SHA-256 of the material the page
// published, the guess count against the boot-time/PID it says it found.

import { createHash } from 'node:crypto'
import { expect, test, type Locator, type Page } from '@playwright/test'

// --- the ladder the page advertises (README: 2^256 down to a headless boot) ---
const STOPS = [
  { value: '0', bits: 256, full: true },
  { value: '1', bits: 31, full: false },
  { value: '2', bits: 28, full: false },
  { value: '3', bits: 24, full: false },
  { value: '4', bits: 20, full: false },
  { value: '5', bits: 16, full: false },
  { value: '6', bits: 14, full: false },
  { value: '7', bits: 12, full: false },
]
const ENUMERABLE_MAX_BITS = 16 // the page's stated live-enumeration cap
const GUESS_RATE = 10_000 // the rate the readout quotes
const BOOT_PID_BITS = 11 // low bits of the secret index are the early-boot PID
const BASE_TIME = 1_704_067_200 // 2024-01-01T00:00:00Z
const MAC_HEX = '525400123456'

const CLONE_SCRIPT = [
  { label: 'Session nonce (public)', bytes: 16 },
  { label: 'Session key (secret)', bytes: 32 },
  { label: 'Next nonce (public)', bytes: 16 },
  { label: 'Next key (secret)', bytes: 32 },
]

// --- helpers ---------------------------------------------------------------

/** Text of a node reduced to its hex digits, with a shape check so a silently empty
 *  or non-hex node fails here rather than sailing through a comparison. */
async function hexOf(loc: Locator): Promise<string> {
  const raw = ((await loc.textContent()) ?? '').replace(/[\s…]/g, '')
  expect(raw, 'expected a hex block').toMatch(/^[0-9a-f]+$/)
  return raw
}

interface LogRow {
  label: string
  hex: string
}

async function logRows(machine: Locator): Promise<LogRow[]> {
  const rows = machine.locator('.log-row')
  const out: LogRow[] = []
  for (let i = 0; i < (await rows.count()); i++) {
    const row = rows.nth(i)
    out.push({
      label: (await row.locator('.log-label').innerText()).trim(),
      hex: await hexOf(row.locator('.hexblock')),
    })
  }
  return out
}

function matchingBytes(a: string, b: string): number {
  expect(a.length).toBe(b.length)
  let n = 0
  for (let i = 0; i < a.length; i += 2) if (a.slice(i, i + 2) === b.slice(i, i + 2)) n++
  return n
}

function num(text: string, re: RegExp): number {
  const m = text.match(re)
  expect(m, `no match for ${re} in: ${text}`).not.toBeNull()
  return Number(m![1].replace(/,/g, ''))
}

/** "2.5 days" / "under a second" -> seconds, or null when unparseable on purpose. */
function durationSeconds(text: string): number | null {
  const m = text.match(/about ([\d.]+) (second|minute|hour|day|year)s?/)
  if (!m) return null
  const unit = { second: 1, minute: 60, hour: 3600, day: 86_400, year: 31_557_600 }[m[2]]!
  return Number(m[1]) * unit
}

const u32be = (n: number) => n.toString(16).padStart(8, '0')
const u16be = (n: number) => n.toString(16).padStart(4, '0')

async function goto(page: Page): Promise<void> {
  await page.goto('.')
  await expect(page.locator('#clone')).toBeVisible()
}

// --- Chapter 1: the headline ----------------------------------------------

test('clone: both restored servers emit byte-identical output, and the verdict is that tally', async ({
  page,
}) => {
  test.setTimeout(60_000)
  await goto(page)
  const clone = page.locator('#clone')
  const live = page.locator('#clone > div[role="status"]')
  const serverA = clone.locator('.machine').nth(0)
  const serverB = clone.locator('.machine').nth(1)
  await expect(serverA.locator('h3')).toHaveText('Server A')
  await expect(serverB.locator('h3')).toHaveText('Server B')

  await clone.getByRole('button', { name: /Snapshot & restore/ }).click()
  await expect(live).toContainText('Internal state (K, V): IDENTICAL')
  await expect(serverB.locator('.sync-badge')).toHaveText('≡ identical to A')
  await expect(serverB.locator('.sync-badge')).toHaveAttribute('data-tone', 'alarm')
  await expect(serverA.locator('.log-row')).toHaveCount(0)

  await clone.getByRole('button', { name: /Auto-run/ }).click()
  await expect(serverA.locator('.log-row')).toHaveCount(CLONE_SCRIPT.length, { timeout: 30_000 })
  await expect(serverB.locator('.log-row')).toHaveCount(CLONE_SCRIPT.length)

  // The bytes on screen, not the sentence about them.
  const rowsA = await logRows(serverA)
  const rowsB = await logRows(serverB)
  let identical = 0
  for (const [i, spec] of CLONE_SCRIPT.entries()) {
    expect(rowsA[i].label).toBe(spec.label)
    expect(rowsB[i].label).toBe(spec.label)
    expect(rowsA[i].hex.length).toBe(spec.bytes * 2)
    expect(rowsB[i].hex.length).toBe(spec.bytes * 2)
    if (rowsA[i].hex === rowsB[i].hex) identical++
  }
  expect(identical, 'every field of a restored clone must match byte for byte').toBe(
    CLONE_SCRIPT.length,
  )
  // Two different fields must not be the same bytes; otherwise "identical" is vacuous.
  expect(new Set(rowsA.map((r) => r.hex)).size).toBe(CLONE_SCRIPT.length)

  // The tally line is read off the same comparison — parts and whole must agree.
  const tally = clone.locator('p.result-line').filter({ hasText: 'Byte-for-byte comparison' })
  const tallyText = await tally.innerText()
  expect(num(tallyText, /: (\d+) of \d+/)).toBe(identical)
  expect(num(tallyText, / of (\d+) /)).toBe(rowsA.length)
  await expect(tally).toContainText('IDENTICAL')
  await expect(tally).toContainText('the streams never diverge')

  // Two-track verdict: correct primitive, collapsed system.
  await expect(clone.locator('.indicator.primitive')).toContainText('HMAC_DRBG operating correctly')
  const verdict = clone.locator('.indicator.verdict')
  await expect(verdict).toHaveAttribute('data-state', 'collapsed')
  await expect(verdict).toContainText('INTEGRITY COLLAPSED')
  await expect(verdict).toContainText('share every nonce and every key')

  // The consequence callout only belongs on a run that actually collapsed.
  const callout = clone.locator('.callout')
  await expect(callout).toHaveCount(1)
  await expect(callout).toContainText('confidentiality is already gone')
  await expect(callout).toContainText('the ECDSA signing key falls out')
  await expect(callout.locator('a[href*="ecdsa-forge"]').first()).toBeVisible()

  // Both servers' live (K, V) chips read the same state.
  const kv = async (m: Locator) => (await m.locator('.state-hex').allInnerTexts()).join('|')
  expect(await kv(serverA)).toBe(await kv(serverB))
  expect(await kv(serverA)).not.toContain('—')
})

test('clone: fresh entropy on Server B diverges every field and flips the verdict', async ({
  page,
}) => {
  test.setTimeout(60_000)
  await goto(page)
  const clone = page.locator('#clone')
  const serverA = clone.locator('.machine').nth(0)
  const serverB = clone.locator('.machine').nth(1)

  await clone.getByRole('button', { name: /Give Server B its own entropy/ }).click()
  await expect(page.locator('#clone > div[role="status"]')).toContainText('Internal state now DIFFERS')
  await expect(serverB.locator('.sync-badge')).toHaveText('≠ differs from A')
  await expect(serverB.locator('.sync-badge')).toHaveAttribute('data-tone', 'ok')
  await expect(serverA.locator('.log-row')).toHaveCount(CLONE_SCRIPT.length, { timeout: 30_000 })

  const rowsA = await logRows(serverA)
  const rowsB = await logRows(serverB)
  let matches = 0
  for (let i = 0; i < rowsA.length; i++) if (rowsA[i].hex === rowsB[i].hex) matches++
  expect(matches, 'one fresh entropy input must break the shared future').toBe(0)

  const line = clone.locator('p.result-line').filter({ hasText: 'Comparison after Server B' })
  const text = await line.innerText()
  expect(num(text, /: (\d+) of \d+ fields match/)).toBe(matches)
  expect(num(text, /of (\d+) fields match/)).toBe(rowsA.length)
  await expect(line).toContainText('DIVERGE')

  const verdict = clone.locator('.indicator.verdict')
  await expect(verdict).toHaveAttribute('data-state', 'intact')
  await expect(verdict).toContainText('INTEGRITY RESTORED')
  // The collapse callout must NOT survive onto a run that did not collapse.
  await expect(clone.locator('.callout')).toHaveCount(0)
})

test('clone: restoring after a finished run re-arms Step and Auto-run', async ({ page }) => {
  // Regression: the panel used to leave both stepping controls disabled after the script
  // ran out, so "press Step" pointed at a dead button and the demo could not be re-run.
  test.setTimeout(60_000)
  await goto(page)
  const clone = page.locator('#clone')
  const serverA = clone.locator('.machine').nth(0)
  const step = clone.getByRole('button', { name: /^Step/ })
  const auto = clone.getByRole('button', { name: /^Auto-run/ })

  await auto.click()
  await expect(serverA.locator('.log-row')).toHaveCount(CLONE_SCRIPT.length, { timeout: 30_000 })
  await expect(step).toBeDisabled()

  await clone.getByRole('button', { name: /Snapshot & restore/ }).click()
  await expect(page.locator('#clone > div[role="status"]')).toContainText('press Step')
  await expect(step).toBeEnabled()
  await expect(auto).toBeEnabled()
  await expect(serverA.locator('.log-row')).toHaveCount(0)

  await step.click()
  await expect(serverA.locator('.log-row')).toHaveCount(1)
})

// --- Chapter 2: fork() -----------------------------------------------------

test('fork: the un-reseeded child reproduces the parent byte for byte, the reseeded child does not', async ({
  page,
}) => {
  test.setTimeout(60_000)
  await goto(page)
  const fork = page.locator('#fork')
  const parent = fork.locator('.machine').nth(0)
  const inherited = fork.locator('.machine').nth(1)
  const reseeded = fork.locator('.machine').nth(2)
  await expect(parent.locator('h3')).toHaveText('Parent process')
  await expect(inherited.locator('h3')).toHaveText('Child — no reseed')
  await expect(reseeded.locator('h3')).toHaveText('Child — reseeded')

  await fork.getByRole('button', { name: /Run fork/ }).click()
  await expect(parent.locator('.log-row')).toHaveCount(2, { timeout: 30_000 })

  // Inherited state is identical at the fork point; the reseeded child's is not.
  await expect(inherited.locator('.sync-badge')).toHaveText('≡ identical to parent')
  await expect(inherited.locator('.sync-badge')).toHaveAttribute('data-tone', 'alarm')
  await expect(reseeded.locator('.sync-badge')).toHaveText('≠ differs')
  await expect(reseeded.locator('.sync-badge')).toHaveAttribute('data-tone', 'ok')

  const rowsP = await logRows(parent)
  const rowsI = await logRows(inherited)
  const rowsR = await logRows(reseeded)
  expect(rowsP.map((r) => r.label)).toEqual(['Next nonce (public)', 'Next key (secret)'])
  expect(rowsP.map((r) => r.hex.length / 2)).toEqual([16, 32])

  // Every child tally must equal the byte-by-byte count of the hex printed beside it.
  for (const [child, rows, expectIdentical] of [
    [inherited, rowsI, true],
    [reseeded, rowsR, false],
  ] as const) {
    const tallies = child.locator('.byte-tally')
    await expect(tallies).toHaveCount(2)
    for (let i = 0; i < rows.length; i++) {
      const actual = matchingBytes(rows[i].hex, rowsP[i].hex)
      const text = await tallies.nth(i).innerText()
      expect(num(text, /^(\d+) of \d+ bytes match/), `tally ${i} of ${await child.locator('h3').innerText()}`).toBe(actual)
      expect(num(text, /of (\d+) bytes match/)).toBe(rows[i].hex.length / 2)
      if (expectIdentical) {
        expect(rows[i].hex).toBe(rowsP[i].hex)
        expect(actual).toBe(rows[i].hex.length / 2)
        await expect(tallies.nth(i)).toHaveAttribute('data-tone', 'alarm')
        await expect(tallies.nth(i)).toContainText('the parent’s secret, byte for byte')
      } else {
        expect(rows[i].hex).not.toBe(rowsP[i].hex)
        // Independent bytes still coincide ~1/256 of the time; the panel says so.
        expect(actual).toBeLessThan(rows[i].hex.length / 2)
        await expect(tallies.nth(i)).toHaveAttribute('data-tone', 'ok')
      }
    }
  }

  const line = fork.locator('p.result-line').filter({ hasText: 'Inherited child vs parent' })
  await expect(line).toContainText('Inherited child vs parent: IDENTICAL')
  await expect(line).toContainText('reseeded child vs parent: DIFFERENT')
  const verdict = fork.locator('.indicator.verdict')
  await expect(verdict).toHaveAttribute('data-state', 'collapsed')
  await expect(verdict).toContainText('CHILD SECRET PREDICTABLE')
  await expect(fork.locator('.indicator.primitive')).toContainText('DRBG correct in every process')
})

test('fork: forking again after a finished run re-arms Step and Run fork', async ({ page }) => {
  // Regression: same dead-control bug as the clone panel.
  test.setTimeout(60_000)
  await goto(page)
  const fork = page.locator('#fork')
  const parent = fork.locator('.machine').nth(0)
  const step = fork.getByRole('button', { name: /^Step/ })
  const auto = fork.getByRole('button', { name: /Run fork/ })

  await auto.click()
  await expect(parent.locator('.log-row')).toHaveCount(2, { timeout: 30_000 })
  await expect(step).toBeDisabled()

  await fork.getByRole('button', { name: /Fork the process/ }).click()
  await expect(page.locator('#fork > div[role="status"]')).toContainText('Step to compare their output')
  await expect(step).toBeEnabled()
  await expect(auto).toBeEnabled()
  await expect(parent.locator('.log-row')).toHaveCount(0)

  await step.click()
  await expect(parent.locator('.log-row')).toHaveCount(1)
})

// --- Chapter 4: the reseed that wasn't -------------------------------------

async function readReseedRun(page: Page): Promise<{
  serverCells: string[]
  attackerCells: string[]
  hits: number[]
  postMatches: number
  counter: number
}> {
  const lanes = page.locator('#reseed .tl-lane')
  await expect(lanes).toHaveCount(2)
  const cellHex = async (lane: Locator) => {
    const cells = lane.locator('.blk')
    const out: string[] = []
    for (let i = 0; i < (await cells.count()); i++) out.push(await hexOf(cells.nth(i).locator('code')))
    return out
  }
  const serverCells = await cellHex(lanes.nth(0))
  const attackerCells = await cellHex(lanes.nth(1))
  const hits: number[] = []
  const cells = lanes.nth(1).locator('.blk')
  for (let i = 0; i < (await cells.count()); i++) {
    if (await cells.nth(i).evaluate((n) => n.classList.contains('hit'))) hits.push(i)
  }
  const live = await page.locator('#reseed > div[role="status"]').innerText()
  return {
    serverCells,
    attackerCells,
    hits,
    postMatches: num(live, /After the reseed, (\d+) of \d+ predicted blocks matched/),
    counter: num(await page.locator('#reseed .health').innerText(), /reseed_counter = (\d+)/),
  }
}

test('reseed: a no-op reseed keeps the attacker in lockstep while the counter still reads healthy', async ({
  page,
}) => {
  test.setTimeout(60_000)
  await goto(page)
  const reseed = page.locator('#reseed')
  await reseed.getByRole('button', { name: /silent no-op reseed/ }).click()

  const run = await readReseedRun(page)
  expect(run.serverCells).toHaveLength(4) // 2 blocks before the reseed, 2 after
  expect(run.attackerCells).toHaveLength(4)
  // Pre-reseed the attacker already tracks the server; that is the premise.
  expect(run.attackerCells.slice(0, 2)).toEqual(run.serverCells.slice(0, 2))
  // Post-reseed, with no entropy in, it keeps tracking it.
  expect(run.attackerCells.slice(2)).toEqual(run.serverCells.slice(2))

  // The hit tags must be exactly the cells whose bytes match, and the "N of 2" line must
  // be the post-reseed part of that same total: 2 pre-reseed hits + N.
  const actualHits = run.attackerCells.filter((h, i) => h === run.serverCells[i]).length
  expect(run.hits.length).toBe(actualHits)
  expect(run.hits.length).toBe(2 + run.postMatches)
  expect(run.postMatches).toBe(2)
  await expect(reseed.locator('.blk.hit')).toHaveCount(4)
  await expect(reseed.locator('.blk.miss')).toHaveCount(0)
  await expect(reseed.locator('.blk.hit').first()).toContainText('attacker predicted')

  const live = page.locator('#reseed > div[role="status"]')
  await expect(live).toContainText('STILL MATCHES')
  await expect(live).toContainText('nothing unpredictable went in')
  const verdict = reseed.locator('.indicator.verdict')
  await expect(verdict).toHaveAttribute('data-state', 'collapsed')
  await expect(verdict).toContainText('STILL PREDICTABLE')
  await expect(reseed.locator('.indicator.primitive')).toContainText('Reseed executed, counter reset')

  // The irony: a compromised run still reads healthy. counter = 1 (reset) + 2 blocks.
  expect(run.counter).toBe(3)
  await expect(reseed.locator('.health')).toContainText('fresh / healthy')
})

test('reseed: a proper reseed diverges the attacker — with an identical health counter', async ({
  page,
}) => {
  test.setTimeout(60_000)
  await goto(page)
  const reseed = page.locator('#reseed')

  await reseed.getByRole('button', { name: /silent no-op reseed/ }).click()
  const noop = await readReseedRun(page)

  await reseed.getByRole('button', { name: /proper reseed/ }).click()
  const proper = await readReseedRun(page)

  // Same premise before the reseed...
  expect(proper.attackerCells.slice(0, 2)).toEqual(proper.serverCells.slice(0, 2))
  // ...different outcome after it.
  expect(proper.attackerCells[2]).not.toBe(proper.serverCells[2])
  expect(proper.attackerCells[3]).not.toBe(proper.serverCells[3])
  expect(proper.postMatches).toBe(0)
  expect(proper.hits.length).toBe(2 + proper.postMatches)
  await expect(reseed.locator('.blk.hit')).toHaveCount(2)
  await expect(reseed.locator('.blk.miss')).toHaveCount(2)
  await expect(reseed.locator('.blk.miss').first()).toContainText('attacker lost track')

  const live = page.locator('#reseed > div[role="status"]')
  await expect(live).toContainText('DIVERGES')
  const verdict = reseed.locator('.indicator.verdict')
  await expect(verdict).toHaveAttribute('data-state', 'intact')
  await expect(verdict).toContainText('FORWARD SECRECY RESTORED')

  // The whole point of the panel: the counter cannot tell the two runs apart.
  expect(proper.counter).toBe(noop.counter)
  await expect(reseed.locator('.health')).toContainText('fresh / healthy')
})

// --- Chapter 3: starve the seed -------------------------------------------

test('entropy: every slider stop is internally consistent and gates live enumeration at 2^16', async ({
  page,
}) => {
  test.setTimeout(60_000)
  await goto(page)
  const entropy = page.locator('#entropy')
  const slider = page.locator('#entropy-slider')
  const recover = entropy.getByRole('button', { name: /Run seed recovery/ })
  await expect(slider).toHaveAttribute('max', String(STOPS.length - 1))

  for (const stop of STOPS) {
    await slider.fill(stop.value)
    const figure = await entropy.locator('.ks-figure').innerText()
    const readout = await page.locator('#entropy-readout').innerText()
    const where = `stop 2^${stop.bits}`

    expect(figure, where).toContain(`2^${stop.bits}`)
    if (stop.bits <= 53) {
      // "2^14 = 16,384" — the printed count must be the printed exponent.
      expect(num(figure, /= ([\d,]+)/), where).toBe(2 ** stop.bits)
    }
    // The meter is the same number as a fraction of 256 bits.
    const width = await entropy.locator('.ks-meter span').getAttribute('style')
    expect(width, where).toBe(`width:${Math.max(2, Math.round((stop.bits / 256) * 100))}%`)

    const enumerable = !stop.full && stop.bits <= ENUMERABLE_MAX_BITS
    await expect(recover, where).toBeEnabled({ enabled: enumerable })

    if (stop.full) {
      expect(readout, where).toContain('Not enumerable: 2^256 candidates')
      expect(readout, where).toContain('This is the entropy that protects you.')
      // No boot-material table exists for a kernel-CSPRNG seed.
      await expect(entropy.locator('table.facts')).toHaveCount(0)
      await expect(entropy.locator('[aria-label="Observed values"]')).toContainText('getrandom()')
      expect(await recover.getAttribute('title'), where).toContain(`limit 2^${ENUMERABLE_MAX_BITS}`)
    } else {
      await expect(entropy.locator('table.facts')).toHaveCount(1)
      if (enumerable) {
        expect(readout, where).toContain('Small enough to enumerate live')
        expect(num(readout, /to sweep all ([\d,]+)/), where).toBe(2 ** stop.bits)
      } else {
        expect(readout, where).toContain('too long to watch here')
        expect(readout, where).toContain(`~${GUESS_RATE.toLocaleString('en-US')} candidate`)
      }
      // The quoted sweep time must be the quoted keyspace at the quoted rate.
      const secs = durationSeconds(readout)
      if (secs !== null) {
        expect(Math.abs((secs * GUESS_RATE) / 2 ** stop.bits - 1), where).toBeLessThan(0.05)
      }
    }
  }
})

test('entropy: brute force recovers the real seed — SHA-256 of the material the page published', async ({
  page,
}) => {
  test.setTimeout(120_000)
  await goto(page)
  const entropy = page.locator('#entropy')
  const result = page.locator('#entropy > div[role="status"]')
  await page.locator('#entropy-slider').fill('6') // 2^14: a sweep a browser finishes

  const fact = (label: string) =>
    entropy.locator('table.facts tr', { has: page.locator('th', { hasText: label }) }).locator('td')
  await expect(fact('MAC address (public)')).toHaveText('52:54:00:12:34:56')
  const bootTime = (await fact('Boot time').innerText()).trim()
  const pid = Number((await fact('Process ID').innerText()).trim())
  const material = (await fact('12-byte seed material').innerText()).trim()
  const nonce = await hexOf(entropy.locator('[aria-label="Observed values"] .hexblock'))

  // The published material is exactly MAC ‖ boot-time ‖ PID, as the label claims.
  const bootSec = Date.parse(bootTime) / 1000
  expect(material).toBe(MAC_HEX + u32be(bootSec) + u16be(pid))
  expect(nonce).toHaveLength(32) // 16-byte public nonce

  await entropy.getByRole('button', { name: /Run seed recovery/ }).click()
  await expect(entropy.locator('.cracked')).toBeVisible({ timeout: 90_000 })

  // The cracked banner must name the same machine the victim table published.
  await expect(entropy.locator('.cracked')).toContainText(
    `This machine booted at ${bootTime} as PID ${pid}.`,
  )

  const seedHex = await hexOf(result.locator('.hexblock').nth(0))
  const keyHex = await hexOf(result.locator('.hexblock').nth(1))
  // THE headline check: the recovered seed is SHA-256 of the material on screen. The page
  // brute-forced it; this recomputes it independently and demands they agree.
  expect(seedHex).toBe(createHash('sha256').update(Buffer.from(material, 'hex')).digest('hex'))
  expect(keyHex).toHaveLength(64) // 32-byte session key
  expect(keyHex).not.toBe(seedHex)
  expect(keyHex).not.toBe(nonce)
  // No byte is highlighted as wrong: the recovered key IS the victim's session key.
  await expect(result.locator('.byte-diff')).toHaveCount(0)

  // The guess count must be the index of the seed it found, +1 (0-based sweep).
  const resultText = await result.innerText()
  const guesses = num(resultText, /Recovered the seed after ([\d,]+) guesses/)
  const secretIndex = (bootSec - BASE_TIME) * 2 ** BOOT_PID_BITS + pid
  expect(guesses).toBe(secretIndex + 1)
  expect(guesses).toBeLessThanOrEqual(2 ** 14)
  expect(resultText).toContain('reproduces the published nonce exactly')

  // The progress label must report the same sweep the result line does, not a stale batch.
  const progress = await entropy.locator('p.result-line[role="status"]').innerText()
  expect(num(progress, /Tried ([\d,]+) of/)).toBe(guesses)
  expect(num(progress, /of ([\d,]+) seeds/)).toBe(2 ** 14)
  await expect(entropy.locator('.progress span')).toHaveAttribute('style', 'width: 100%;')

  const verdict = entropy.locator('.indicator.verdict')
  await expect(verdict).toHaveAttribute('data-state', 'collapsed')
  await expect(verdict).toContainText('KEY RECOVERED')
  await expect(entropy.locator('.indicator.primitive')).toContainText('DRBG reproduced bit-for-bit')
})

test('entropy: a new victim machine is genuinely a new machine, and 2^31 stays un-run', async ({
  page,
}) => {
  test.setTimeout(60_000)
  await goto(page)
  const entropy = page.locator('#entropy')
  await page.locator('#entropy-slider').fill('1') // 2^31: too large to sweep here
  const recover = entropy.getByRole('button', { name: /Run seed recovery/ })
  await expect(recover).toBeDisabled()

  const materialCell = entropy.locator('table.facts td').last()
  const seen = new Set<string>()
  for (let i = 0; i < 3; i++) {
    seen.add((await materialCell.innerText()).trim())
    await entropy.getByRole('button', { name: /New victim machine/ }).click()
  }
  seen.add((await materialCell.innerText()).trim())
  // Four independent draws from a 2^31 space: repeats are not a thing that happens.
  expect(seen.size).toBe(4)
  for (const m of seen) expect(m.slice(0, 12)).toBe(MAC_HEX)
})

// --- the page as a whole ---------------------------------------------------

test('tour: the guided tour drives the real panels and lands its closing line', async ({ page }) => {
  test.setTimeout(120_000)
  await goto(page)
  const bar = page.locator('.tour-bar')
  await expect(bar).toBeHidden()

  await page.locator('#start-tour').click()
  await expect(bar).toBeVisible()
  await expect(page.locator('.tour-dot')).toHaveCount(4)
  await expect(page.locator('.tour-text')).toContainText('Chapter 1 — Clone')
  // It drives the real panel, not a scripted replica: the clone log fills in.
  await expect(page.locator('#clone .machine').first().locator('.log-row')).not.toHaveCount(0, {
    timeout: 30_000,
  })

  const next = bar.getByRole('button', { name: /Next/ })
  for (const chapter of ['Chapter 2 — Fork', 'Chapter 3 — Starve', 'Chapter 4 — Stale']) {
    await next.click()
    await expect(page.locator('.tour-text')).toContainText(chapter, { timeout: 30_000 })
  }
  await next.click()
  await expect(page.locator('.tour-text')).toContainText(
    'The generator did nothing wrong. Nobody attacked it.',
    { timeout: 30_000 },
  )
  await expect(next).toBeHidden()

  await bar.getByRole('button', { name: /Exit/ }).click()
  await expect(bar).toBeHidden()
})

test('page: the five chapters the README promises are present and deep-linkable', async ({
  page,
}) => {
  await goto(page)
  const chapters: [string, string][] = [
    ['clone', 'Chapter 1 · The headline'],
    ['fork', 'Chapter 2 · fork() safety'],
    ['entropy', 'Chapter 3 · Break it yourself'],
    ['reseed', 'Chapter 4 · The reseed that wasn’t'],
    ['history', 'Chapter 5 · This already happened'],
  ]
  for (const [id, kicker] of chapters) {
    await expect(page.locator(`#${id} .panel-kicker`)).toHaveText(kicker)
    await expect(page.locator(`.chapter-nav a[href="#${id}"]`)).toHaveCount(1)
  }
  // Every panel states its scope limit, per the lab's own convention.
  await expect(page.locator('.panel .not-this')).toHaveCount(chapters.length)

  // The historical numbers the README quotes, on the page.
  const history = page.locator('#history')
  await expect(history).toContainText('CVE-2008-0166')
  await expect(history).toContainText('32,768')
  await expect(history).toContainText('13 May 2008')
  await expect(history).toContainText('0.75% of TLS certificates')
  await expect(history).toContainText('0.50% of TLS hosts')
  await expect(history).toContainText('0.03% of SSH hosts')
  await expect(history).toContainText('1.03% of SSH hosts')
})
