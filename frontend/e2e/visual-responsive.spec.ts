import { expect, test, type Page } from '@playwright/test'

const sizes = [
  { name: '1440x900', width: 1440, height: 900 },
  { name: '1280x800', width: 1280, height: 800 },
  { name: '768x1024', width: 768, height: 1024 },
  { name: '390x844', width: 390, height: 844 },
]

function captureDiagnostics(page: Page) {
  const failures: string[] = []
  page.on('console', (message) => { if (message.type() === 'error') failures.push(`console: ${message.text()}`) })
  page.on('pageerror', (error) => failures.push(`page: ${error.message}`))
  page.on('requestfailed', (request) => failures.push(`request: ${request.url()} ${request.failure()?.errorText ?? ''}`))
  return failures
}

for (const size of sizes) {
  test(`responsive evidence workspace ${size.name}`, async ({ page }) => {
    const failures = captureDiagnostics(page)
    await page.setViewportSize({ width: size.width, height: size.height })
    await page.goto('/')
    await page.getByRole('button', { name: 'Run Guided Demo' }).click()
    await page.getByRole('button', { name: /Secure Baseline/ }).click()

    await page.getByRole('link', { name: 'Tunnel' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Tunnel reconstruction' })).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-3/workspace-tunnel-${size.name}.png`, fullPage: true })

    await page.getByRole('link', { name: 'Evidence' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Evidence ledger' })).toBeVisible()
    await expect(page.getByText('ev-protocol-ike-001').first()).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-3/evidence-${size.name}.png`, fullPage: true })

    await page.getByRole('link', { name: 'Report' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Analysis report' })).toBeVisible()
    await expect(page.getByRole('heading', { level: 2, name: 'Limitations' })).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-3/report-${size.name}.png`, fullPage: true })

    const horizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(horizontalOverflow).toBeLessThanOrEqual(1)
    expect(failures).toEqual([])
  })
}

test('print report composition retains provenance and limitations', async ({ page }) => {
  const failures = captureDiagnostics(page)
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  await page.getByRole('button', { name: 'Run Guided Demo' }).click()
  await page.getByRole('button', { name: /Secure Baseline/ }).click()
  await page.getByRole('link', { name: 'Report' }).click()
  await page.emulateMedia({ media: 'print' })
  await expect(page.getByText('Observed', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('ESP payloads were not decrypted.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Print report' })).toBeHidden()
  await page.screenshot({ path: 'artifacts/visual-review-3/report-print-1440x900.png', fullPage: true })
  expect(failures).toEqual([])
})
