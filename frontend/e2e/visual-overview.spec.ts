import { expect, test, type Page } from '@playwright/test'

const sizes = [
  { name: '1440x900', width: 1440, height: 900 },
  { name: '1280x800', width: 1280, height: 800 },
]

function captureDiagnostics(page: Page) {
  const failures: string[] = []
  page.on('console', (message) => { if (message.type() === 'error') failures.push(`console: ${message.text()}`) })
  page.on('pageerror', (error) => failures.push(`page: ${error.message}`))
  page.on('requestfailed', (request) => failures.push(`request: ${request.url()} ${request.failure()?.errorText ?? ''}`))
  return failures
}

for (const size of sizes) {
  test(`visual review overview ${size.name}`, async ({ page }) => {
    const failures = captureDiagnostics(page)
    await page.setViewportSize({ width: size.width, height: size.height })
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'IPsec Sentinel' })).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-1/landing-${size.name}.png`, fullPage: true })

    await page.getByRole('button', { name: 'Run Guided Demo' }).click()
    await page.getByRole('button', { name: /Secure Baseline/ }).click()
    await expect(page.getByRole('heading', { name: 'Analysis overview' })).toBeVisible()
    await expect(page.getByText('AES-256-GCM').first()).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-1/secure-baseline-${size.name}.png`, fullPage: true })

    await page.getByRole('button', { name: 'New analysis' }).click()
    await page.getByRole('button', { name: 'Run Guided Demo' }).click()
    await page.getByRole('button', { name: /PFS Disabled/ }).click()
    await expect(page.getByText('PFS disabled').first()).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-1/no-pfs-${size.name}.png`, fullPage: true })

    expect(failures).toEqual([])
  })
}
