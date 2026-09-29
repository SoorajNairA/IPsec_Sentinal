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
  test(`visual review traffic and security ${size.name}`, async ({ page }) => {
    const failures = captureDiagnostics(page)
    await page.setViewportSize({ width: size.width, height: size.height })
    await page.goto('/')

    await page.getByRole('button', { name: 'Run Guided Demo' }).click()
    await page.getByRole('button', { name: /Video Traffic Intelligence/ }).click()
    await page.getByRole('link', { name: 'Traffic' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Traffic intelligence' })).toBeVisible()
    await expect(page.getByText('video', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('Payload visibility: 0%').first()).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-2/traffic-video-${size.name}.png`, fullPage: true })

    await page.getByRole('button', { name: 'New analysis' }).click()
    await page.getByRole('button', { name: 'Run Guided Demo' }).click()
    await page.getByRole('button', { name: /PFS Disabled/ }).click()
    await page.getByRole('link', { name: 'Security' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Security findings' })).toBeVisible()
    await expect(page.getByText(/CHILD-SA PFS disabled/i).first()).toBeVisible()
    await page.screenshot({ path: `artifacts/visual-review-2/security-no-pfs-${size.name}.png`, fullPage: true })

    expect(failures).toEqual([])
  })
}
