import { expect, test } from '@playwright/test'

import { captureDiagnostics, loadDemo } from './support'

const viewports = [
  { name: '1440x900', width: 1440, height: 900 },
  { name: '1280x800', width: 1280, height: 800 },
  { name: '768x1024', width: 768, height: 1024 },
  { name: '390x844', width: 390, height: 844 },
] as const

for (const viewport of viewports) {
  test(`final PFS-disabled judge story ${viewport.name}`, async ({ page }) => {
    const failures = captureDiagnostics(page)
    await page.setViewportSize(viewport)
    await loadDemo(page, /PFS Disabled/)

    await expect(page.getByText('PFS disabled').first()).toBeVisible()
    await page.getByRole('link', { name: 'Tunnel' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Tunnel reconstruction' })).toBeVisible()

    await page.getByRole('link', { name: 'Security' }).click()
    const evidenceButton = page.getByRole('button', { name: /Inspect evidence for CHILD-SA PFS disabled/i })
    await evidenceButton.click()
    await expect(page.getByRole('dialog', { name: 'Evidence inspector' })).toContainText('Controlled strongSwan/XFRM')
    await page.getByRole('button', { name: 'Close evidence inspector' }).click()
    await expect(evidenceButton).toBeFocused()

    await page.getByRole('link', { name: 'Traffic' }).click()
    await expect(page.getByText('Payload visibility: 0%').first()).toBeVisible()

    await page.getByRole('link', { name: 'Report' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Analysis report' })).toBeVisible()
    await expect(page.getByRole('heading', { level: 2, name: 'Limitations' })).toBeVisible()

    const horizontalOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    )
    expect(horizontalOverflow).toBeLessThanOrEqual(1)
    expect(failures).toEqual([])

    await page.screenshot({
      path: `../docs/evidence/frontend/final-${viewport.name}.png`,
      fullPage: true,
    })
  })
}
