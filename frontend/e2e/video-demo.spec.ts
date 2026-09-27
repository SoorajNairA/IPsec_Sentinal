import { expect, test } from '@playwright/test'

import { captureDiagnostics, loadDemo } from './support'

test('video demo exposes real ESP projection and honest AI inference', async ({ page }) => {
  const failures = captureDiagnostics(page)
  await loadDemo(page, /Video Traffic Intelligence/)
  await page.getByRole('link', { name: 'Traffic' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Traffic intelligence' })).toBeVisible()
  expect(await page.getByTestId('packet-mark').count()).toBeGreaterThan(100)
  await expect(page.getByTestId('packet-mark').first()).not.toHaveCSS('stroke', 'none')
  await expect(page.getByText('video', { exact: true })).toBeVisible()
  await expect(page.getByText('100.0% raw / uncalibrated')).toBeVisible()
  await expect(page.getByLabel('AI-inferred provenance')).toBeVisible()
  await expect(page.getByText('Payload visibility: 0%').first()).toBeVisible()
  expect(failures).toEqual([])
})
