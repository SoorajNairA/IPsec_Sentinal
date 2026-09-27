import { expect, test } from '@playwright/test'

import { captureDiagnostics, loadDemo } from './support'

test('secure demo reaches evidence and complete report', async ({ page }) => {
  const failures = captureDiagnostics(page)
  await loadDemo(page, /Secure Baseline/)
  await expect(page.getByText('AES-256-GCM').first()).toBeVisible()

  await page.getByRole('link', { name: 'Tunnel' }).click()
  await expect(page.getByText('Session PFS enabled')).toBeVisible()
  await page.getByRole('link', { name: 'Evidence' }).click()
  const evidenceButton = page.getByRole('button', { name: /Inspect evidence ev-protocol-ike-001/i })
  await evidenceButton.click()
  await expect(page.getByRole('dialog', { name: 'Evidence inspector' })).toBeVisible()
  await page.getByRole('button', { name: 'Close evidence inspector' }).click()
  await expect(evidenceButton).toBeFocused()

  await page.getByRole('link', { name: 'Report' }).click()
  await expect(page.getByRole('heading', { name: 'Executive Summary' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Limitations' })).toBeVisible()
  expect(failures).toEqual([])
})

test('reduced motion replaces continuous tunnel flow with static direction markers', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await loadDemo(page, /Secure Baseline/)
  await expect(page.getByTestId('tunnel-flow')).toHaveAttribute('data-motion', 'reduced')
})
