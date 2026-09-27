import { expect, test } from '@playwright/test'

import { captureDiagnostics, loadDemo } from './support'

test('PFS-disabled demo connects warning, deduction, and retained evidence', async ({ page }) => {
  const failures = captureDiagnostics(page)
  await loadDemo(page, /PFS Disabled/)
  await expect(page.getByText('PFS disabled').first()).toBeVisible()
  await page.getByRole('link', { name: 'Security' }).click()
  await expect(page.getByText('CHILD-SA PFS disabled').first()).toBeVisible()
  const evidenceButton = page.getByRole('button', { name: /Inspect evidence for CHILD-SA PFS disabled/i })
  await evidenceButton.click()
  await expect(page.getByRole('dialog', { name: 'Evidence inspector' })).toContainText('Controlled strongSwan/XFRM')
  await page.getByRole('button', { name: 'Close evidence inspector' }).click()
  await expect(evidenceButton).toBeFocused()
  expect(failures).toEqual([])
})
