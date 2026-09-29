import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

import { loadDemo } from './support'

async function expectNoSeriousViolations(page: Parameters<typeof AxeBuilder>[0]['page']) {
  const result = await new AxeBuilder({ page }).analyze()
  expect(result.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''))).toEqual([])
}

test('landing and analysis workspace have no serious or critical axe violations', async ({ page }) => {
  await page.goto('/')
  await expectNoSeriousViolations(page)
  await loadDemo(page, /Secure Baseline/)
  await expectNoSeriousViolations(page)
  await page.getByRole('link', { name: 'Report' }).click()
  await expectNoSeriousViolations(page)
})

test('primary intake is keyboard operable', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Drop a packet capture/i }).focus()
  await expect(page.getByRole('button', { name: /Drop a packet capture/i })).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(page.getByText('Local Analysis')).toBeVisible()
})
