import { expect, type Page } from '@playwright/test'

export function captureDiagnostics(page: Page) {
  const failures: string[] = []
  page.on('console', (message) => { if (message.type() === 'error') failures.push(`console: ${message.text()}`) })
  page.on('pageerror', (error) => failures.push(`page: ${error.message}`))
  page.on('requestfailed', (request) => failures.push(`request: ${request.url()} ${request.failure()?.errorText ?? ''}`))
  return failures
}

export async function loadDemo(page: Page, label: RegExp) {
  await page.goto('/')
  await page.getByRole('button', { name: 'Run Guided Demo' }).click()
  await page.getByRole('button', { name: label }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Analysis overview' })).toBeVisible()
}
