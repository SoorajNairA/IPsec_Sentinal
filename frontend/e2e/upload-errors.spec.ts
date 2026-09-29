import { expect, test } from '@playwright/test'

import { captureDiagnostics } from './support'

test('PCAPNG is rejected locally with a supported next action', async ({ page }) => {
  const failures = captureDiagnostics(page)
  await page.goto('/')
  await page.getByLabel('Choose a classic PCAP capture').setInputFiles({ name: 'capture.pcapng', mimeType: 'application/octet-stream', buffer: Buffer.from('pcapng') })
  await expect(page.getByRole('alert')).toContainText('PCAPNG is not supported yet')
  await expect(page.getByRole('alert')).toContainText('Export the capture as classic PCAP and retry')
  expect(failures).toEqual([])
})

test('unexpected analyzer details are replaced with safe copy and a diagnostic code', async ({ page }) => {
  const failures = captureDiagnostics(page)
  await page.route('**/api/analyze', async (route) => route.fulfill({
    status: 500,
    contentType: 'application/json',
    body: JSON.stringify({ error: { code: 'ANALYZER_FAILURE', message: 'Traceback: C:\\private\\secret.key' } }),
  }))
  await page.goto('/')
  await page.getByLabel('Choose a classic PCAP capture').setInputFiles({ name: 'capture.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: Buffer.from('capture') })
  await expect(page.getByRole('alert')).toContainText('Local analysis could not complete')
  await expect(page.getByRole('alert')).toContainText('ANALYZER_FAILURE')
  await expect(page.getByText(/private\\secret/i)).toHaveCount(0)
  expect(failures).toHaveLength(1)
  expect(failures[0]).toContain('500')
})
