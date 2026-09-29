import { expect, test } from '@playwright/test'

import { captureDiagnostics } from './support'

const realLiveLab = process.env.IPSEC_SENTINEL_LIVE_E2E === '1'

test.describe('real local Live Lab', () => {
  test.skip(!realLiveLab, 'Set IPSEC_SENTINEL_LIVE_E2E=1 and run the privileged loopback agent.')

  test.afterEach(async ({ page }) => {
    const sessionId = await page.evaluate(() => window.localStorage.getItem('ipsec-sentinel.live-session-id')).catch(() => null)
    if (sessionId) {
      await page.request.post(`/api/lab/sessions/${encodeURIComponent(sessionId)}/disconnect`, { data: {} }).catch(() => undefined)
    }
  })

  test('connects, restores replay, runs isolated workloads, rekeys, analyzes, and cleans up', async ({ page }) => {
    test.setTimeout(240_000)
    const failures = captureDiagnostics(page)

    await page.goto('/')
    await page.getByRole('link', { name: 'Start Live Lab' }).click()
    await expect(page.getByRole('heading', { name: 'Start Live Lab' })).toBeVisible()
    await page.getByRole('button', { name: 'Secure Baseline' }).click()
    await page.getByRole('button', { name: 'Create lab session' }).click()
    await expect(page.getByRole('button', { name: 'Connect' })).toBeEnabled()

    const duplicate = await page.request.post('/api/lab/sessions', {
      data: { scenario_id: 'aes128-gcm' },
    })
    expect(duplicate.status()).toBe(409)
    expect((await duplicate.json()).error.code).toBe('ACTIVE_SESSION_EXISTS')

    await page.getByRole('button', { name: 'Connect' }).click()
    await expect(page.getByText('IKE SA INIT request sent')).toBeVisible({ timeout: 90_000 })
    await expect(page.getByText('CHILD SA established', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('XFRM policies installed', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('TUNNEL ACTIVE', { exact: true }).first()).toBeVisible()

    await page.getByRole('button', { name: 'Ping Server' }).click()
    await expect(page.getByText(/icmp workload completed/i)).toBeVisible({ timeout: 90_000 })
    await expect(page.getByTestId('live-esp-flow')).toBeVisible()

    await page.getByRole('button', { name: 'Start Video Stream' }).click()
    await expect(page.getByText(/video workload completed/i)).toBeVisible({ timeout: 120_000 })

    await page.reload()
    await expect(page.getByText('TUNNEL ACTIVE', { exact: true }).first()).toBeVisible({ timeout: 30_000 })
    await expect(page.getByText(/video workload completed/i)).toBeVisible()
    await expect(page.getByTestId('live-esp-flow')).toBeVisible()

    await page.getByRole('button', { name: 'Trigger Rekey' }).click()
    await expect(page.getByText('New CHILD SA and PFS evidence observed')).toBeVisible({ timeout: 90_000 })
    await expect(page.getByText('PFS VERIFIED')).toBeVisible()
    await expect(page.getByText(/New CHILD SA SPI/)).toBeVisible()

    await page.getByRole('button', { name: 'Analyze Session' }).click()
    await expect(page.getByText('Session analysis completed')).toBeVisible({ timeout: 120_000 })
    await expect(page.getByText('VIDEO', { exact: true })).toBeVisible()
    await expect(page.getByText(/raw confidence · AI-INFERRED/)).toBeVisible()
    await expect(page.getByText(/\/100/)).toBeVisible()

    await page.getByRole('button', { name: 'Disconnect' }).click()
    await expect(page.getByText('Session cleanup completed')).toBeVisible({ timeout: 90_000 })
    await expect(page.getByText('DISCONNECTED', { exact: true })).toBeVisible()

    expect(failures.filter((item) => !item.includes('/events'))).toEqual([])
  })
})
