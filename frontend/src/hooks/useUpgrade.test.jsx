import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useUpgrade } from './useUpgrade.js'

beforeEach(() => localStorage.clear())
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })
const reply = (data) => ({ json: async () => ({ success: true, data }) })

it('restores an active upgrade after refresh and keeps it visible across downtime', async () => {
  vi.useFakeTimers()
  const status = { id: 'job', active: true, stage: 'Restarting', events: ['Downloading', 'Restarting'] }
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply(status)).mockRejectedValueOnce(new Error('restart'))
    .mockResolvedValue(reply({ ...status, active: false, stage: 'Upgrade complete' })))
  const { result, unmount } = renderHook(() => useUpgrade())
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  expect(result.current.open).toBe(true)
  expect(result.current.status.active).toBe(true)
  await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
  expect(result.current.offline).toBe(true)
  expect(result.current.status.active).toBe(true)
  await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
  expect(result.current.status.stage).toBe('Upgrade complete')
  expect(result.current.offline).toBe(false)
  act(() => result.current.dismiss())
  expect(result.current.open).toBe(false)
  expect(localStorage.getItem('miao-upgrade-dismissed')).toBe('job')
  unmount()
})

it('starts with the selected proxy and requests cancellation', async () => {
  const fetch = vi.fn()
    .mockResolvedValueOnce(reply({ id: '', active: false, stage: '', events: [] }))
    .mockResolvedValueOnce(reply({ id: 'job', active: true, stage: 'Checking release', events: [] }))
    .mockResolvedValueOnce(reply({ id: 'job', active: false, stage: 'Upgrade cancelled', events: [] }))
  vi.stubGlobal('fetch', fetch)
  const { result } = renderHook(() => useUpgrade())
  await waitFor(() => expect(result.current.status).not.toBeNull())
  await act(async () => { await result.current.start('https://example.test/gh/') })
  expect(fetch.mock.calls[1][0]).toBe('/api/upgrade')
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ github_proxy: 'https://example.test/gh/' })
  await act(async () => { await result.current.cancel() })
  expect(fetch.mock.calls[2][0]).toBe('/api/upgrade/cancel')
  expect(result.current.status.stage).toBe('Upgrade cancelled')
})

it('shows an unacknowledged failure after refresh', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply({ id: 'failed-job', active: false, stage: 'Upgrade failed: SHA256 mismatch' })))
  const { result } = renderHook(() => useUpgrade())
  await waitFor(() => expect(result.current.open).toBe(true))
  expect(result.current.status.stage).toContain('SHA256 mismatch')
})
