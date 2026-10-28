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

it('shows an unacknowledged failure after refresh', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply({ id: 'failed-job', active: false, stage: 'Upgrade failed: SHA256 mismatch' })))
  const { result } = renderHook(() => useUpgrade())
  await waitFor(() => expect(result.current.open).toBe(true))
  expect(result.current.status.stage).toContain('SHA256 mismatch')
})
