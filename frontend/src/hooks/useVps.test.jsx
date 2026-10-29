import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useVps } from './useVps.js'

const reply = data => ({ ok: true, json: async () => ({ success: true, data }) })
beforeEach(() => { localStorage.clear(); sessionStorage.clear() })
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

it('restores active tasks after refresh but respects closing for this page session', async () => {
  vi.useFakeTimers()
  const task = { id: 'task', active: true, stage: 'downloading', events: [] }
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply([task])))
  const { result, unmount } = renderHook(() => useVps())
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  expect(result.current.open).toBe(true)
  act(() => result.current.close())
  await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
  expect(result.current.open).toBe(false)
  unmount()
  const refreshed = renderHook(() => useVps())
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  expect(refreshed.result.current.open).toBe(true)
  refreshed.unmount()
})

it('retains task state during a failed poll and stores only the API token in session storage', async () => {
  vi.useFakeTimers()
  const task = { id: 'task', active: true, stage: 'activating', events: [] }
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply([task])).mockRejectedValue(new Error('offline')))
  const { result, unmount } = renderHook(() => useVps())
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
  expect(result.current.jobs[0].stage).toBe('activating')
  expect(result.current.error).toBe('offline')
  act(() => result.current.updateToken('access-token'))
  expect(sessionStorage.getItem('miao-vps-token')).toBe('access-token')
  expect(localStorage.getItem('miao-vps-token')).toBeNull()
  unmount()
})
