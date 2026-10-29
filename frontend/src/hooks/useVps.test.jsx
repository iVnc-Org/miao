import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useVps } from './useVps.js'

const reply = data => ({ ok: true, json: async () => ({ success: true, data }) })
beforeEach(() => { localStorage.clear(); sessionStorage.clear() })
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

it('restores active tasks after refresh but respects closing for this page session', async () => {
  vi.useFakeTimers()
  const task = { id: 'task', active: true, stage: 'downloading', events: [] }
  vi.stubGlobal('fetch', vi.fn().mockImplementation(url => Promise.resolve(reply(url.endsWith('/access') ? { local: false, token_configured: true, authorized: true } : [task]))))
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
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ authorized: true })).mockResolvedValueOnce(reply([task])).mockRejectedValue(new Error('offline')))
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

it('permits remote HTTP requests with bearer token and clears tasks when permission is lost', async () => {
  vi.useFakeTimers()
  vi.stubGlobal('location', { protocol: 'http:', hostname: '192.168.1.10' })
  sessionStorage.setItem('miao-vps-token', 'valid-token')
  const task = { id: 'task', active: true, stage: 'checking', events: [] }
  const fetch = vi.fn().mockResolvedValueOnce(reply({ authorized: true }))
    .mockResolvedValueOnce(reply([task]))
    .mockResolvedValue(reply({ authorized: false, local: false, token_configured: true }))
  vi.stubGlobal('fetch', fetch)
  const { result, unmount } = renderHook(() => useVps())
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  expect(result.current.jobs).toHaveLength(1)
  expect(fetch.mock.calls[0][1].headers.Authorization).toBe('Bearer valid-token')
  await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
  expect(result.current.jobs).toEqual([])
  expect(result.current.access.authorized).toBe(false)
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/deployments'))).toHaveLength(1)
  unmount()
})

it('discards a previous token poll that completes after the token changes', async () => {
  vi.useFakeTimers()
  let finishOldPoll
  const fetch = vi.fn().mockResolvedValueOnce(reply({ authorized: true }))
    .mockImplementationOnce(() => new Promise(resolve => { finishOldPoll = resolve }))
    .mockResolvedValue(reply({ authorized: false, local: false, token_configured: true }))
  vi.stubGlobal('fetch', fetch)
  const { result, unmount } = renderHook(() => useVps())
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  act(() => result.current.updateToken('replacement-token'))
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  await act(async () => { finishOldPoll(reply([{ id: 'old', active: true, stage: 'checking' }])) })
  expect(result.current.jobs).toEqual([])
  expect(result.current.open).toBe(false)
  expect(result.current.access.authorized).toBe(false)
  unmount()
})

it('clears displayed tasks if authorization expires between capability and task requests', async () => {
  vi.useFakeTimers()
  const fetch = vi.fn().mockResolvedValueOnce(reply({ authorized: true }))
    .mockResolvedValueOnce(reply([{ id: 'task', active: true, stage: 'checking' }]))
    .mockResolvedValueOnce(reply({ authorized: true }))
    .mockResolvedValue({ ok: false, status: 403, json: async () => ({ success: false, message: 'VPS access token missing or invalid' }) })
  vi.stubGlobal('fetch', fetch)
  const { result, unmount } = renderHook(() => useVps())
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  expect(result.current.jobs).toHaveLength(1)
  await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
  expect(result.current.jobs).toEqual([])
  expect(result.current.access).toBeNull()
  expect(result.current.error).toBe('VPS access token missing or invalid')
  unmount()
})
