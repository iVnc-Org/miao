import { renderHook } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { useApi } from './useApi.js'

afterEach(() => vi.unstubAllGlobals())

it('keeps Stop pending when an older Start response finishes', async () => {
  let finishStart, finishStop
  vi.stubGlobal('fetch', vi.fn()
    .mockImplementationOnce(() => new Promise((resolve) => { finishStart = resolve }))
    .mockImplementationOnce(() => new Promise((resolve) => { finishStop = resolve })))
  const setLoadingAction = vi.fn()
  const { result } = renderHook(() => useApi({ loadingAction: '', setLoadingAction }))
  const start = result.current.apiCall('service/start', { method: 'POST' }, 'start')
  const stop = result.current.apiCall('service/stop', { method: 'POST' }, 'stop')
  finishStart({ ok: true, json: async () => ({ success: true }) })
  await start
  expect(setLoadingAction).toHaveBeenLastCalledWith('stop')
  finishStop({ ok: true, json: async () => ({ success: true }) })
  await stop
  expect(setLoadingAction).toHaveBeenLastCalledWith('')
})
