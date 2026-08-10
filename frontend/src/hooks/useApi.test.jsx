import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useConnectivity, useDelays, usePool } from './useApi.js'

const DELAY_RESULTS_STORAGE_KEY = 'miao.delay-results.v1'
const CONNECTIVITY_RESULTS_STORAGE_KEY = 'miao.connectivity-results.v1'

beforeEach(() => {
  window.localStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('useDelays', () => {
  it('restores valid cached delays and persists the next test result', async () => {
    window.localStorage.setItem(DELAY_RESULTS_STORAGE_KEY, JSON.stringify({
      cached: 86,
      timeout: -1,
      invalid: '42',
    }))
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ delay: 35 }),
    }))

    const { result } = renderHook(() => useDelays())

    expect(result.current.delays).toEqual({ cached: 86, timeout: -1 })

    await act(async () => {
      await result.current.testDelay('/api/clash', 'cached')
    })

    expect(result.current.delays).toEqual({ cached: 35, timeout: -1 })
    await waitFor(() => {
      expect(JSON.parse(window.localStorage.getItem(DELAY_RESULTS_STORAGE_KEY))).toEqual({
        cached: 35,
        timeout: -1,
      })
    })
  })
})

describe('useConnectivity', () => {
  it('keeps untested cached sites while replacing tested site results', async () => {
    window.localStorage.setItem(CONNECTIVITY_RESULTS_STORAGE_KEY, JSON.stringify({
      Google: { success: true, latency_ms: 120 },
      GitHub: { success: false },
      invalid: { success: true, latency_ms: null },
    }))
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      json: async () => ({
        success: true,
        data: { success: true, latency_ms: 48 },
      }),
    }))

    const { result } = renderHook(() => useConnectivity())

    expect(result.current.connectivityResults).toEqual({
      Google: { success: true, latency_ms: 120 },
      GitHub: { success: false },
    })

    await act(async () => {
      await result.current.testAllConnectivity([
        { name: 'Google', url: 'https://www.google.com' },
      ])
    })

    expect(result.current.connectivityResults).toEqual({
      Google: { success: true, latency_ms: 48 },
      GitHub: { success: false },
    })
    await waitFor(() => {
      expect(JSON.parse(window.localStorage.getItem(CONNECTIVITY_RESULTS_STORAGE_KEY))).toEqual({
        Google: { success: true, latency_ms: 48 },
        GitHub: { success: false },
      })
    })
  })
})

describe('usePool', () => {
  it('tests the selected endpoint and stores the HTTP result', async () => {
    const responseData = {
      tag: 'node-a',
      status_code: 404,
      status_text: 'Not Found',
      body: { ip: '3.0.3.0' },
    }
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ success: true, data: responseData }),
    })
    vi.stubGlobal('fetch', fetchMock)
    const endpoint = { tag: 'node-a', port: 51000 }
    const { result } = renderHook(() => usePool('pool'))

    await act(async () => {
      await result.current.testPoolEndpoint(endpoint)
    })

    expect(fetchMock).toHaveBeenCalledWith('/api/share/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(endpoint),
    })
    expect(result.current.testingPoolPort).toBeNull()
    expect(result.current.poolTestResult).toEqual(responseData)
  })
})
