import { afterEach, expect, it, vi } from 'vitest'
import { installAuthFetch, setAuthCsrf } from './authFetch.js'
afterEach(() => { vi.unstubAllGlobals(); setAuthCsrf('') })
it('adds CSRF only to same-origin API mutations, with no password or bearer token', async () => {
  const original = vi.fn().mockResolvedValue({ status: 200 })
  vi.stubGlobal('fetch', original)
  installAuthFetch(); setAuthCsrf('csrf')
  await window.fetch('/api/nodes', { method: 'POST' })
  expect(original.mock.calls[0][1].headers.get('X-Miao-CSRF')).toBe('csrf')
  expect(original.mock.calls[0][1].headers.get('Authorization')).toBeNull()
  await window.fetch('https://other.example/api/nodes', { method: 'POST' })
  expect(original.mock.calls[1][1].headers).toBeUndefined()
})
it('ignores obsolete 401 responses after a new session is installed', async () => {
  let complete
  vi.stubGlobal('fetch', vi.fn(() => new Promise(resolve => { complete = resolve })))
  const expired = vi.fn()
  window.addEventListener('miao-auth-expired', expired)
  installAuthFetch(); setAuthCsrf('old')
  const pending = window.fetch('/api/status')
  setAuthCsrf('new'); complete({ status: 401 }); await pending
  expect(expired).not.toHaveBeenCalled()
  const next = window.fetch('/api/status'); complete({ status: 401 }); await next
  expect(expired).toHaveBeenCalledOnce()
  window.removeEventListener('miao-auth-expired', expired)
})
it('expires the page session when a protected authentication action returns 401', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 401 }))
  const expired = vi.fn()
  window.addEventListener('miao-auth-expired', expired)
  installAuthFetch(); setAuthCsrf('csrf')
  await window.fetch('/api/auth/password', { method: 'PUT' })
  expect(expired).toHaveBeenCalledOnce()
  window.removeEventListener('miao-auth-expired', expired)
})
