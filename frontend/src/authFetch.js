let csrf = ''
let generation = 0
export function setAuthCsrf(value) {
  const next = value || ''
  if (next !== csrf) { csrf = next; generation++ }
}
export function installAuthFetch() {
  const original = window.fetch.bind(window)
  window.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href)
    const api = url.origin === location.origin && url.pathname.startsWith('/api/')
    const version = generation
    let requestOptions = options
    if (api) {
      const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined))
      const method = (options.method || (input instanceof Request ? input.method : 'GET')).toUpperCase()
      if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrf) headers.set('X-Miao-CSRF', csrf)
      requestOptions = { ...options, headers, credentials: 'same-origin' }
    }
    const response = await original(input, requestOptions)
    if (api && response.status === 401 && !['/api/auth/login', '/api/auth/status'].includes(url.pathname) && version === generation) {
      window.dispatchEvent(new Event('miao-auth-expired'))
    }
    return response
  }
}
