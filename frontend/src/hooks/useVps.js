import { useCallback, useEffect, useRef, useState } from 'react'

export function useVps() {
  const [token, setToken] = useState(() => sessionStorage.getItem('miao-vps-token') || '')
  const [jobs, setJobs] = useState([])
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const hiddenTask = useRef('')
  const request = useCallback(async (endpoint, body, signal) => {
    if (location.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)) throw new Error('VPS deployment requires HTTPS or a localhost SSH tunnel')
    const response = await fetch(`/api/vps/${endpoint}`, {
      method: body ? 'POST' : 'GET', signal,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    const payload = await response.json()
    if (!response.ok || !payload.success) throw new Error(payload.message || `HTTP ${response.status}`)
    return payload.data
  }, [token])
  useEffect(() => {
    let stopped = false
    let timer
    let controller
    async function poll() {
      controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 8000)
      try {
        const records = await request('deployments', null, controller.signal)
        if (!stopped) {
          setJobs(records)
          setError('')
          const latest = records[0]
          if (latest && hiddenTask.current !== latest.id && (latest.active || localStorage.getItem('miao-vps-dismissed') !== `${latest.id}:${latest.stage}`)) setOpen(true)
        }
      } catch (cause) {
        if (!stopped) setError(cause.message)
      } finally {
        clearTimeout(timeout)
        if (!stopped) timer = setTimeout(poll, 2000)
      }
    }
    poll()
    return () => { stopped = true; clearTimeout(timer); controller?.abort() }
  }, [request])
  const updateToken = value => {
    setToken(value)
    if (value) sessionStorage.setItem('miao-vps-token', value)
    else sessionStorage.removeItem('miao-vps-token')
  }
  const close = () => {
    const latest = jobs[0]
    if (latest) localStorage.setItem('miao-vps-dismissed', `${latest.id}:${latest.stage}`)
    hiddenTask.current = latest?.id || ''
    setOpen(false)
  }
  return { jobs, open, setOpen, error, token, updateToken, request, close }
}
