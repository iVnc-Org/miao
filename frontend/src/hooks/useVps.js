import { useCallback, useEffect, useRef, useState } from 'react'

export function useVps() {
  const [jobs, setJobs] = useState([])
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const hiddenTask = useRef('')
  const request = useCallback(async (endpoint, body, signal) => {
    const response = await fetch(`/api/vps/${endpoint}`, {
      method: body ? 'POST' : 'GET', signal,
      headers: { 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    const payload = await response.json()
    if (!response.ok || !payload.success) {
      const cause = new Error(payload.message || `HTTP ${response.status}`)
      cause.status = response.status
      throw cause
    }
    return payload.data
  }, [])
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
        if (!stopped) {
          setError(cause.message)
          if (cause.status === 403) {
            setJobs([])
          }
        }
      } finally {
        clearTimeout(timeout)
        if (!stopped) timer = setTimeout(poll, 2000)
      }
    }
    poll()
    return () => { stopped = true; clearTimeout(timer); controller?.abort() }
  }, [request])
  const close = () => {
    const latest = jobs[0]
    if (latest) localStorage.setItem('miao-vps-dismissed', `${latest.id}:${latest.stage}`)
    hiddenTask.current = latest?.id || ''
    setOpen(false)
  }
  return { jobs, open, setOpen, error, request, close }
}
