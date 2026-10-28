import { useCallback, useEffect, useState } from 'react'

export function useUpgrade() {
  const [status, setStatus] = useState(null)
  const [offline, setOffline] = useState(false)
  const [open, setOpen] = useState(false)
  const accept = useCallback((next) => {
    setStatus(next)
    setOffline(false)
    if (next.id && (next.active || localStorage.getItem('miao-upgrade-dismissed') !== next.id)) setOpen(true)
  }, [])
  useEffect(() => {
    let stopped = false
    let timer
    let request
    async function poll() {
      request = new AbortController()
      const timeout = setTimeout(() => request.abort(), 5000)
      try {
        const response = await fetch('/api/upgrade', { signal: request.signal })
        const payload = await response.json()
        if (!payload.success) throw new Error(payload.message)
        if (!stopped) accept(payload.data)
      } catch {
        if (!stopped) setOffline(true)
      } finally {
        clearTimeout(timeout)
        if (!stopped) timer = setTimeout(poll, 1000)
      }
    }
    poll()
    return () => { stopped = true; clearTimeout(timer); request?.abort() }
  }, [accept])
  const start = useCallback(async () => {
    setOpen(true)
    const response = await fetch('/api/upgrade', { method: 'POST' })
    const payload = await response.json()
    if (!payload.success) throw new Error(payload.message)
    accept(payload.data)
  }, [accept])
  const dismiss = () => {
    if (status?.active) return
    if (status?.id) localStorage.setItem('miao-upgrade-dismissed', status.id)
    setOpen(false)
  }
  return { status, offline, open, start, dismiss, show: () => setOpen(true) }
}
