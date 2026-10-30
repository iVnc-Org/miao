import { useCallback, useEffect, useRef, useState } from 'react'
import { useI18n } from '../i18n.jsx'
import { setAuthCsrf } from '../authFetch.js'

export function AuthGate({ children }) {
  const { locale } = useI18n()
  const text = (cn, en) => locale === 'zh' ? cn : en
  const epoch = useRef(0)
  const dialogRef = useRef(null)
  const returnFocus = useRef(null)
  const [status, setStatus] = useState(null)
  const [initialConfirm, setInitialConfirm] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [change, setChange] = useState(false)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const clearSecrets = () => { setInitialConfirm(''); setPassword(''); setCurrent(''); setNext(''); setConfirm(''); setChange(false) }
  const expire = useCallback(() => { epoch.current++; setAuthCsrf(''); setStatus(previous => ({ ...previous, authenticated: false })); setInitialConfirm(''); setPassword(''); setCurrent(''); setNext(''); setConfirm(''); setChange(false) }, [])
  useEffect(() => {
    let stopped = false
    let timer
    let controller
    const check = async () => {
      const version = epoch.current
      controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 8000)
      try {
        const response = await fetch('/api/auth/status', { signal: controller.signal })
        const payload = await response.json()
        if (stopped || version !== epoch.current) return
        if (!response.ok || !payload.success) throw new Error('Authentication unavailable')
        setAuthCsrf(payload.data.csrf)
        setStatus(payload.data)
        if (!payload.data.authenticated) { setCurrent(''); setNext(''); setConfirm(''); setChange(false) }
        setError('')
      } catch {
        if (!stopped && version === epoch.current) { expire(); setError('unavailable') }
      } finally {
        clearTimeout(timeout)
        if (!stopped) timer = setTimeout(check, 15000)
      }
    }
    check()
    window.addEventListener('miao-auth-expired', expire)
    // Previous VPS API tokens are no longer used.
    sessionStorage.removeItem('miao-vps-token')
    return () => { stopped = true; clearTimeout(timer); controller?.abort(); window.removeEventListener('miao-auth-expired', expire) }
  }, [expire])
  useEffect(() => {
    if (!change) return
    const previous = document.activeElement
    const dialog = dialogRef.current
    const keydown = event => {
      if (event.key === 'Escape') { event.preventDefault(); clearSecrets() }
      if (event.key !== 'Tab') return
      const fields = [...dialog.querySelectorAll('input, button')].filter(field => !field.disabled)
      if (event.shiftKey && document.activeElement === fields[0]) { event.preventDefault(); fields.at(-1)?.focus() }
      else if (!event.shiftKey && document.activeElement === fields.at(-1)) { event.preventDefault(); fields[0]?.focus() }
    }
    dialog.addEventListener('keydown', keydown)
    return () => { dialog.removeEventListener('keydown', keydown); (returnFocus.current || previous)?.focus() }
  }, [change])
  const submit = async event => {
    event.preventDefault(); setError('')
    const initializing = status.configured === false
    if (initializing && password !== initialConfirm) { setError('mismatch'); return }
    setBusy(true)
    try {
      const response = await fetch(initializing ? '/api/auth/setup' : '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(initializing ? { password, confirm_password: initialConfirm } : { password }) })
      const payload = await response.json()
      if (!response.ok || !payload.success) {
        if (initializing && response.status === 409) {
          epoch.current++; clearSecrets(); setStatus({ configured: true, authenticated: false }); setError('initialized')
        } else setError(response.status === 429 ? 'limited' : initializing ? 'setup' : 'incorrect')
        return
      }
      epoch.current++; setAuthCsrf(payload.data.csrf); setStatus({ configured: true, authenticated: true }); clearSecrets()
    } catch { setError('unavailable') }
    finally { setBusy(false) }
  }
  const logout = async () => {
    setBusy(true); setError('')
    try {
      const response = await fetch('/api/auth/logout', { method: 'POST' })
      if (!response.ok) throw new Error()
      expire()
    } catch { setError('unavailable') }
    finally { setBusy(false) }
  }
  const save = async event => {
    event.preventDefault(); setError('')
    if (next !== confirm) { setError('mismatch'); return }
    setBusy(true)
    try {
      const response = await fetch('/api/auth/password', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ current_password: current, new_password: next }) })
      if (!response.ok) { setError('change'); return }
      clearSecrets(); expire()
    } catch { setError('unavailable') }
    finally { setBusy(false) }
  }
  const errors = {
    initialized: text('密码已设置，请使用当前密码登录。', 'Password is already configured. Sign in with the current password.'),
    setup: text('设置失败，请检查密码格式及认证文件权限。', 'Setup failed. Check password format and authentication file permissions.'),
    unavailable: text('认证暂不可用，请检查服务或通过 CLI 修复密码。', 'Authentication unavailable. Check the service or repair the password through CLI.'),
    incorrect: text('密码错误。', 'Incorrect password.'), limited: text('尝试过于频繁，请一分钟后重试。', 'Too many attempts. Retry in one minute.'),
    mismatch: text('两次新密码不一致。', 'New passwords do not match.'), change: text('修改失败，请检查当前密码和认证文件权限。', 'Update failed. Check current password and authentication file permissions.'),
  }
  if (!status?.authenticated) return <main className="auth-page"><section className="modal-card auth-card">
    <h1>Miao {location.protocol === 'http:' && <span className="vps-help" title={text('HTTP 会明文传输密码，建议使用 HTTPS 或 SSH 隧道。', 'HTTP transmits passwords without encryption. HTTPS or an SSH tunnel is recommended.')}><button type="button" className="vps-help-button" aria-label={text('连接说明', 'Connection information')}>?</button></span>}</h1>
    {status === null ? <p role="status">{text('正在检查登录状态…', 'Checking sign-in…')}</p> : status.configured ? <form onSubmit={submit}>
      <label className="field"><span>{text('面板密码', 'Panel password')}</span><input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
      <button className="btn" disabled={busy || !password}>{text('登录', 'Sign in')}</button>
    </form> : status.configured === false ? <form onSubmit={submit}>
      <h2>{text('设置初始密码', 'Set initial password')}</h2>
      <label className="field"><span>{text('初始密码', 'Initial password')}</span><input type="password" autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
      <label className="field"><span>{text('确认初始密码', 'Confirm initial password')}</span><input type="password" autoComplete="new-password" value={initialConfirm} onChange={event => setInitialConfirm(event.target.value)} required /></label>
      <button className="btn btn-primary" disabled={busy || !password || !initialConfirm}>{text('设置并进入面板', 'Set password and continue')}</button>
    </form> : <p>{text('正在等待认证服务恢复…', 'Waiting for authentication service…')}</p>}
    {error && <p role="alert">{errors[error]}</p>}
  </section></main>
  return <>
    <div className="auth-toolbar"><button className="btn btn-ghost" onClick={event => { returnFocus.current = event.currentTarget; setChange(true); setError('') }}>{text('修改密码', 'Change password')}</button><button className="btn btn-ghost" disabled={busy} onClick={logout}>{text('退出登录', 'Sign out')}</button>{error && !change && <span role="alert">{errors[error]}</span>}</div>
    {children}
    {change && <div className="modal-overlay"><section ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="password-title" className="modal-card auth-card">
      <h2 id="password-title">{text('修改密码', 'Change password')}</h2>
      <form onSubmit={save}>
        <label className="field"><span>{text('当前密码', 'Current password')}</span><input autoFocus type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} required /></label>
        <label className="field"><span>{text('新密码', 'New password')}</span><input type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} required /></label>
        <label className="field"><span>{text('确认新密码', 'Confirm new password')}</span><input type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} required /></label>
        {error && <p role="alert">{errors[error]}</p>}
        <div className="modal-actions"><button type="button" className="btn" onClick={clearSecrets}>{text('取消', 'Cancel')}</button><button className="btn btn-primary" disabled={busy}>{text('保存并重新登录', 'Save and sign in again')}</button></div>
      </form>
    </section></div>}
  </>
}
