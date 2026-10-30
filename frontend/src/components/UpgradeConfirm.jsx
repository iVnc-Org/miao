import { useEffect, useState } from 'react'
import { useI18n } from '../i18n.jsx'
import { Button } from './ui.jsx'

export const DEFAULT_GITHUB_PROXY = 'https://httptunnel.top/gh/'
const PROXY_STORAGE_KEY = 'miao.upgrade-proxy'

function readUpgradeProxy() {
  try {
    return window.localStorage.getItem(PROXY_STORAGE_KEY) || DEFAULT_GITHUB_PROXY
  } catch {
    return DEFAULT_GITHUB_PROXY
  }
}

function validUpgradeProxy(value) {
  const trimmed = value.trim()
  if (!trimmed) return true
  try {
    const url = new URL(trimmed)
    return url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password && !url.search && !url.hash
  } catch {
    return false
  }
}

export function UpgradeConfirm({ open, current, target, onCancel, onConfirm }) {
  const { t } = useI18n()
  const [proxy, setProxy] = useState(readUpgradeProxy)
  const [error, setError] = useState('')
  useEffect(() => {
    if (open) {
      setProxy(readUpgradeProxy())
      setError('')
    }
  }, [open])
  if (!open) return null
  const confirm = () => {
    const trimmed = proxy.trim()
    if (!validUpgradeProxy(trimmed)) {
      setError(t('confirm.upgradeProxyInvalid'))
      return
    }
    try {
      if (!trimmed || trimmed === DEFAULT_GITHUB_PROXY) window.localStorage.removeItem(PROXY_STORAGE_KEY)
      else window.localStorage.setItem(PROXY_STORAGE_KEY, trimmed.endsWith('/') ? trimmed : `${trimmed}/`)
    } catch {
      // The request still uses the value shown in this dialog.
    }
    onConfirm(trimmed)
  }
  return (
    <div className="modal-overlay">
      <section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="upgrade-confirm-title">
        <h2 id="upgrade-confirm-title">{t('confirm.upgradeTitle')}</h2>
        <p>{t('confirm.upgradeMessage', { current, target })}</p>
        <label className="field">
          <span>{t('confirm.upgradeProxy')}</span>
          <span className="upgrade-proxy-row">
            <input
              aria-label={t('confirm.upgradeProxy')}
              value={proxy}
              spellCheck="false"
              onChange={(event) => { setProxy(event.target.value); setError('') }}
            />
            <Button tone="ghost" size="sm" onClick={() => {
              try { window.localStorage.removeItem(PROXY_STORAGE_KEY) } catch { /* shown value is authoritative */ }
              setProxy(DEFAULT_GITHUB_PROXY)
              setError('')
            }}>{t('confirm.upgradeReset')}</Button>
          </span>
        </label>
        <p className="upgrade-proxy-hint">{t('confirm.upgradeProxyHint')}</p>
        {error && <p role="alert">{error}</p>}
        <div className="modal-actions">
          <Button tone="ghost" size="sm" onClick={onCancel}>{t('modal.cancel')}</Button>
          <Button tone="primary" size="sm" onClick={confirm}>{t('confirm.upgradeConfirm')}</Button>
        </div>
      </section>
    </div>
  )
}
