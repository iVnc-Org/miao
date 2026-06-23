import { useEffect, useMemo, useState } from 'react'
import { ListFilter, Save, Sparkles } from 'lucide-react'
import { Button, SectionCard } from './ui.jsx'
import { classNames } from '../utils.js'
import { normalizeTunProcessConfig } from '../hooks/useApi.js'

const SUGGESTED_NAMES = ['curl', 'git', 'git-remote-https', 'ssh']

function namesToText(names) {
  return (names || []).join(', ')
}

function parseProcessNames(value) {
  const names = value
    .split(/[,\n，]+/)
    .map((item) => item.trim())
    .filter(Boolean)

  for (const name of names) {
    if (/\s/.test(name)) {
      throw new Error(`进程名不支持命令参数或空格：${name}`)
    }
    if (name.includes('/')) {
      throw new Error(`进程名不能包含路径分隔符：${name}`)
    }
  }

  return Array.from(new Set(names))
}

export function TunProcessCard({ config, loading, disabled, onSave, showToast }) {
  const normalizedConfig = useMemo(() => normalizeTunProcessConfig(config), [config])
  const [enabled, setEnabled] = useState(normalizedConfig.enabled)
  const [mode, setMode] = useState(normalizedConfig.mode)
  const [namesText, setNamesText] = useState(namesToText(normalizedConfig.match.names))

  useEffect(() => {
    setEnabled(normalizedConfig.enabled)
    setMode(normalizedConfig.mode)
    setNamesText(namesToText(normalizedConfig.match.names))
  }, [normalizedConfig])

  const names = useMemo(() => {
    try {
      return parseProcessNames(namesText)
    } catch {
      return []
    }
  }, [namesText])

  const dirty = enabled !== normalizedConfig.enabled
    || mode !== normalizedConfig.mode
    || namesToText(names) !== namesToText(normalizedConfig.match.names)

  const handleSuggestedName = (name) => {
    try {
      const current = parseProcessNames(namesText)
      if (!current.includes(name)) {
        setNamesText(namesToText([...current, name]))
      }
    } catch {
      setNamesText(name)
    }
  }

  const handleSave = () => {
    let nextNames
    try {
      nextNames = parseProcessNames(namesText)
    } catch (error) {
      showToast(error.message, 'error')
      return
    }

    if (enabled && nextNames.length === 0) {
      showToast('启用进程代理时至少需要填写一个进程名', 'error')
      return
    }

    onSave({
      ...normalizedConfig,
      enabled,
      mode,
      match: {
        ...normalizedConfig.match,
        names: nextNames,
      },
      dns_follow_process: true,
      bypass_action: normalizedConfig.bypass_action || 'bypass',
    })
  }

  return (
    <SectionCard
      bodyClassName="panel-body-tight"
      header={
        <div className="section-header">
          <div className="section-title-wrap">
            <ListFilter size={14} className="section-icon" />
            <span>进程代理</span>
            {enabled && <span className="counter-pill">{names.length}</span>}
          </div>
          <Button
            tone="secondary"
            size="sm"
            icon={<Save size={12} />}
            loading={loading}
            disabled={disabled || loading || !dirty}
            onClick={handleSave}
          >
            保存
          </Button>
        </div>
      }
    >
      <div className="tun-process-body">
        <label className="tun-process-toggle">
          <input
            type="checkbox"
            checked={enabled}
            disabled={disabled || loading}
            onChange={(event) => setEnabled(event.target.checked)}
          />
          <span>启用 TUN 进程代理</span>
        </label>

        {enabled ? (
          <>
            <div className="tun-process-segment" role="group" aria-label="进程代理模式">
              <button
                type="button"
                className={classNames('route-mode-option', mode === 'global_bypass' && 'active')}
                disabled={disabled || loading}
                aria-pressed={mode === 'global_bypass'}
                onClick={() => setMode('global_bypass')}
              >
                <span>清单绕过</span>
              </button>
              <button
                type="button"
                className={classNames('route-mode-option', mode === 'process_only' && 'active')}
                disabled={disabled || loading}
                aria-pressed={mode === 'process_only'}
                onClick={() => setMode('process_only')}
              >
                <span>仅清单代理</span>
              </button>
            </div>

            <label className="field tun-process-field">
              <span>进程/命令名</span>
              <textarea
                value={namesText}
                disabled={disabled || loading}
                onChange={(event) => setNamesText(event.target.value)}
                placeholder="curl, git, git-remote-https, ssh"
                rows={3}
              />
            </label>

            <div className="tun-process-suggestions">
              <Sparkles size={12} className="section-icon" />
              {SUGGESTED_NAMES.map((name) => (
                <button
                  key={name}
                  type="button"
                  className="process-chip"
                  disabled={disabled || loading}
                  onClick={() => handleSuggestedName(name)}
                >
                  {name}
                </button>
              ))}
            </div>

            <div className="tun-process-note">
              {mode === 'process_only'
                ? '非清单进程将绕过 sing-box。'
                : '清单内进程将绕过代理。'}
            </div>
          </>
        ) : (
          <div className="empty-block">未启用进程代理</div>
        )}
      </div>
    </SectionCard>
  )
}
