import { useEffect, useMemo, useState } from 'react'
import { ListFilter, Save, Sparkles } from 'lucide-react'
import { Button, SectionCard } from './ui.jsx'
import { classNames } from '../utils.js'
import { normalizeProcessProxyConfig } from '../hooks/useApi.js'

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

export function ProcessProxyCard({ proxyMode, config, loading, disabled, onSave, showToast }) {
  const normalizedConfig = useMemo(() => normalizeProcessProxyConfig(config), [config])
  const [mode, setMode] = useState(normalizedConfig.mode)
  const [namesText, setNamesText] = useState(namesToText(normalizedConfig.match.names))

  useEffect(() => {
    setMode(normalizedConfig.mode)
    setNamesText(namesToText(normalizedConfig.match.names))
  }, [normalizedConfig])

  const parsedNames = useMemo(() => {
    try {
      return { names: parseProcessNames(namesText), valid: true }
    } catch {
      return { names: [], valid: false }
    }
  }, [namesText])
  const names = parsedNames.names

  const dirty = !parsedNames.valid
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

    if (nextNames.length === 0) {
      showToast('进程代理模式至少需要填写一个进程名', 'error')
      return
    }

    onSave({
      ...normalizedConfig,
      mode,
      match: {
        ...normalizedConfig.match,
        names: nextNames,
      },
      dns_follow_process: true,
      bypass_action: normalizedConfig.bypass_action || 'bypass',
    })
  }

  if (proxyMode !== 'process') return null

  return (
    <SectionCard
      bodyClassName="panel-body-tight"
      header={
        <div className="section-header">
          <div className="section-title-wrap">
            <ListFilter size={14} className="section-icon" />
            <span>进程代理</span>
            <span className="counter-pill">{names.length}</span>
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
        <div className="tun-process-segment" role="group" aria-label="进程代理名单类型">
          <button
            type="button"
            className={classNames('route-mode-option', mode === 'blacklist' && 'active')}
            disabled={disabled || loading}
            aria-pressed={mode === 'blacklist'}
            onClick={() => setMode('blacklist')}
          >
            <span>黑名单</span>
          </button>
          <button
            type="button"
            className={classNames('route-mode-option', mode === 'whitelist' && 'active')}
            disabled={disabled || loading}
            aria-pressed={mode === 'whitelist'}
            onClick={() => setMode('whitelist')}
          >
            <span>白名单</span>
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
          {mode === 'whitelist'
            ? '仅白名单进程使用代理，其他进程直接连接。'
            : '黑名单进程直接连接，其他进程使用当前代理节点。'}
        </div>
      </div>
    </SectionCard>
  )
}
