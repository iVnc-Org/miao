import { useEffect, useState } from 'react'
import { useI18n } from '../i18n.jsx'

const LOCKED_STAGES = new Set([
  'Backing up and installing binary',
  'Stopping sing-box',
  'Restarting',
  'Upgrade complete',
])

export function UpgradeModal({ upgrade }) {
  const { t, locale } = useI18n()
  const [cancelling, setCancelling] = useState(false)
  const [cancelError, setCancelError] = useState('')
  const stage = upgrade.status?.stage
  const active = upgrade.status?.active
  useEffect(() => { setCancelError('') }, [stage, active])
  if (!upgrade.open) return null
  const zh = locale === 'zh'
  const labels = {
    'Checking release': '检查最新版本',
    'Checking download access and checksum (GitHub, fallback httptunnel.top/gh)': '检查下载地址与校验文件（GitHub 直连失败后使用 httptunnel.top/gh）',
    'Downloading binary (GitHub, fallback httptunnel.top/gh)': '下载程序（GitHub 直连失败后使用 httptunnel.top/gh）',
    'Downloading binary via GitHub': '正在从 GitHub 下载程序',
    'Downloading binary via httptunnel.top/gh': '正在通过 httptunnel.top/gh 下载程序',
    'Retrying binary download via httptunnel.top/gh': '正在通过 httptunnel.top/gh 重试下载',
    'Upgrade cancelled': '升级已取消',
    'Verifying SHA256 and executable version': '校验 SHA256 与程序版本',
    'Backing up and installing binary': '备份并安装新程序',
    'Stopping sing-box': '停止 sing-box',
    'Restarting': '正在重启并等待核心恢复',
    'Upgrade complete': '升级完成，核心已恢复',
    'Already up to date': '当前已是最新版本',
    'Upgrade interrupted, rolled back, or core recovery failed': '升级中断、已回退，或核心恢复失败',
  }
  const label = (value) => {
    if (!zh || !value) return value
    if (labels[value]) return labels[value]
    const checksum = value.match(/^Checking download access and checksum \(GitHub, fallback (.+)\)$/)
    if (checksum) return `检查下载地址与校验文件（GitHub 直连失败后使用 ${checksum[1]}）`
    const download = value.match(/^Downloading binary \(GitHub, fallback (.+)\)$/)
    if (download) return `下载程序（GitHub 直连失败后使用 ${download[1]}）`
    const direct = value.match(/^Downloading binary via (.+)$/)
    if (direct) return `正在通过 ${direct[1]} 下载程序`
    const retry = value.match(/^Retrying binary download via (.+)$/)
    if (retry) return `正在通过 ${retry[1]} 重试下载`
    return value.replace('Upgrade failed:', '升级失败：')
  }
  const s = upgrade.status
  const locked = LOCKED_STAGES.has(s?.stage)
  const percent = s?.total ? Math.min(100, Math.floor(s.downloaded / s.total * 100)) : 0
  return <div className="modal-overlay">
    <section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="upgrade-title">
      <h2 id="upgrade-title">{zh ? '升级过程' : 'Upgrade progress'}</h2>
      <p role="status">{label(s?.stage) || (zh ? '正在启动升级…' : 'Starting upgrade…')}</p>
      {s?.target && <p>{zh ? '目标版本：' : 'Target: '}{s.target}</p>}
      {s?.total > 0 && <><progress value={s.downloaded} max={s.total} style={{ width: '100%' }} /><p>{percent}% · {(s.downloaded / 1048576).toFixed(1)} / {(s.total / 1048576).toFixed(1)} MB</p></>}
      {upgrade.offline && <p>{zh ? '连接暂时中断，正在等待服务恢复…' : 'Connection lost; waiting for the service to return…'}</p>}
      <ol style={{ maxHeight: '40vh', overflowY: 'auto', overflowWrap: 'anywhere' }}>{s?.events.map((event, index) => <li key={index}>{label(event)}</li>)}</ol>
      {s?.active && <div className="modal-actions">
        <button className="btn btn-ghost" disabled={locked || cancelling} onClick={async () => {
          setCancelError('')
          setCancelling(true)
          try { await upgrade.cancel() } catch (error) { setCancelError(error.message || t('upgrade.cancelFailed')) }
          finally { setCancelling(false) }
        }}>{t('upgrade.cancel')}</button>
      </div>}
      {s?.active && locked && <p>{t('upgrade.locked')}</p>}
      {cancelError && <p role="alert">{cancelError}</p>}
      {!s?.active && <div className="modal-actions"><button onClick={upgrade.dismiss}>{zh ? '关闭' : 'Close'}</button><button onClick={() => window.location.reload()}>{zh ? '刷新页面' : 'Reload page'}</button></div>}
    </section>
  </div>
}
