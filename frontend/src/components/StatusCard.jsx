import {
  ArrowUp,
  ArrowDown,
  Globe2,
  ListFilter,
  Power,
  Share2,
} from 'lucide-react'
import { Button, SectionCard } from './ui.jsx'
import { classNames, formatUptime, formatSpeed } from '../utils.js'
import { useI18n } from '../i18n.jsx'

export function StatusCard({
  status,
  traffic,
  loadingAction,
  onToggleService,
  onSetMode,
  onSetTunRouting,
  onOpenConnections
}) {
  const { t } = useI18n()
  const sourceText = status.config_source === 'cache'
    ? t('status.cacheConfig')
    : status.config_source === 'generated'
      ? t('status.generatedConfig')
      : null
  const runningText = sourceText
    ? t('status.pidUptimeSource', {
      pid: status.pid ?? '--',
      uptime: formatUptime(status.uptime_secs),
      source: sourceText,
    })
    : t('status.pidUptime', {
      pid: status.pid ?? '--',
      uptime: formatUptime(status.uptime_secs),
    })
  const currentMode = status.mode || 'global'
  const modeSwitching = loadingAction === 'mode'
  const starting = loadingAction === 'start' || ['preparing', 'starting'].includes(status.runtime?.phase)
  const modeControlDisabled = modeSwitching || status.initializing || starting
  const modes = [
    { value: 'global', label: t('mode.global'), icon: Globe2 },
    { value: 'process', label: t('mode.process'), icon: ListFilter },
    { value: 'pool', label: t('mode.pool'), icon: Share2 },
  ]
  const stateLabel = status.initializing || starting
    ? t('status.initializing')
    : status.running
      ? t('status.running')
      : t('status.stopped')

  return (
    <SectionCard className="status-card" bodyClassName="status-card-body" header={null}>
      <div className="status-left-wrap">
        <div className="status-pill-icon"><span className="status-pill-dot" /></div>
        <div className="status-copy">
          <div className="status-title">
            {t('status.singbox', { state: stateLabel })}
          </div>
          <div className="status-subtitle">
            {status.running
              ? runningText
              : status.initializing
                ? t('status.preparing')
                : t('status.waitStart')}
          </div>
          {status.mode !== 'pool' && onSetTunRouting && (
            <label className="routing-control">
              <span>{t('routing.label')}</span>
              <select aria-label={t('routing.label')} value={status.tun?.routing || 'auto'}
                disabled={modeControlDisabled || Boolean(loadingAction)} onChange={(event) => onSetTunRouting(event.target.value)}>
                <option value="auto">{t('routing.auto')}</option>
                <option value="nftables">{t('routing.nftables')}</option>
                <option value="policy_route">{t('routing.policy_route')}</option>
              </select>
              {status.runtime?.routing?.effective && status.runtime.routing.effective !== 'none' && (
                <span>{t('routing.effective', { mode: t(`routing.${status.runtime.routing.effective}`) })}</span>
              )}
            </label>
          )}
          {status.runtime?.routing?.reason && <div className="routing-note" role="status">{status.runtime.routing.reason}</div>}
          {status.runtime?.error && <div className="routing-error" role="alert">{status.runtime.error}</div>}
        </div>
      </div>

      <button type="button" className="traffic-chip" onClick={onOpenConnections} title={t('status.viewConnections')}>
        <div className="traffic-item">
          <ArrowUp size={14} className="traffic-icon up" />
          <span>{formatSpeed(traffic.up)}</span>
        </div>
        <div className="traffic-item">
          <ArrowDown size={14} className="traffic-icon down" />
          <span>{formatSpeed(traffic.down)}</span>
        </div>
      </button>

      <div className="status-card-spacer" />
      <div className="route-mode-segment" role="group" aria-label={t('status.modeGroup')}>
        {modes.map(({ value, label, icon: ModeIcon }) => (
          <button
            key={value}
            type="button"
            className={classNames('route-mode-option', currentMode === value && 'active')}
            disabled={modeControlDisabled}
            aria-pressed={currentMode === value}
            onClick={() => onSetMode(value)}
          >
            <ModeIcon size={13} />
            <span>{label}</span>
          </button>
        ))}
      </div>
      <Button
        tone={status.running || starting ? 'danger' : 'success'}
        icon={<Power size={14} />}
        loading={loadingAction === 'stop' || (status.initializing && !starting)}
        disabled={loadingAction === 'stop' || (status.initializing && !starting)}
        onClick={onToggleService}
      >
        {starting ? t('status.cancelStart') : status.running ? t('status.stop') : t('status.start')}
      </Button>
    </SectionCard>
  )
}
