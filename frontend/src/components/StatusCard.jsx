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
  const modeControlDisabled = modeSwitching || status.initializing
  const modes = [
    { value: 'global', label: t('mode.global'), icon: Globe2 },
    { value: 'process', label: t('mode.process'), icon: ListFilter },
    { value: 'pool', label: t('mode.pool'), icon: Share2 },
  ]
  const stateLabel = status.initializing
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
        tone={status.running ? 'danger' : 'success'}
        icon={<Power size={14} />}
        loading={loadingAction === 'start' || loadingAction === 'stop' || status.initializing}
        disabled={loadingAction === 'start' || loadingAction === 'stop' || status.initializing}
        onClick={onToggleService}
      >
        {status.running ? t('status.stop') : t('status.start')}
      </Button>
    </SectionCard>
  )
}
