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

export function StatusCard({
  status,
  traffic,
  loadingAction,
  onToggleService,
  onSetMode,
  onOpenConnections
}) {
  const sourceText = status.config_source === 'cache'
    ? '缓存配置'
    : status.config_source === 'generated'
      ? '最新配置'
      : null
  const runningText = `PID: ${status.pid ?? '--'} · 运行时长: ${formatUptime(status.uptime_secs)}${sourceText ? ` · ${sourceText}` : ''}`
  const currentMode = status.mode || 'global'
  const modeSwitching = loadingAction === 'mode'
  const modeControlDisabled = modeSwitching || status.initializing
  const modes = [
    { value: 'global', label: '全局代理', icon: Globe2 },
    { value: 'process', label: '进程代理', icon: ListFilter },
    { value: 'pool', label: '代理池', icon: Share2 },
  ]

  return (
    <SectionCard className="status-card" bodyClassName="status-card-body" header={null}>
      <div className="status-left-wrap">
        <div className="status-pill-icon"><span className="status-pill-dot" /></div>
        <div className="status-copy">
          <div className="status-title">
            Sing-box {status.initializing ? '初始化中' : status.running ? '运行中' : '已停止'}
          </div>
          <div className="status-subtitle">
            {status.running 
              ? runningText
              : status.initializing 
                ? '正在准备配置并启动服务…'
                : '等待启动服务'}
          </div>
        </div>
      </div>

      <button type="button" className="traffic-chip" onClick={onOpenConnections} title="查看连接统计">
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
      <div className="route-mode-segment" role="group" aria-label="代理模式">
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
        {status.running ? '停止服务' : '启动服务'}
      </Button>
    </SectionCard>
  )
}
