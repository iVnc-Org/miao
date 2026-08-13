import { memo } from 'react'
import { Radio, Zap, LoaderCircle, Plus } from 'lucide-react'
import { Button, SectionCard } from './ui.jsx'
import {
  classNames,
  formatDelay,
  getDelayTone,
  protocolLabel
} from '../utils.js'
import { useI18n } from '../i18n.jsx'

const ProxyTile = memo(function ProxyTile({
  nodeName,
  delay,
  isActive,
  isTesting,
  disabled,
  onSwitchProxy,
  onTestDelay,
  group,
  testingLabel,
  timeoutLabel,
}) {
  return (
    <div
      className={classNames('proxy-tile', isActive && 'active', disabled && 'disabled')}
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled}
      onClick={() => !disabled && !isTesting && onSwitchProxy(group, nodeName)}
      onKeyDown={(event) => {
        if (!disabled && !isTesting && (event.key === 'Enter' || event.key === ' ')) {
          event.preventDefault()
          onSwitchProxy(group, nodeName)
        }
      }}
    >
      <div className="proxy-tile-top">
        {isActive
          ? <div className="proxy-tag"><span className="proxy-tag-dot" /><span>{nodeName}</span></div>
          : <span className="proxy-node-name">{nodeName}</span>}
      </div>
      <button
        className={classNames('proxy-test-chip', getDelayTone(delay))}
        onClick={(event) => { event.stopPropagation(); onTestDelay(nodeName); }}
        disabled={disabled || isTesting}
      >
        {isTesting
          ? <LoaderCircle size={10} className="spin" />
          : <Zap size={10} />}
        <span>{isTesting ? testingLabel : formatDelay(delay, timeoutLabel)}</span>
      </button>
    </div>
  )
})

export function ProxyCard({
  status,
  primaryGroup,
  primaryGroupName,
  interactive,
  currentNodeMeta,
  delays,
  testingNodes,
  testingGroup,
  onTestDelay,
  onTestGroupDelays,
  onSwitchProxy,
  onOpenAddNode
}) {
  const { t } = useI18n()
  const currentNodeDelay = primaryGroup?.now ? delays[primaryGroup.now] : undefined
  const isTestingCurrent = primaryGroup?.now ? testingNodes[primaryGroup.now] : false
  const timeoutLabel = t('delay.timeout')

  return (
    <SectionCard
      className="proxy-card"
      bodyClassName="panel-body-tight"
      header={
        <div className="section-header">
          <div className="section-title-wrap">
            <Radio size={14} className="section-icon" />
            <span>{t('proxy.title')}</span>
          </div>
          <Button
            tone="secondary"
            size="sm"
            icon={<Zap size={12} />}
            loading={testingGroup === primaryGroupName}
            disabled={!primaryGroup || !interactive}
            onClick={() => primaryGroup && onTestGroupDelays(primaryGroupName, primaryGroup.all)}
          >
            {t('proxy.testDelay')}
          </Button>
        </div>
      }
    >
      <button
        className="current-node-banner"
        onClick={() => primaryGroup?.now && onTestDelay(primaryGroup.now)}
        disabled={!interactive || !primaryGroup?.now || Boolean(testingNodes[primaryGroup?.now])}
      >
        <div className="banner-icon-wrap"><span className="banner-dot" /></div>
        <div className="banner-copy">
          <span className="banner-label">{t('proxy.currentNode')}</span>
          <strong>{primaryGroup?.now || t('proxy.unselected')}</strong>
          <span className="banner-meta">
            {currentNodeMeta
              ? `${currentNodeMeta.server}:${currentNodeMeta.server_port} · ${protocolLabel(currentNodeMeta.node_type)}`
              : primaryGroup
                ? status.running ? t('proxy.fromGroup', { name: primaryGroupName }) : t('proxy.fromInventory')
                : t('proxy.noNodes')}
          </span>
        </div>
        <div className={classNames('banner-delay', getDelayTone(currentNodeDelay))}>
          {isTestingCurrent
            ? <LoaderCircle size={20} className="spin" />
            : <strong>{currentNodeDelay !== undefined && currentNodeDelay >= 0 ? currentNodeDelay : '--'}</strong>}
          <span>ms</span>
        </div>
      </button>

      <div className="proxy-grid-wrap">
        {primaryGroup ? (
          <div className="proxy-grid">
            {primaryGroup.all.map((nodeName) => (
              <ProxyTile
                key={nodeName}
                nodeName={nodeName}
                delay={delays[nodeName]}
                isActive={primaryGroup.now === nodeName}
                isTesting={Boolean(testingNodes[nodeName])}
                disabled={!interactive}
                group={primaryGroupName}
                onSwitchProxy={onSwitchProxy}
                onTestDelay={onTestDelay}
                testingLabel={t('proxy.testing')}
                timeoutLabel={timeoutLabel}
              />
            ))}
            <button className="proxy-tile add-tile" onClick={onOpenAddNode}>
              <Plus size={13} />
              <span>{t('proxy.addNode')}</span>
            </button>
          </div>
        ) : <div className="empty-block">{t('proxy.empty')}</div>}
      </div>
    </SectionCard>
  )
}
