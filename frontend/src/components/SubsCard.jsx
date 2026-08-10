import { memo, useState } from 'react'
import {
  Check,
  CircleAlert,
  CircleX,
  Clock3,
  Database,
  Link2,
  Plus,
  RefreshCw,
  Rss,
  X,
} from 'lucide-react'
import { Button, SectionCard } from './ui.jsx'
import { classNames, maskSubscription } from '../utils.js'

function subscriptionStatus(sub) {
  if (sub.error) {
    return { tone: 'error', icon: CircleX, text: sub.error }
  }

  switch (sub.state) {
    case 'ok':
      return { tone: 'success', icon: Check, text: `${sub.node_count} 个节点 · 已更新` }
    case 'cached':
      return { tone: 'cached', icon: Database, text: `${sub.node_count} 个节点 · 使用本地缓存` }
    case 'expired':
      return {
        tone: 'warning',
        icon: CircleAlert,
        text: `订阅链接已失效 · 仍在使用 ${sub.node_count} 个缓存节点`,
      }
    default:
      return { tone: 'pending', icon: Clock3, text: '等待首次获取' }
  }
}

const SubRow = memo(function SubRow({ sub, disabled, onDelete, onStartReplace }) {
  const status = subscriptionStatus(sub)
  const StatusIcon = status.icon

  return (
    <div className="list-row">
      <div className={classNames('status-icon-badge', status.tone)}>
        <StatusIcon size={12} />
      </div>
      <div className="list-row-content">
        <div className="list-row-title">{maskSubscription(sub.url)}</div>
        <div className={classNames('list-row-meta', status.tone)}>{status.text}</div>
      </div>
      <div className="list-row-actions">
        {sub.state === 'expired' && (
          <button
            type="button"
            className="icon-button subtle"
            disabled={disabled}
            onClick={() => onStartReplace(sub.url)}
            title="替换链接"
            aria-label="替换订阅链接"
          >
            <Link2 size={13} />
          </button>
        )}
        <button
          type="button"
          className="icon-button subtle"
          disabled={disabled}
          onClick={() => onDelete(sub.url)}
          title="删除订阅"
          aria-label="删除订阅"
        >
          <X size={13} />
        </button>
      </div>
    </div>
  )
})

export function SubsCard({
  subs,
  newSubUrl,
  setNewSubUrl,
  loadingAction,
  onAddSub,
  onDeleteSub,
  onReplaceSub,
  onRefreshSubs,
  isInitializing,
}) {
  const [replacingUrl, setReplacingUrl] = useState('')
  const [replacementUrl, setReplacementUrl] = useState('')
  const busy = isInitializing || Boolean(loadingAction)

  const startReplacement = (url) => {
    setReplacingUrl(url)
    setReplacementUrl('')
  }

  const cancelReplacement = () => {
    setReplacingUrl('')
    setReplacementUrl('')
  }

  const submitReplacement = async () => {
    if (!replacingUrl || !replacementUrl.trim() || busy) return
    const replaced = await onReplaceSub(replacingUrl, replacementUrl)
    if (replaced) cancelReplacement()
  }

  return (
    <SectionCard
      bodyClassName="panel-body-tight"
      header={
        <div className="section-header">
          <div className="section-title-wrap">
            <Rss size={14} className="section-icon" />
            <span>订阅管理</span>
          </div>
          <Button
            tone="secondary"
            size="sm"
            icon={<RefreshCw size={12} />}
            loading={loadingAction === 'refreshSubs'}
            disabled={subs.length === 0 || busy}
            onClick={onRefreshSubs}
          >
            刷新
          </Button>
        </div>
      }
    >
      <div className="list-stack">
        {subs.length === 0
          ? <div className="empty-block">暂无订阅</div>
          : subs.map((sub) => (
            <div key={sub.url} className="subscription-entry">
              <SubRow
                sub={sub}
                disabled={busy}
                onDelete={onDeleteSub}
                onStartReplace={startReplacement}
              />
              {replacingUrl === sub.url && (
                <div className="subscription-replace-row">
                  <input
                    value={replacementUrl}
                    disabled={busy}
                    onChange={(event) => setReplacementUrl(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') submitReplacement()
                      if (event.key === 'Escape') cancelReplacement()
                    }}
                    placeholder="粘贴新的订阅链接..."
                    aria-label="新的订阅链接"
                    autoFocus
                  />
                  <Button
                    tone="secondary"
                    size="sm"
                    icon={<Link2 size={12} />}
                    loading={loadingAction === 'replaceSub'}
                    disabled={!replacementUrl.trim() || busy}
                    onClick={submitReplacement}
                  >
                    替换
                  </Button>
                  <button
                    type="button"
                    className="icon-button subtle"
                    disabled={busy}
                    onClick={cancelReplacement}
                    title="取消替换"
                    aria-label="取消替换"
                  >
                    <X size={13} />
                  </button>
                </div>
              )}
            </div>
          ))}
        <div className="subscription-add-row">
          <input
            value={newSubUrl}
            disabled={busy}
            onChange={(event) => setNewSubUrl(event.target.value)}
            onKeyDown={(event) => event.key === 'Enter' && onAddSub()}
            placeholder="粘贴订阅链接..."
          />
          <Button
            tone="secondary"
            size="sm"
            icon={<Plus size={12} />}
            loading={loadingAction === 'addSub'}
            disabled={busy}
            onClick={onAddSub}
          >
            添加
          </Button>
        </div>
      </div>
    </SectionCard>
  )
}
