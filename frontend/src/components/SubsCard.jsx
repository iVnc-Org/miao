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
import { SubscriptionModal } from './modals.jsx'
import { classNames, maskSubscription } from '../utils.js'
import { useI18n } from '../i18n.jsx'

function subscriptionStatus(sub, t) {
  if (sub.error) {
    return { tone: 'error', icon: CircleX, text: sub.error }
  }

  switch (sub.state) {
    case 'ok':
      return {
        tone: 'success',
        icon: Check,
        text: sub.local
          ? t('subs.statusOkLocal', { count: sub.node_count })
          : t('subs.statusOkRemote', { count: sub.node_count }),
      }
    case 'cached':
      return {
        tone: 'cached',
        icon: Database,
        text: sub.local
          ? t('subs.statusCachedLocal', { count: sub.node_count })
          : t('subs.statusCachedRemote', { count: sub.node_count }),
      }
    case 'expired':
      return {
        tone: 'warning',
        icon: CircleAlert,
        text: sub.local
          ? t('subs.statusExpiredLocal', { count: sub.node_count })
          : t('subs.statusExpiredRemote', { count: sub.node_count }),
      }
    default:
      return {
        tone: 'pending',
        icon: Clock3,
        text: sub.local ? t('subs.statusPendingLocal') : t('subs.statusPendingRemote'),
      }
  }
}

const SubRow = memo(function SubRow({ sub, disabled, onDelete, onStartReplace, t }) {
  const status = subscriptionStatus(sub, t)
  const StatusIcon = status.icon
  const title = sub.name || (sub.local ? t('subs.localName') : maskSubscription(sub.url))

  return (
    <div className="list-row">
      <div className={classNames('status-icon-badge', status.tone)}>
        <StatusIcon size={12} />
      </div>
      <div className="list-row-content">
        <div className="list-row-title">{title}</div>
        <div className={classNames('list-row-meta', status.tone)}>{status.text}</div>
      </div>
      <div className="list-row-actions">
        {sub.state === 'expired' && !sub.local && (
          <button
            type="button"
            className="icon-button subtle"
            disabled={disabled}
            onClick={() => onStartReplace(sub.url)}
            title={t('subs.replaceLink')}
            aria-label={t('subs.replaceLinkAria')}
          >
            <Link2 size={13} />
          </button>
        )}
        <button
          type="button"
          className="icon-button subtle"
          disabled={disabled}
          onClick={() => onDelete(sub.url, title)}
          title={t('subs.delete')}
          aria-label={t('subs.delete')}
        >
          <X size={13} />
        </button>
      </div>
    </div>
  )
})

export function SubsCard({
  subs,
  loadingAction,
  onAddSub,
  onDeleteSub,
  onReplaceSub,
  onRefreshSubs,
  isInitializing,
}) {
  const { t } = useI18n()
  const [addModalOpen, setAddModalOpen] = useState(false)
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
            <span>{t('subs.title')}</span>
          </div>
          <Button
            tone="secondary"
            size="sm"
            icon={<RefreshCw size={12} />}
            loading={loadingAction === 'refreshSubs'}
            disabled={subs.length === 0 || busy}
            onClick={onRefreshSubs}
          >
            {t('subs.refresh')}
          </Button>
        </div>
      }
    >
      <div className="list-stack">
        {subs.length === 0
          ? <div className="empty-block">{t('subs.empty')}</div>
          : subs.map((sub) => (
            <div key={sub.url} className="subscription-entry">
              <SubRow
                sub={sub}
                disabled={busy}
                onDelete={onDeleteSub}
                onStartReplace={startReplacement}
                t={t}
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
                    placeholder={t('subs.replacePlaceholder')}
                    aria-label={t('subs.replaceAria')}
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
                    {t('subs.replace')}
                  </Button>
                  <button
                    type="button"
                    className="icon-button subtle"
                    disabled={busy}
                    onClick={cancelReplacement}
                    title={t('subs.cancelReplace')}
                    aria-label={t('subs.cancelReplace')}
                  >
                    <X size={13} />
                  </button>
                </div>
              )}
            </div>
          ))}
        <div className="subscription-add-action">
          <Button
            tone="secondary"
            size="sm"
            icon={<Plus size={12} />}
            disabled={busy}
            onClick={() => setAddModalOpen(true)}
          >
            {t('subs.add')}
          </Button>
        </div>
      </div>
      {addModalOpen && (
        <SubscriptionModal
          open
          loading={loadingAction === 'addSub'}
          onClose={() => setAddModalOpen(false)}
          onSubmit={onAddSub}
        />
      )}
    </SectionCard>
  )
}
