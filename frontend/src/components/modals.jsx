import { useEffect, useMemo, useState } from 'react'
import {
  X,
  CircleAlert,
  Plus,
  Activity,
  ArrowDown,
  ArrowUp,
  FileText,
  Link2,
  Network,
  Pencil,
  RefreshCw,
  Route,
  Rss,
  Save,
  Search,
  Trash2,
} from 'lucide-react'
import { Button } from './ui.jsx'
import { 
  classNames, 
  CIPHER_OPTIONS, 
  CLIENT_FINGERPRINT_OPTIONS,
  HYSTERIA2_OBFS_OPTIONS,
  NODE_TYPE_OPTIONS,
  PACKET_ENCODING_OPTIONS,
  TRANSPORT_OPTIONS,
  TUIC_CONGESTION_OPTIONS,
  TUIC_UDP_RELAY_OPTIONS,
  VMESS_CIPHER_OPTIONS,
  formatBytes,
  nodeTypeDefaults,
} from '../utils.js'
import { useI18n } from '../i18n.jsx'

export function ConfirmModal({ open, title, message, onCancel, onConfirm }) {
  const { t } = useI18n()
  if (!open) return null
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-card modal-confirm" onClick={(event) => event.stopPropagation()}>
        <div className="modal-title-row">
          <div className="modal-title-wrap">
            <CircleAlert size={18} className="icon-warning" />
            <h3>{title}</h3>
          </div>
          <button className="icon-button" onClick={onCancel}>
            <X size={16} />
          </button>
        </div>
        <p className="modal-message">{message}</p>
        <div className="modal-actions">
          <Button tone="ghost" size="sm" onClick={onCancel}>{t('modal.cancel')}</Button>
          <Button tone="danger" size="sm" onClick={onConfirm}>{t('modal.confirm')}</Button>
        </div>
      </div>
    </div>
  )
}

export function SubscriptionModal({ open, loading, onClose, onSubmit }) {
  const { t } = useI18n()
  const [mode, setMode] = useState('url')
  const [url, setUrl] = useState('')
  const [name, setName] = useState('')
  const [content, setContent] = useState('')

  if (!open) return null

  const canSubmit = mode === 'url' ? Boolean(url.trim()) : Boolean(content.trim())
  const close = () => {
    if (!loading) onClose()
  }
  const submit = async () => {
    if (!canSubmit || loading) return
    const added = await onSubmit(
      mode === 'url'
        ? { mode, url: url.trim() }
        : { mode, name: name.trim(), content: content.trim() }
    )
    if (added) onClose()
  }

  return (
    <div className="modal-overlay" onClick={close}>
      <div
        className="modal-card subscription-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="subscription-modal-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-title-row">
          <div className="modal-title-wrap">
            <Rss size={18} className="icon-accent" />
            <h3 id="subscription-modal-title">{t('subModal.title')}</h3>
          </div>
          <button
            type="button"
            className="icon-button"
            disabled={loading}
            onClick={close}
            title={t('modal.close')}
            aria-label={t('subModal.closeAria')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="subscription-source-switch" aria-label={t('subModal.source')}>
          <button
            type="button"
            className={classNames(mode === 'url' && 'active')}
            aria-pressed={mode === 'url'}
            disabled={loading}
            onClick={() => setMode('url')}
          >
            <Link2 size={14} />
            <span>{t('subModal.urlMode')}</span>
          </button>
          <button
            type="button"
            className={classNames(mode === 'content' && 'active')}
            aria-pressed={mode === 'content'}
            disabled={loading}
            onClick={() => setMode('content')}
          >
            <FileText size={14} />
            <span>{t('subModal.contentMode')}</span>
          </button>
        </div>

        {mode === 'url' ? (
          <div className="form-grid single subscription-modal-fields">
            <label className="field">
              <span>{t('subModal.url')}</span>
              <input
                value={url}
                disabled={loading}
                onChange={(event) => setUrl(event.target.value)}
                onKeyDown={(event) => event.key === 'Enter' && submit()}
                placeholder="https://example.com/subscription"
                autoFocus
              />
            </label>
          </div>
        ) : (
          <div className="form-grid single subscription-modal-fields">
            <label className="field">
              <span>{t('subModal.displayName')}</span>
              <input
                value={name}
                maxLength={80}
                disabled={loading}
                onChange={(event) => setName(event.target.value)}
                placeholder={t('subModal.displayNamePh')}
                autoFocus
              />
            </label>
            <label className="field">
              <span>{t('subModal.content')}</span>
              <textarea
                className="subscription-content-input"
                value={content}
                disabled={loading}
                onChange={(event) => setContent(event.target.value)}
                placeholder={t('subModal.contentPh')}
                spellCheck={false}
              />
            </label>
          </div>
        )}

        <div className="modal-actions">
          <Button tone="ghost" size="sm" disabled={loading} onClick={close}>{t('modal.cancel')}</Button>
          <Button
            tone="primary"
            size="sm"
            icon={<Plus size={12} />}
            loading={loading}
            disabled={!canSubmit}
            onClick={submit}
          >
            {t('modal.add')}
          </Button>
        </div>
      </div>
    </div>
  )
}

export function PoolTestResultModal({ result, onClose }) {
  const { t } = useI18n()
  if (!result) return null

  const statusTone = result.status_code >= 200 && result.status_code < 300
    ? 'success'
    : result.status_code >= 400
      ? 'error'
      : 'warning'
  const statusLabel = `HTTP ${result.status_code}${result.status_text ? ` ${result.status_text}` : ''}`
  const formattedBody = JSON.stringify(result.body, null, 2) ?? 'null'

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card pool-test-modal" onClick={(event) => event.stopPropagation()}>
        <div className="modal-title-row">
          <div className="modal-title-wrap">
            <Activity size={18} className="icon-accent" />
            <h3>{t('poolTest.title')}</h3>
          </div>
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
            title={t('modal.close')}
            aria-label={t('poolTest.closeAria')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="pool-test-summary">
          <span className={classNames('pool-test-status', statusTone)}>{statusLabel}</span>
          <code className="pool-test-tag" title={result.tag}>{result.tag}</code>
        </div>
        <pre className="pool-test-json" aria-label={t('poolTest.jsonAria')}>{formattedBody}</pre>

        <div className="modal-actions">
          <Button tone="secondary" size="sm" onClick={onClose}>{t('modal.close')}</Button>
        </div>
      </div>
    </div>
  )
}

export function NodeModal({ open, editing, nodeType, setNodeType, form, setForm, loading, onClose, onSubmit }) {
  const { t } = useI18n()
  if (!open) return null

  const activeLabel = NODE_TYPE_OPTIONS.find((option) => option.value === nodeType)?.label || nodeType
  const isSimpleProxy = nodeType === 'socks' || nodeType === 'http'
  const requiresPassword = ['hysteria2', 'anytls', 'ss', 'trojan', 'tuic'].includes(nodeType)
  const requiresUuid = ['vmess', 'vless', 'tuic'].includes(nodeType)
  const supportsTransport = ['vmess', 'vless', 'trojan'].includes(nodeType)
  const showsTlsToggle = ['vmess', 'vless'].includes(nodeType)
  const showsTlsFields = !isSimpleProxy && nodeType !== 'ss' && (!showsTlsToggle || form.tls_enabled || form.reality_public_key.trim())
  const pathTransport = ['ws', 'http', 'h2'].includes(form.transport_type)
  const handleNodeTypeChange = (event) => {
    const value = event.target.value
    setNodeType(value)
    setForm((prev) => ({ ...prev, ...nodeTypeDefaults(value) }))
  }

  const canSubmit = form.tag.trim()
    && form.server.trim()
    && form.server_port
    && (isSimpleProxy || !requiresPassword || form.password.trim())
    && (!requiresUuid || form.uuid.trim())
    && (nodeType !== 'hysteria2' || !form.obfs_type || form.obfs_password.trim())

  return (
    <div className="modal-overlay">
      <div className="modal-card node-modal" onClick={(event) => event.stopPropagation()}>
        <div className="modal-title-row">
          <div className="modal-title-wrap">
            {editing
              ? <Pencil size={18} className="icon-accent" />
              : <Plus size={18} className="icon-accent" />}
            <h3>{editing ? t('node.editTitle') : t('node.addTitle')}</h3>
          </div>
          <button className="icon-button" onClick={onClose} title={t('modal.close')} aria-label={t('node.closeAria')}>
            <X size={16} />
          </button>
        </div>

        <div className="form-grid single">
          <label className="field">
            <span>{t('node.protocol')}</span>
            <select value={nodeType} onChange={handleNodeTypeChange}>
              {NODE_TYPE_OPTIONS.map(({ value, label }) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>
        </div>

        <div className="form-grid single">
          <label className="field">
            <span>{t('node.name')}</span>
            <input 
              value={form.tag} 
              onChange={(event) => setForm((prev) => ({ ...prev, tag: event.target.value }))} 
              placeholder={t('node.namePh')} 
            />
          </label>
        </div>

        <div className="form-grid two">
          <label className="field">
            <span>{t('node.server')}</span>
            <input 
              value={form.server} 
              onChange={(event) => setForm((prev) => ({ ...prev, server: event.target.value }))} 
              placeholder="example.com" 
            />
          </label>
          <label className="field">
            <span>{t('node.port')}</span>
            <input
              type="number"
              value={form.server_port}
              onChange={(event) => setForm((prev) => ({ ...prev, server_port: Number(event.target.value || 0) }))}
              placeholder="443"
            />
          </label>
        </div>

        {nodeType === 'ss' && (
          <div className="form-grid single">
            <label className="field">
              <span>{t('node.cipher')}</span>
              <select 
                value={form.cipher} 
                onChange={(event) => setForm((prev) => ({ ...prev, cipher: event.target.value }))}
              >
                {CIPHER_OPTIONS.map((cipher) => (
                  <option key={cipher} value={cipher}>{cipher}</option>
                ))}
              </select>
            </label>
          </div>
        )}

        {nodeType === 'vmess' && (
          <div className="form-grid two">
            <label className="field">
              <span>VMess security</span>
              <select
                value={form.vmess_cipher}
                onChange={(event) => setForm((prev) => ({ ...prev, vmess_cipher: event.target.value }))}
              >
                {VMESS_CIPHER_OPTIONS.map((cipher) => (
                  <option key={cipher} value={cipher}>{cipher}</option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Alter ID</span>
              <input
                type="number"
                value={form.alter_id}
                onChange={(event) => setForm((prev) => ({ ...prev, alter_id: Number(event.target.value || 0) }))}
                min="0"
              />
            </label>
          </div>
        )}

        {requiresUuid && (
          <div className="form-grid single">
            <label className="field">
              <span>UUID</span>
              <input
                value={form.uuid}
                onChange={(event) => setForm((prev) => ({ ...prev, uuid: event.target.value }))}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              />
            </label>
          </div>
        )}

        {showsTlsToggle && (
          <div className="form-grid single">
            <label className="field checkbox-field">
              <input
                type="checkbox"
                checked={form.tls_enabled}
                onChange={(event) => setForm((prev) => ({ ...prev, tls_enabled: event.target.checked }))}
              />
              <span>{t('node.enableTls')}</span>
            </label>
          </div>
        )}

        {isSimpleProxy && (
          <div className="form-grid two">
            <label className="field">
              <span>{t('node.usernameOptional')}</span>
              <input
                value={form.username}
                onChange={(event) => setForm((prev) => ({ ...prev, username: event.target.value }))}
                placeholder={t('node.authOptionalPh')}
              />
            </label>
            <label className="field">
              <span>{t('node.passwordOptional')}</span>
              <input
                value={form.password}
                onChange={(event) => setForm((prev) => ({ ...prev, password: event.target.value }))}
                placeholder={t('node.authOptionalPh')}
              />
            </label>
          </div>
        )}

        {nodeType === 'vless' && (
          <div className="form-grid two">
            <label className="field">
              <span>Flow</span>
              <select
                value={form.flow}
                onChange={(event) => setForm((prev) => ({ ...prev, flow: event.target.value }))}
              >
                <option value="">{t('node.default')}</option>
                <option value="xtls-rprx-vision">xtls-rprx-vision</option>
              </select>
            </label>
            <label className="field">
              <span>Packet encoding</span>
              <select
                value={form.packet_encoding}
                onChange={(event) => setForm((prev) => ({ ...prev, packet_encoding: event.target.value }))}
              >
                {PACKET_ENCODING_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.value ? option.label : t('node.default')}</option>
                ))}
              </select>
            </label>
          </div>
        )}

        {nodeType === 'vmess' && (
          <div className="form-grid single">
            <label className="field">
              <span>Packet encoding</span>
              <select
                value={form.packet_encoding}
                onChange={(event) => setForm((prev) => ({ ...prev, packet_encoding: event.target.value }))}
              >
                {PACKET_ENCODING_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.value ? option.label : t('node.default')}</option>
                ))}
              </select>
            </label>
          </div>
        )}

        {showsTlsFields && (
          <>
            <div className="form-grid two">
              <label className="field">
                <span>{t('node.sniOptional')}</span>
                <input
                  value={form.sni}
                  onChange={(event) => setForm((prev) => ({ ...prev, sni: event.target.value }))}
                  placeholder={t('node.sniPh')}
                />
              </label>
              <label className="field">
                <span>{t('node.fingerprint')}</span>
                <select
                  value={form.client_fingerprint}
                  onChange={(event) => setForm((prev) => ({ ...prev, client_fingerprint: event.target.value }))}
                >
                  {CLIENT_FINGERPRINT_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.value ? option.label : t('node.default')}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="form-grid single">
              <label className="field">
                <span>{t('node.alpnOptional')}</span>
                <input
                  value={form.alpn}
                  onChange={(event) => setForm((prev) => ({ ...prev, alpn: event.target.value }))}
                  placeholder="h2, http/1.1"
                />
              </label>
            </div>
            <div className="form-grid single">
              <label className="field checkbox-field">
                <input
                  type="checkbox"
                  checked={form.skip_cert_verify}
                  onChange={(event) => setForm((prev) => ({ ...prev, skip_cert_verify: event.target.checked }))}
                />
                <span>{t('node.skipCert')}</span>
              </label>
            </div>
          </>
        )}

        {nodeType === 'vless' && (
          <div className="form-grid two">
            <label className="field">
              <span>Reality public key</span>
              <input
                value={form.reality_public_key}
                onChange={(event) => {
                  const publicKey = event.target.value
                  setForm((prev) => ({
                    ...prev,
                    reality_public_key: publicKey,
                    client_fingerprint: publicKey.trim() && !prev.client_fingerprint
                      ? 'chrome'
                      : prev.client_fingerprint,
                  }))
                }}
                placeholder={t('node.optional')}
              />
            </label>
            <label className="field">
              <span>Reality short ID</span>
              <input
                value={form.reality_short_id}
                onChange={(event) => setForm((prev) => ({ ...prev, reality_short_id: event.target.value }))}
                placeholder={t('node.optional')}
              />
            </label>
          </div>
        )}

        {supportsTransport && (
          <>
            <div className="form-grid single">
              <label className="field">
                <span>{t('node.transport')}</span>
                <select
                  value={form.transport_type}
                  onChange={(event) => setForm((prev) => ({ ...prev, transport_type: event.target.value }))}
                >
                  {TRANSPORT_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
            </div>
            {pathTransport && (
              <div className="form-grid two">
                <label className="field">
                  <span>{t('node.path')}</span>
                  <input
                    value={form.transport_path}
                    onChange={(event) => setForm((prev) => ({ ...prev, transport_path: event.target.value }))}
                    placeholder="/ws"
                  />
                </label>
                <label className="field">
                  <span>{t('node.host')}</span>
                  <input
                    value={form.transport_host}
                    onChange={(event) => setForm((prev) => ({ ...prev, transport_host: event.target.value }))}
                    placeholder={t('node.optional')}
                  />
                </label>
              </div>
            )}
            {form.transport_type === 'grpc' && (
              <div className="form-grid single">
                <label className="field">
                  <span>gRPC service name</span>
                  <input
                    value={form.grpc_service_name}
                    onChange={(event) => setForm((prev) => ({ ...prev, grpc_service_name: event.target.value }))}
                    placeholder={t('node.optional')}
                  />
                </label>
              </div>
            )}
          </>
        )}

        {nodeType === 'hysteria2' && (
          <>
            <div className="form-grid two">
              <label className="field">
                <span>{t('node.obfsType')}</span>
                <select
                  value={form.obfs_type}
                  onChange={(event) => {
                    const obfsType = event.target.value
                    setForm((prev) => ({
                      ...prev,
                      obfs_type: obfsType,
                      obfs_password: obfsType ? prev.obfs_password : '',
                    }))
                  }}
                >
                  {HYSTERIA2_OBFS_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.value ? option.label : t('node.obfsDisabled')}</option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>{t('node.obfsPassword')}</span>
                <input
                  value={form.obfs_password}
                  disabled={!form.obfs_type}
                  onChange={(event) => setForm((prev) => ({ ...prev, obfs_password: event.target.value }))}
                  placeholder={form.obfs_type ? 'obfs password' : t('node.obfsOff')}
                />
              </label>
            </div>
          </>
        )}

        {nodeType === 'tuic' && (
          <div className="form-grid two">
            <label className="field">
              <span>{t('node.congestion')}</span>
              <select
                value={form.tuic_congestion_control}
                onChange={(event) => setForm((prev) => ({ ...prev, tuic_congestion_control: event.target.value }))}
              >
                {TUIC_CONGESTION_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>UDP relay mode</span>
              <select
                value={form.tuic_udp_relay_mode}
                onChange={(event) => setForm((prev) => ({ ...prev, tuic_udp_relay_mode: event.target.value }))}
              >
                {TUIC_UDP_RELAY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </label>
          </div>
        )}

        {nodeType === 'tuic' && (
          <div className="form-grid single">
            <label className="field checkbox-field">
              <input
                type="checkbox"
                checked={form.tuic_zero_rtt}
                onChange={(event) => setForm((prev) => ({ ...prev, tuic_zero_rtt: event.target.checked }))}
              />
              <span>{t('node.zeroRtt')}</span>
            </label>
          </div>
        )}

        {requiresPassword && (
          <div className="form-grid single">
            <label className="field">
              <span>{t('node.password')}</span>
              <input
                value={form.password}
                onChange={(event) => setForm((prev) => ({ ...prev, password: event.target.value }))}
                placeholder={t('node.password')}
              />
            </label>
          </div>
        )}

        <Button 
          tone="primary" 
          loading={loading} 
          icon={editing ? <Save size={14} /> : <Plus size={14} />}
          disabled={!canSubmit || loading} 
          onClick={onSubmit}
        >
          {editing ? t('node.saveNamed', { label: activeLabel }) : t('node.addNamed', { label: activeLabel })}
        </Button>
      </div>
    </div>
  )
}

function countBy(items, mapper) {
  return items.reduce((acc, item) => {
    const key = mapper(item) || 'unknown'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
}

function topEntries(counts, limit = 5) {
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
}

const CONNECTION_PAGE_SIZE = 20

const SORT_OPTIONS = [
  { value: 'downloadSpeed', labelKey: 'connections.sortDownloadSpeed' },
  { value: 'uploadSpeed', labelKey: 'connections.sortUploadSpeed' },
  { value: 'download', labelKey: 'connections.sortDownload' },
  { value: 'upload', labelKey: 'connections.sortUpload' },
  { value: 'start', labelKey: 'connections.sortStart' },
  { value: 'host', labelKey: 'connections.sortHost' },
  { value: 'source', labelKey: 'connections.sortSource' },
  { value: 'outbound', labelKey: 'connections.sortOutbound' },
]

function processName(connection) {
  const path = connection.metadata?.processPath || ''
  return connection.metadata?.process || path.replace(/^.*[/\\]/, '') || '-'
}

function connectionTarget(connection) {
  const metadata = connection.metadata || {}
  const host = metadata.host || metadata.sniffHost || metadata.remoteDestination || metadata.destinationIP || metadata.destination
  const port = metadata.destinationPort || metadata.remoteDestinationPort
  if (!host) return 'unknown'
  return port ? `${host}:${port}` : host
}

function connectionDestination(connection) {
  const metadata = connection.metadata || {}
  return metadata.remoteDestination || metadata.destinationIP || metadata.host || metadata.sniffHost || 'unknown'
}

function connectionSource(connection) {
  const metadata = connection.metadata || {}
  const ip = connectionSourceIP(connection)
  return metadata.sourcePort ? `${ip}:${metadata.sourcePort}` : ip
}

function connectionSourceIP(connection) {
  return connection.metadata?.sourceIP || 'inner'
}

function connectionRule(connection) {
  const rule = connection.rule || '-'
  return connection.rulePayload ? `${rule} : ${connection.rulePayload}` : rule
}

function connectionOutbound(connection) {
  if (Array.isArray(connection.chains) && connection.chains.length > 0) {
    return connection.chains[0]
  }
  return connection.rule || 'direct'
}

function connectionSearchText(connection) {
  return [
    connection.id,
    connectionTarget(connection),
    connectionDestination(connection),
    connectionSource(connection),
    connectionRule(connection),
    connectionOutbound(connection),
    processName(connection),
    connection.metadata?.network,
    connection.metadata?.type,
    ...(Array.isArray(connection.chains) ? connection.chains : []),
  ].filter(Boolean).join(' ').toLowerCase()
}

function sortValue(connection, sortKey) {
  switch (sortKey) {
    case 'uploadSpeed':
      return Number(connection.uploadSpeed || 0)
    case 'download':
      return Number(connection.download || 0)
    case 'upload':
      return Number(connection.upload || 0)
    case 'start':
      return new Date(connection.start || 0).getTime()
    case 'host':
      return connectionTarget(connection)
    case 'source':
      return connectionSource(connection)
    case 'outbound':
      return connectionOutbound(connection)
    case 'downloadSpeed':
    default:
      return Number(connection.downloadSpeed || 0)
  }
}

function formatStartTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function DetailRow({ label, value }) {
  return (
    <>
      <dt>{label}</dt>
      <dd title={String(value || '-')}>{value || '-'}</dd>
    </>
  )
}

export function ConnectionsModal({
  open,
  status,
  data,
  loading,
  error,
  onClose,
  onRefresh,
  onCloseConnection,
  onCloseAllConnections,
  showToast,
}) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [sortKey, setSortKey] = useState('downloadSpeed')
  const [sortDesc, setSortDesc] = useState(true)
  const [page, setPage] = useState(0)
  const [selectedId, setSelectedId] = useState('')
  const [closingId, setClosingId] = useState('')
  const [closingAll, setClosingAll] = useState(false)

  useEffect(() => {
    if (open) setPage(0)
  }, [open, query, sourceFilter, sortKey, sortDesc])

  const connections = useMemo(() => {
    return Array.isArray(data?.connections) ? data.connections : []
  }, [data?.connections])
  const uploadTotal = Number(data?.uploadTotal || connections.reduce((sum, item) => sum + Number(item.upload || 0), 0))
  const downloadTotal = Number(data?.downloadTotal || connections.reduce((sum, item) => sum + Number(item.download || 0), 0))
  const uploadSpeed = connections.reduce((sum, item) => sum + Number(item.uploadSpeed || 0), 0)
  const downloadSpeed = connections.reduce((sum, item) => sum + Number(item.downloadSpeed || 0), 0)
  const networkCounts = topEntries(countBy(connections, (item) => item.metadata?.network), 4)
  const outboundCounts = topEntries(countBy(connections, connectionOutbound), 5)
  const sourceOptions = useMemo(() => {
    return [...new Set(connections.map(connectionSourceIP))].sort()
  }, [connections])
  const filteredConnections = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const filtered = connections.filter((connection) => {
      if (sourceFilter && connectionSourceIP(connection) !== sourceFilter) return false
      return !needle || connectionSearchText(connection).includes(needle)
    })

    return [...filtered].sort((a, b) => {
      const aValue = sortValue(a, sortKey)
      const bValue = sortValue(b, sortKey)
      const comparison = typeof aValue === 'number' && typeof bValue === 'number'
        ? aValue - bValue
        : String(aValue).localeCompare(String(bValue))
      return sortDesc ? -comparison : comparison
    })
  }, [connections, query, sortDesc, sortKey, sourceFilter])
  const pageCount = Math.max(1, Math.ceil(filteredConnections.length / CONNECTION_PAGE_SIZE))
  const safePage = Math.min(page, pageCount - 1)
  const pageStart = safePage * CONNECTION_PAGE_SIZE
  const visibleConnections = filteredConnections.slice(pageStart, pageStart + CONNECTION_PAGE_SIZE)
  const selectedConnection = selectedId
    ? connections.find((connection) => connection.id === selectedId)
    : null

  const handleCloseSingle = async (connectionId) => {
    setClosingId(connectionId)
    try {
      await onCloseConnection(connectionId)
      if (selectedId === connectionId) setSelectedId('')
    } catch (closeError) {
      showToast?.(closeError.message || t('connections.closeFailed'), 'error')
    } finally {
      setClosingId('')
    }
  }

  const handleCloseAll = async () => {
    setClosingAll(true)
    try {
      await onCloseAllConnections()
      setSelectedId('')
    } catch (closeError) {
      showToast?.(closeError.message || t('connections.closeAllFailed'), 'error')
    } finally {
      setClosingAll(false)
    }
  }

  if (!open) return null

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card connections-modal" onClick={(event) => event.stopPropagation()}>
        <div className="modal-title-row">
          <div className="modal-title-wrap">
            <Activity size={18} className="icon-accent" />
            <h3>{t('connections.title')}</h3>
          </div>
          <div className="modal-title-actions">
            <button className="icon-button" onClick={onRefresh} disabled={loading || !status.running} title={t('connections.refresh')}>
              <RefreshCw size={16} className={loading ? 'spin' : undefined} />
            </button>
            <button className="icon-button" onClick={onClose} title={t('modal.close')}>
              <X size={16} />
            </button>
          </div>
        </div>

        {!status.running ? (
          <div className="connections-empty">{t('connections.emptyStopped')}</div>
        ) : (
          <>
            <div className="connection-stat-grid">
              <div className="connection-stat">
                <span>{t('connections.active')}</span>
                <strong>{connections.length}</strong>
              </div>
              <div className="connection-stat">
                <span>{t('connections.speed')}</span>
                <strong>↓ {formatBytes(downloadSpeed)}/s</strong>
                <small>↑ {formatBytes(uploadSpeed)}/s</small>
              </div>
              <div className="connection-stat">
                <span>{t('connections.uploadTotal')}</span>
                <strong>{formatBytes(uploadTotal)}</strong>
              </div>
              <div className="connection-stat">
                <span>{t('connections.downloadTotal')}</span>
                <strong>{formatBytes(downloadTotal)}</strong>
              </div>
              <div className="connection-stat">
                <span>{t('connections.total')}</span>
                <strong>{formatBytes(uploadTotal + downloadTotal)}</strong>
              </div>
            </div>

            {error && <div className="connections-error">{error}</div>}

            <div className="connections-toolbar">
              <label className="connections-search">
                <Search size={14} />
                <input
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder={t('connections.searchPh')}
                />
              </label>
              <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
                <option value="">{t('connections.allSources')}</option>
                {sourceOptions.map((source) => (
                  <option key={source} value={source}>{source}</option>
                ))}
              </select>
              <select value={sortKey} onChange={(event) => setSortKey(event.target.value)}>
                {SORT_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{t(option.labelKey)}</option>
                ))}
              </select>
              <button className="connections-tool-button" onClick={() => setSortDesc((value) => !value)}>
                {sortDesc ? t('connections.desc') : t('connections.asc')}
              </button>
              <button
                className="connections-tool-button danger"
                onClick={handleCloseAll}
                disabled={closingAll || loading || connections.length === 0}
                title={t('connections.closeAll')}
              >
                {closingAll ? <RefreshCw size={14} className="spin" /> : <Trash2 size={14} />}
              </button>
            </div>

            <div className="connections-split">
              <div className="connections-panel">
                <div className="connections-panel-title">
                  <Network size={14} />
                  <span>{t('connections.networkDist')}</span>
                </div>
                {networkCounts.length > 0 ? networkCounts.map(([name, count]) => (
                  <div className="connection-count-row" key={name}>
                    <span>{name}</span>
                    <strong>{count}</strong>
                  </div>
                )) : <div className="connections-muted">{t('connections.noData')}</div>}
              </div>

              <div className="connections-panel">
                <div className="connections-panel-title">
                  <Route size={14} />
                  <span>{t('connections.outboundDist')}</span>
                </div>
                {outboundCounts.length > 0 ? outboundCounts.map(([name, count]) => (
                  <div className="connection-count-row" key={name}>
                    <span title={name}>{name}</span>
                    <strong>{count}</strong>
                  </div>
                )) : <div className="connections-muted">{t('connections.noData')}</div>}
              </div>
            </div>

            <div className="connections-table">
              <div className="connections-table-header">
                <span />
                <span>{t('connections.target')}</span>
                <span>{t('connections.ruleOutbound')}</span>
                <span>{t('connections.source')}</span>
                <span>{t('connections.speedCol')}</span>
                <span>{t('connections.totalCol')}</span>
              </div>
              {visibleConnections.length > 0 ? visibleConnections.map((connection, index) => (
                <div
                  className={classNames('connections-table-row', selectedId === connection.id && 'active')}
                  key={connection.id || `${connectionTarget(connection)}-${index}`}
                  onClick={() => setSelectedId(connection.id)}
                >
                  <button
                    className="connection-row-close"
                    onClick={(event) => {
                      event.stopPropagation()
                      handleCloseSingle(connection.id)
                    }}
                    disabled={closingId === connection.id}
                    title={t('connections.closeOne')}
                  >
                    {closingId === connection.id ? <RefreshCw size={13} className="spin" /> : <X size={13} />}
                  </button>
                  <span className="connection-host" title={connectionTarget(connection)}>
                    <strong>{connectionTarget(connection)}</strong>
                    <small>{processName(connection)} · {formatStartTime(connection.start)}</small>
                  </span>
                  <span className="connection-rule" title={`${connectionRule(connection)} → ${(connection.chains || []).join(' → ')}`}>
                    <strong>{connectionRule(connection)}</strong>
                    <small>{(connection.chains || []).length ? [...connection.chains].reverse().join(' → ') : connectionOutbound(connection)}</small>
                  </span>
                  <span title={connectionSource(connection)}>{connectionSource(connection)}</span>
                  <span>
                    <small><ArrowDown size={12} />{formatBytes(Number(connection.downloadSpeed || 0))}/s</small>
                    <small><ArrowUp size={12} />{formatBytes(Number(connection.uploadSpeed || 0))}/s</small>
                  </span>
                  <span>
                    <small><ArrowDown size={12} />{formatBytes(Number(connection.download || 0))}</small>
                    <small><ArrowUp size={12} />{formatBytes(Number(connection.upload || 0))}</small>
                  </span>
                </div>
              )) : <div className="connections-empty inline">{t('connections.noMatch')}</div>}
            </div>

            <div className="connections-pagination">
              <span>
                {filteredConnections.length === 0
                  ? '0 / 0'
                  : `${pageStart + 1}-${Math.min(pageStart + visibleConnections.length, filteredConnections.length)} / ${filteredConnections.length}`}
              </span>
              <div>
                <button className="connections-tool-button" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{t('connections.prev')}</button>
                <button className="connections-tool-button" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{t('connections.next')}</button>
              </div>
            </div>

            {selectedConnection && (
              <div className="connection-detail-panel">
                <div className="connection-detail-title">
                  <strong>{t('connections.detail')}</strong>
                  <button className="icon-button subtle" onClick={() => setSelectedId('')} title={t('connections.closeDetail')}>
                    <X size={14} />
                  </button>
                </div>
                <dl>
                  <DetailRow label={t('connections.id')} value={selectedConnection.id} />
                  <DetailRow label={t('connections.startTime')} value={formatStartTime(selectedConnection.start)} />
                  <DetailRow label={t('connections.network')} value={`${selectedConnection.metadata?.type || '-'} / ${selectedConnection.metadata?.network || '-'}`} />
                  <DetailRow label={t('connections.target')} value={connectionTarget(selectedConnection)} />
                  <DetailRow label={t('connections.remote')} value={connectionDestination(selectedConnection)} />
                  <DetailRow label={t('connections.source')} value={connectionSource(selectedConnection)} />
                  <DetailRow label={t('connections.rule')} value={connectionRule(selectedConnection)} />
                  <DetailRow label={t('connections.chain')} value={(selectedConnection.chains || []).join(' → ')} />
                  <DetailRow label={t('connections.process')} value={processName(selectedConnection)} />
                  <DetailRow label={t('connections.processPath')} value={selectedConnection.metadata?.processPath} />
                  <DetailRow label={t('connections.inbound')} value={selectedConnection.metadata?.inboundName || selectedConnection.metadata?.inboundUser || selectedConnection.metadata?.inboundIP} />
                </dl>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
