import { useEffect, useMemo, useRef, useState } from 'react'
import { Copy, Save, Share2 } from 'lucide-react'
import { Button, SectionCard } from './ui.jsx'
import { normalizePoolConfig } from '../hooks/useApi.js'

const PORT_PLACEHOLDER = '12000'
const WILDCARD_HOSTS = new Set(['0.0.0.0', '::'])

function parsePort(value) {
  const trimmed = value.trim()
  // Number('') === 0 且 Number('0x10') === 16，都会让"改动检测"和"保存校验"对不上号。
  if (!/^\d+$/.test(trimmed)) return null
  const port = Number(trimmed)
  return port >= 1 && port <= 65535 ? port : null
}

// 后端 normalized() 用 IpAddr::parse 校验，非 IP 一律拒绝。前端跟着用同一套规则，
// 免得这里放行 'localhost' 之后再被后端以另一个理由退回。
function parseListen(value) {
  const host = value.trim()
  if (!host) return null
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (ipv4) {
    return ipv4.slice(1).every((part) => Number(part) <= 255) ? host : null
  }
  // IPv6：字符集里要带上 '.'，否则 ::ffff:192.168.1.1 这种映射地址会被误杀。
  // 这里只做形状检查、故意放宽：漏网的会被后端以准确的理由拒掉，
  // 而误杀会让一个后端本可以接受的地址在界面上根本存不进去。
  return /^[0-9a-fA-F:.]+$/.test(host) && host.includes(':') ? host : null
}

/** 面板显示用的地址：通配监听时换成当前访问面板的主机名，那必定是可达的。 */
function resolveEndpointUrl(url, listen) {
  if (!WILDCARD_HOSTS.has(listen)) return url
  const host = window.location.hostname
  if (!host) return url
  try {
    const parsed = new URL(url)
    parsed.hostname = host
    return parsed.toString()
  } catch {
    return url
  }
}

/** 表单当前内容对应的提交负载；`base_port` 非法时为 null。 */
function buildPayload({ listen, basePort, username, password }) {
  const port = parsePort(basePort)
  if (port === null) return null
  return {
    listen: listen.trim(),
    base_port: port,
    username: username.trim(),
    password: password.trim(),
  }
}

export function PoolCard({
  proxyMode,
  config,
  endpoints,
  loading,
  disabled,
  onSave,
  showToast,
}) {
  const normalizedConfig = useMemo(() => normalizePoolConfig(config), [config])
  const [listen, setListen] = useState(normalizedConfig.listen)
  const [basePort, setBasePort] = useState(String(normalizedConfig.base_port))
  const [username, setUsername] = useState(normalizedConfig.username)
  const [password, setPassword] = useState(normalizedConfig.password)

  // 记录本地表单是基于哪份服务端配置填出来的。只有服务端的值真的和它不一样时才回填，
  // 否则保存后紧跟着的那次 GET /api/share 会把用户刚敲进去的字符冲掉
  // （POST 一返回输入框就解锁了，后续几个刷新请求还在路上）。
  const syncedRef = useRef(null)

  useEffect(() => {
    const incoming = JSON.stringify(normalizedConfig)
    if (syncedRef.current === incoming) return
    syncedRef.current = incoming
    setListen(normalizedConfig.listen)
    setBasePort(String(normalizedConfig.base_port))
    setUsername(normalizedConfig.username)
    setPassword(normalizedConfig.password)
  }, [normalizedConfig])

  const payload = buildPayload({ listen, basePort, username, password })
  // 和 handleSave 实际发送的负载逐字段比对，保存按钮的亮灭才和"点了会不会有效果"一致。
  // 端口填得不合法时算作"有改动"：让按钮保持可点，点下去会给出明确的错误提示；
  // 直接置灰只会让用户对着一个和已保存值明显不同的表单，却得不到任何解释。
  const dirty = payload === null
    ? true
    : payload.listen !== normalizedConfig.listen
      || payload.base_port !== normalizedConfig.base_port
      || payload.username !== normalizedConfig.username
      || payload.password !== normalizedConfig.password

  const handleSave = () => {
    if (payload === null) {
      showToast('起始端口必须是 1-65535 的整数', 'error')
      return
    }
    if (!payload.listen) {
      showToast('监听地址不能为空', 'error')
      return
    }
    if (parseListen(payload.listen) === null) {
      showToast('监听地址必须是合法 IP', 'error')
      return
    }
    if (Boolean(payload.username) !== Boolean(payload.password)) {
      showToast('用户名和密码需同时填写或同时留空', 'error')
      return
    }

    // 乐观地认为提交值就是新的基线，这样后续刷新回来的同一份值不会触发回填。
    syncedRef.current = JSON.stringify(normalizePoolConfig(payload))
    onSave(payload)
  }

  const handleCopy = async (url) => {
    // 面板默认是局域网明文 HTTP，非安全上下文里 navigator.clipboard 根本不存在，
    // 而"从别的机器打开面板复制地址"恰恰是代理池的主要用法。
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url)
      } else {
        const textarea = document.createElement('textarea')
        textarea.value = url
        textarea.setAttribute('readonly', '')
        textarea.style.position = 'fixed'
        textarea.style.opacity = '0'
        document.body.appendChild(textarea)
        textarea.select()
        const ok = document.execCommand('copy')
        document.body.removeChild(textarea)
        if (!ok) throw new Error('execCommand copy failed')
      }
      showToast('已复制 SOCKS 地址', 'success')
    } catch {
      showToast('复制失败，请手动选中地址复制', 'error')
    }
  }

  if (proxyMode !== 'pool') return null

  return (
    <SectionCard
      className="share-card"
      bodyClassName="panel-body-tight"
      header={
        <div className="section-header">
          <div className="section-title-wrap">
            <Share2 size={14} className="section-icon" />
            <span>代理池</span>
            {endpoints?.length > 0 && (
              <span className="counter-pill">{endpoints.length}</span>
            )}
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
      <div className="share-body">
        <div className="share-grid">
          <label className="field">
            <span>监听地址</span>
            <input
              value={listen}
              disabled={disabled || loading}
              onChange={(event) => setListen(event.target.value)}
              placeholder="0.0.0.0"
            />
          </label>
          <label className="field">
            <span>起始端口</span>
            <input
              value={basePort}
              disabled={disabled || loading}
              onChange={(event) => setBasePort(event.target.value)}
              placeholder={PORT_PLACEHOLDER}
            />
          </label>
          <label className="field">
            <span>用户名</span>
            <input
              value={username}
              disabled={disabled || loading}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="可选"
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>密码</span>
            <input
              type="password"
              value={password}
              disabled={disabled || loading}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="可选"
              autoComplete="new-password"
            />
          </label>
        </div>

        <div className="share-note">
          端口按节点名称持久分配，订阅刷新重排后端口不变。默认监听 0.0.0.0；
          用户名和密码可留空，填写时需同时填写。
        </div>

        {endpoints?.length > 0 ? (
          <div className="share-endpoints">
            {endpoints.map((item) => {
              const displayUrl = resolveEndpointUrl(item.url, item.listen)
              return (
                <div key={`${item.tag}-${item.port}`} className="share-endpoint-row">
                  <div className="share-endpoint-meta" title={item.tag}>
                    <span className="share-endpoint-tag">{item.tag}</span>
                  </div>
                  <div className="share-endpoint-address">
                    <code className="share-endpoint-url" title={displayUrl}>{displayUrl}</code>
                    <button
                      type="button"
                      className="share-copy-btn"
                      disabled={disabled || loading}
                      onClick={() => handleCopy(displayUrl)}
                      title={`复制 ${item.tag} 的 SOCKS 地址`}
                      aria-label={`复制 ${item.tag} 的 SOCKS 地址`}
                    >
                      <Copy size={12} />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        ) : null}
        {endpoints?.length === 0 && (
          <div className="empty-block">保存并启动服务后显示节点端口</div>
        )}
      </div>
    </SectionCard>
  )
}
