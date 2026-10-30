import { createPortal } from 'react-dom'
import { useEffect, useId, useRef, useState } from 'react'
import { CircleHelp } from 'lucide-react'
import { useI18n } from '../i18n.jsx'
import { Button } from './ui.jsx'

const PHASES = {
  installing_dependencies: ['安装缺失依赖', 'Installing missing prerequisites'], starting: ['准备部署', 'Preparing deployment'], reconnecting: ['重新核查远端', 'Inspecting remote task'],
  checking: ['检查远端', 'Checking remote host'], downloading: ['下载 Hysteria2', 'Downloading Hysteria2'],
  verifying_download: ['校验下载', 'Verifying download'], preparing: ['准备配置和证书', 'Preparing configuration and certificate'],
  backing_up: ['备份旧部署', 'Backing up deployment'], activating: ['激活服务', 'Activating service'],
  checking_service: ['检查服务稳定性', 'Checking service stability'], repairing: ['修复已有服务', 'Repairing service'],
  remote_ready: ['远端已就绪', 'Remote ready'], saving_node: ['保存节点', 'Saving node'],
  verifying_connection: ['验证实际代理连接', 'Verifying proxy connectivity'], success: ['部署完成，连接正常', 'Complete; connectivity verified'],
  connectivity_failed: ['节点已保存，连接验证失败', 'Node saved; connectivity check failed'],
  rolling_back: ['正在回滚', 'Rolling back'], rolled_back: ['部署失败，已回滚', 'Deployment failed; rolled back'],
  recovery_required: ['需要手工恢复，请保留备份', 'Manual recovery required; preserve backup'],
  unknown: ['结果待核查，请重新认证', 'Outcome unknown; re-authenticate'], error: ['远端执行失败', 'Remote operation failed'],
}
const EMPTY = { host: '', ssh_port: 22, user: 'root', auth: 'password', secret: '', listen_port: 543, node_host: '', node_port: 0, name: '', download_proxy: '' }

function Help({ label, children }) {
  const id = useId()
  const [position, setPosition] = useState(null)
  const hideTimer = useRef(null)
  useEffect(() => () => clearTimeout(hideTimer.current), [])
  const hide = () => { hideTimer.current = setTimeout(() => setPosition(null), 150) }
  const show = event => {
    clearTimeout(hideTimer.current)
    const rect = event.currentTarget.getBoundingClientRect()
    const width = Math.min(300, window.innerWidth - 32)
    setPosition({ left: Math.max(16, Math.min(rect.left, window.innerWidth - width - 16)), top: Math.max(8, Math.min(rect.bottom + 8, window.innerHeight - Math.min(260, window.innerHeight * 0.45) - 16)), width })
  }
  return <span className="vps-help">
    <button type="button" className="vps-help-button" aria-label={label} aria-describedby={position ? id : undefined}
      onMouseEnter={show} onMouseLeave={hide} onFocus={show} onBlur={() => setPosition(null)} onClick={show}
      onKeyDown={event => { if (event.key === 'Escape' && position) { event.stopPropagation(); setPosition(null) } }}><CircleHelp size={14} strokeWidth={1.75} /></button>
    {position && createPortal(<span id={id} role="tooltip" className="vps-help-content" style={position} onMouseEnter={() => clearTimeout(hideTimer.current)} onMouseLeave={hide}>{children}</span>, document.body)}
  </span>
}

export function VpsModal({ vps }) {
  const { locale } = useI18n()
  const zh = locale === 'zh'
  const text = (cn, en) => zh ? cn : en
  const [form, setForm] = useState(EMPTY)
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [resume, setResume] = useState('')
  const idempotencyKey = useRef('')
  const latest = vps.jobs[0]
  const previousOpen = useRef(false)
  const dialogRef = useRef(null)
  const closeRef = useRef(vps.close)
  closeRef.current = vps.close
  useEffect(() => {
    if (!vps.open) return
    const previousFocus = document.activeElement
    const dialog = dialogRef.current
    const focusable = () => [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary')].filter(element => element.getClientRects().length > 0)
    dialog.querySelector('button')?.focus()
    const keyboard = event => {
      if (event.key === 'Escape') {
        if (event.target.closest('.vps-help-button[aria-describedby]')) return
        closeRef.current()
      }
      if (event.key !== 'Tab') return
      const elements = focusable()
      const first = elements[0]
      const last = elements[elements.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }
    dialog.addEventListener('keydown', keyboard)
    return () => { dialog.removeEventListener('keydown', keyboard); previousFocus?.focus() }
  }, [vps.open])
  useEffect(() => {
    if (!vps.open && previousOpen.current) {
      setForm(value => ({ ...value, secret: '' }))
      setReport(null)
    }
    previousOpen.current = vps.open
  }, [vps.open])
  if (!vps.open) return null
  const field = (key, value) => { idempotencyKey.current = ''; setForm(previous => ({ ...previous, [key]: value })); setReport(null) }
  const execute = async (start) => {
    setBusy(true); setError('')
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), start ? 20000 : 60000)
    try {
      if (start && !resume && !idempotencyKey.current) idempotencyKey.current = [...crypto.getRandomValues(new Uint8Array(24))].map(value => value.toString(16).padStart(2, '0')).join('')
      const body = { ...form, id: start ? resume : '', idempotency_key: start && !resume ? idempotencyKey.current : '' }
      const result = await vps.request(start ? 'deployments' : 'preflight', body, controller.signal)
      if (start) { idempotencyKey.current = ''; setForm(value => ({ ...value, secret: '' })); setReport(null); setResume('') }
      else setReport(result)
    } catch (cause) { setError(cause.name === 'AbortError' ? text('请求中断；先查看任务记录，不要重复部署。', 'Request interrupted; inspect task history before retrying.') : cause.message) }
    finally { clearTimeout(timer); setBusy(false) }
  }
  const resumeTask = job => {
    setForm({ ...EMPTY, host: job.host, ssh_port: job.ssh_port, listen_port: job.listen_port, node_host: job.node_host, node_port: job.node_port })
    setResume(job.id); setReport(null); setError('')
  }
  const input = (key, cn, en, type = 'text') => <label className="field"><span>{text(cn, en)}</span><input type={type} autoComplete={key === 'secret' ? 'new-password' : 'off'} value={form[key]} disabled={busy || latest?.active} onChange={event => field(key, type === 'number' ? Number(event.target.value) : event.target.value)} /></label>
  return <div className="modal-overlay"><section ref={dialogRef} className="modal-card node-modal" role="dialog" aria-modal="true" aria-labelledby="vps-title">
    <div className="modal-title-row"><h2 id="vps-title">{text('VPS 部署', 'VPS deployment')}</h2><Button tone="ghost" onClick={vps.close}>{text('关闭', 'Close')}</Button></div>
    <p>{text('通过 SSH 安装或恢复 Hysteria2。', 'Install or recover Hysteria2 over SSH.')} <Help label={text('部署说明', 'About deployment')}>{text('未知服务不会被覆盖；SSH 凭据不保存。首次连接采用首次信任，主机密钥变化会阻止连接。', 'Unknown services are protected; SSH credentials are not saved. First SSH connection uses trust on first use; changed host keys are rejected.')}</Help></p>
    {vps.error && <p role="alert">{vps.error}</p>}
    {location.protocol === 'http:' && <p className="vps-compact-note">HTTP <Help label={text('HTTP 连接说明', 'About HTTP')}>{text('SSH 密码和临时私钥会明文传输，建议使用 HTTPS 或 SSH 隧道。', 'HTTP transmits SSH password and temporary private key without encryption. HTTPS or an SSH tunnel is recommended.')}</Help></p>}
    {latest && <section aria-label={text('部署状态', 'Deployment status')}>
      <p role="status"><strong>{PHASES[latest.stage]?.[zh ? 0 : 1] || latest.stage}</strong> · {latest.host}</p>
      {latest.stage === 'downloading' && <p>{latest.source === 'proxy' ? text('代理下载', 'Proxy download') : text('直接下载', 'Direct download')} · {Math.round((latest.downloaded || 0) / 1024)} KiB{latest.total > 0 && <> / {Math.round(latest.total / 1024)} KiB <progress aria-label={text('下载进度', 'Download progress')} value={Math.min(latest.downloaded, latest.total)} max={latest.total} /></>}</p>}
      <details><summary>{text('部署记录' , 'Deployment history')}</summary><ol>{latest.events.map((event, index) => <li key={index}>{PHASES[event]?.[zh ? 0 : 1] || event}</li>)}</ol></details>
      {!latest.active && ['unknown', 'connectivity_failed', 'error'].includes(latest.stage) && <Button onClick={() => resumeTask(latest)}>{text('重新认证并核查', 'Re-authenticate and inspect')}</Button>}
    </section>}
    {!latest?.active && <>
      {resume && <p role="status">{text('核查已有任务：不会重新安装。请重新输入 SSH 凭据。', 'Inspecting an existing task without reinstalling. Enter SSH credentials again.')}</p>}
      <div className="form-grid single">{input('host', 'VPS 管理地址', 'VPS management address')}
        <label className="field"><span>{text('SSH 认证', 'SSH authentication')}</span><select value={form.auth} onChange={event => field('auth', event.target.value)} disabled={busy}>
          <option value="password">{text('root 密码', 'Root password')}</option><option value="private_key">{text('临时私钥（不支持加密私钥）', 'Temporary private key (unencrypted)')}</option><option value="local_key">{text('Miao 主机已有密钥', 'Existing Miao host key')}</option>
        </select></label>
        {form.auth === 'password' && input('secret', 'root 密码', 'Root password', 'password')}
        {form.auth === 'private_key' && <label className="field"><span>{text('SSH 私钥', 'SSH private key')}</span><textarea value={form.secret} disabled={busy} onChange={event => field('secret', event.target.value)} spellCheck={false} /></label>}
        {form.auth === 'local_key' && <span className="vps-compact-note">{text('使用 Miao 主机密钥', 'Uses Miao host keys')} <Help label={text('已有密钥说明', 'About existing keys')}>{text('读取运行 Miao 的账户可访问的 SSH 密钥，不读取浏览器所在电脑的密钥。', 'Uses SSH keys accessible to the account running Miao, not keys on your browser computer.')}</Help></span>}
      </div>
      <details><summary>{text('高级设置', 'Advanced settings')}</summary>
        <div className="form-grid two">{input('ssh_port', 'SSH 端口', 'SSH port', 'number')}{input('listen_port', 'VPS 监听 UDP 端口', 'VPS UDP listen port', 'number')}{input('node_host', '节点连接地址（默认同管理地址）', 'Node address (defaults to management address)')}{input('node_port', '节点连接端口（0 为同监听端口）', 'Node port (0 uses listen port)', 'number')}{input('name', '节点名称（可选）', 'Node name (optional)')}{input('download_proxy', 'HTTPS 下载代理前缀（可选）', 'HTTPS download proxy prefix (optional)')}
        </div>
      </details>
      <p className="vps-compact-note">{text('需开放 SSH TCP 和节点 UDP 端口', 'Allow SSH TCP and node UDP ports')} <Help label={text('网络要求说明', 'About network requirements')}>{text('安全组、防火墙及 NAT 映射不会自动修改。默认 SSH 22/TCP、节点 543/UDP，可在高级设置修改。无公网 IP 时须有私网/VPN 互通或 UDP 映射。', 'Security groups, firewalls and NAT mappings are not changed. Defaults: SSH 22/TCP and node 543/UDP; customize in advanced settings. Private VPS requires private/VPN connectivity or UDP mapping.')}</Help></p>
      {report && <p role="status">{text('检查结果：', 'Inspection: ')}{({ install: text('可全新安装', 'Ready to install'), recover: text('恢复已有节点，不重启服务', 'Recover existing node without restarting'), repair: text('修复已有服务，将重启服务', 'Repair existing service; service will restart'), migrate: text('迁移旧部署的证书和内核，保留密码和混淆，将重启服务', 'Migrate legacy certificate and binary; preserve credentials and obfs; restart service'), dependencies_required: text('需安装依赖后进一步检查，未知部署仍会被保护', 'Dependencies required before further inspection; unknown deployments remain protected'), blocked: text('检查未通过：', 'Blocked: ') + (report.error || '') })[report.action] || report.action}</p>}
      {error && <p role="alert">{error}</p>}
      <div className="modal-actions"><Button disabled={busy || !form.host || (form.auth !== 'local_key' && !form.secret)} onClick={() => execute(false)}>{busy ? text('处理中…', 'Working…') : text('检查环境', 'Inspect')}</Button>
        <Button tone="primary" disabled={busy || (!resume && (!report || report.action === 'blocked')) || !form.host || (form.auth !== 'local_key' && !form.secret)} onClick={() => execute(true)}>{resume ? text('核查远端任务', 'Inspect remote task') : text('按检查结果执行', 'Execute inspected action')}</Button>
        {resume && <Button tone="ghost" onClick={() => { setResume(''); setForm(EMPTY); setReport(null) }}>{text('返回新建', 'New deployment')}</Button>}
      </div>
    </>}
    {vps.jobs.length > 1 && <details><summary>{text('历史任务', 'Earlier tasks')}</summary><ul>{vps.jobs.slice(1).map(job => <li key={job.id}>{job.host} · {PHASES[job.stage]?.[zh ? 0 : 1] || job.stage}{!job.active && <Button tone="ghost" onClick={() => resumeTask(job)}>{text('核查', 'Inspect')}</Button>}</li>)}</ul></details>}
  </section></div>
}

export function VpsStatus({ vps }) {
  const { locale } = useI18n()
  if (!vps.jobs.length) return null
  return <button className="vps-task-status" onClick={() => vps.setOpen(true)}>{vps.jobs.some(job => job.active) ? (locale === 'zh' ? 'VPS 部署中' : 'VPS deploying') : 'VPS'}</button>
}
