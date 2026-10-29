import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import { VpsModal } from './VpsModal.jsx'
import { PrefsProvider, LOCALE_STORAGE_KEY } from '../i18n.jsx'

const controller = () => ({ access: { local: false, token_configured: true, authorized: true }, open: true, close: vi.fn(), jobs: [], token: '', updateToken: vi.fn(), request: vi.fn(), error: '' })

it('requires inspection, blocks unknown services and clears credentials after closing', async () => {
  const vps = controller()
  vps.request.mockResolvedValueOnce({ action: 'blocked', error: 'third_party_deployment_protected' }).mockResolvedValueOnce({ action: 'install' }).mockResolvedValueOnce({ id: 'task' })
  const { rerender } = render(<VpsModal vps={vps} />)
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('VPS 管理地址'), '203.0.113.10')
  await user.type(screen.getByLabelText('root 密码'), 'private-secret')
  expect(screen.getByRole('button', { name: '按检查结果执行' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: '检查环境' }))
  expect(await screen.findByText(/third_party_deployment_protected/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '按检查结果执行' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: '检查环境' }))
  await user.click(screen.getByRole('button', { name: '按检查结果执行' }))
  expect(vps.request.mock.calls[2][0]).toBe('deployments')
  await waitFor(() => expect(screen.getByLabelText('root 密码')).toHaveValue(''))
  await user.type(screen.getByLabelText('root 密码'), 'another-secret')
  rerender(<VpsModal vps={{ ...vps, open: false }} />)
  rerender(<VpsModal vps={vps} />)
  expect(screen.getByLabelText('root 密码')).toHaveValue('')
})

it('renders real progress and permits closing without cancelling deployment', async () => {
  const vps = controller()
  vps.jobs = [{ id: 'task', host: '203.0.113.10', active: true, stage: 'downloading', downloaded: 1024, total: 2048, source: 'proxy', events: ['checking', 'downloading'] }]
  render(<VpsModal vps={vps} />)
  expect(screen.getByRole('progressbar')).toHaveAttribute('value', '1024')
  expect(screen.getByRole('progressbar')).toHaveAttribute('max', '2048')
  expect(screen.queryByLabelText('root 密码')).not.toBeInTheDocument()
  fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
  expect(vps.close).toHaveBeenCalledOnce()
  expect(vps.request).not.toHaveBeenCalled()
})

it('resumes the original NAT endpoint instead of creating a new installation', async () => {
  const vps = controller()
  vps.jobs = [{ id: 'a'.repeat(48), host: '203.0.113.10', ssh_port: 22022, listen_port: 543, node_host: 'node.example.com', node_port: 30543, active: false, stage: 'unknown', events: [] }]
  vps.request.mockResolvedValue({ id: vps.jobs[0].id })
  render(<VpsModal vps={vps} />)
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: '重新认证并核查' }))
  expect(screen.getByLabelText('SSH 端口')).toHaveValue(22022)
  expect(screen.getByLabelText('节点连接端口（0 为同监听端口）')).toHaveValue(30543)
  await user.type(screen.getByLabelText('root 密码'), 'secret')
  await user.click(screen.getByRole('button', { name: '核查远端任务' }))
  expect(vps.request).toHaveBeenCalledWith('deployments', expect.objectContaining({ id: 'a'.repeat(48), ssh_port: 22022, node_host: 'node.example.com', node_port: 30543 }), expect.any(AbortSignal))
})

it('shows English connection results and security requirements', () => {
  localStorage.setItem(LOCALE_STORAGE_KEY, 'en')
  const vps = controller()
  vps.jobs = [{ id: 'task', host: '203.0.113.10', stage: 'connectivity_failed', active: false, events: [] }]
  render(<PrefsProvider><VpsModal vps={vps} /></PrefsProvider>)
  expect(screen.getByText('Node saved; connectivity check failed')).toBeInTheDocument()
  expect(screen.getByText(/Remote HTTP\/HTTPS access requires/)).toBeInTheDocument()
})

for (const auth of ['password', 'private_key', 'local_key']) {
  it(`allows inspection using ${auth} over remote HTTP with authorized access`, async () => {
    const vps = controller()
    vps.request.mockResolvedValue({ action: 'recover' })
    render(<VpsModal vps={vps} />)
    fireEvent.change(screen.getByLabelText('VPS 管理地址'), { target: { value: '203.0.113.10' } })
    fireEvent.change(screen.getByLabelText('SSH 认证'), { target: { value: auth } })
    if (auth !== 'local_key') fireEvent.change(screen.getByLabelText(auth === 'password' ? 'root 密码' : 'SSH 私钥'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: '检查环境' }))
    await waitFor(() => expect(vps.request).toHaveBeenCalledWith('preflight', expect.objectContaining({ auth }), expect.any(AbortSignal)))
    expect(screen.getByText(/当前连接使用 HTTP/)).toBeInTheDocument()
    expect(screen.getByLabelText('部署访问令牌')).toBeVisible()
  })
}

it('explains missing configuration and invalid tokens before inspection, including active tasks', () => {
  const vps = controller()
  vps.access = { local: false, token_configured: false, authorized: false }
  const { rerender } = render(<VpsModal vps={vps} />)
  expect(screen.getByText(/远程部署尚未启用/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '检查环境' })).toBeDisabled()
  rerender(<VpsModal vps={{ ...vps, access: { ...vps.access, token_configured: true } }} />)
  expect(screen.getByText('请填写有效的部署访问令牌后检查环境。')).toBeInTheDocument()
  rerender(<VpsModal vps={{ ...vps, jobs: [{ active: true, stage: 'checking', host: 'host', events: [] }] }} />)
  expect(screen.getByLabelText('部署访问令牌')).toBeVisible()
})
