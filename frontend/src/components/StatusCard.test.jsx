import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { StatusCard } from './StatusCard.jsx'

const props = {
  status: { running: false, initializing: false, mode: 'global', tun: { routing: 'auto' } },
  traffic: { up: 0, down: 0 }, loadingAction: '',
  onToggleService: vi.fn(), onSetMode: vi.fn(), onOpenConnections: vi.fn(),
}

it('automatically configures routing without a selector and retains read-only diagnostics', () => {
  render(<StatusCard {...props} status={{ ...props.status, running: true, runtime: { phase: 'ready', routing: { effective: 'policy_route', reason: '内核不支持 nftables，已自动适配' }, dns: { phase: 'active', message: 'dnsmasq 公网查询已自动接入代理 DNS' } } }} />)
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  expect(screen.getByRole('status')).toHaveTextContent('流量接管：已自动配置')
  const details = screen.getByText('网络诊断').closest('details')
  expect(details).not.toHaveAttribute('open')
  fireEvent.click(screen.getByText('网络诊断'))
  expect(screen.getByText('当前：策略路由接管')).toBeInTheDocument()
  expect(screen.getByText('内核不支持 nftables，已自动适配')).toBeInTheDocument()
  expect(screen.getByText('DNS：dnsmasq 公网查询已自动接入代理 DNS')).toBeInTheDocument()
})

it('keeps cancellation available while preparation is pending', () => {
  render(<StatusCard {...props} loadingAction="start" status={{ ...props.status, initializing: true, runtime: { phase: 'preparing' } }} />)
  expect(screen.getByRole('status')).toHaveTextContent('正在检测并配置系统网络')
  const cancel = screen.getByRole('button', { name: '取消启动' })
  expect(cancel).toBeEnabled()
  fireEvent.click(cancel)
  expect(props.onToggleService).toHaveBeenCalled()
})

it('does not show TUN controls for a proxy pool', () => {
  render(<StatusCard {...props} status={{ ...props.status, mode: 'pool' }} />)
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
})

it('does not show stale runtime routing as active after stopping', () => {
  render(<StatusCard {...props} status={{ ...props.status, runtime: { phase: 'stopped', routing: { effective: 'nftables' } } }} />)
  expect(screen.getByRole('status')).toHaveTextContent('启动时自动适配系统网络')
  expect(screen.queryByText('网络诊断')).not.toBeInTheDocument()
})
