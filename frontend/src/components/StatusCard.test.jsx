import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { StatusCard } from './StatusCard.jsx'

const props = {
  status: { running: false, initializing: false, mode: 'global', tun: { routing: 'auto' } },
  traffic: { up: 0, down: 0 }, loadingAction: '',
  onToggleService: vi.fn(), onSetMode: vi.fn(), onSetTunRouting: vi.fn(), onOpenConnections: vi.fn(),
}

it('shows the selected and effective routing separately and retains diagnostics', () => {
  render(<StatusCard {...props} status={{ ...props.status, runtime: { phase: 'ready', routing: { effective: 'policy_route', reason: '使用兼容策略路由' } } }} />)
  expect(screen.getByRole('combobox', { name: '流量接管' })).toHaveValue('auto')
  expect(screen.getByText('当前：兼容模式')).toBeInTheDocument()
  expect(screen.getByRole('status')).toHaveTextContent('使用兼容策略路由')
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'policy_route' } })
  expect(props.onSetTunRouting).toHaveBeenCalledWith('policy_route')
})

it('keeps cancellation available while preparation is pending', () => {
  render(<StatusCard {...props} loadingAction="start" status={{ ...props.status, initializing: true, runtime: { phase: 'preparing' } }} />)
  expect(screen.getByRole('combobox')).toBeDisabled()
  const cancel = screen.getByRole('button', { name: '取消启动' })
  expect(cancel).toBeEnabled()
  fireEvent.click(cancel)
  expect(props.onToggleService).toHaveBeenCalled()
})

it('does not show TUN controls for a proxy pool', () => {
  render(<StatusCard {...props} status={{ ...props.status, mode: 'pool' }} />)
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
})
