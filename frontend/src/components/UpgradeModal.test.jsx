import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { UpgradeModal } from './UpgradeModal.jsx'
import { TopBar } from './TopBar.jsx'

it('offers cancellation while downloading and explains when replacement has started', async () => {
  const cancel = vi.fn().mockResolvedValue()
  const { rerender } = render(<UpgradeModal upgrade={{ open: true, offline: false, cancel, dismiss: vi.fn(), status: {
    active: true, stage: 'Downloading binary via example.test', downloaded: 10, total: 100, events: [],
  } }} />)
  fireEvent.click(screen.getByRole('button', { name: '取消升级' }))
  expect(cancel).toHaveBeenCalledOnce()
  rerender(<UpgradeModal upgrade={{ open: true, offline: false, cancel, dismiss: vi.fn(), status: {
    active: true, stage: 'Backing up and installing binary', events: [],
  } }} />)
  expect(screen.getByRole('button', { name: '取消升级' })).toBeDisabled()
  expect(screen.getByText('程序即将替换，无法取消')).toBeInTheDocument()
})

it('shows progress, history and reconnection while the upgrade is active', () => {
  render(<UpgradeModal upgrade={{ open: true, offline: true, dismiss: vi.fn(), status: {
    active: true, stage: 'Downloading binary via httptunnel.top/gh', downloaded: 50, total: 100,
    events: ['Checking release', 'Downloading binary via httptunnel.top/gh'],
  } }} />)
  expect(screen.getByRole('dialog')).toBeInTheDocument()
  expect(screen.getByRole('progressbar')).toHaveAttribute('value', '50')
  expect(screen.getByText(/连接暂时中断/)).toBeInTheDocument()
  expect(screen.getByText('检查最新版本')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '关闭' })).not.toBeInTheDocument()
})

it('labels the top-right button as upgrading and allows reopening progress', () => {
  render(<TopBar status={{ running: false, initializing: true }} versionInfo={{ current: 'abc1234' }} upgrading onUpgradeClick={vi.fn()} />)
  expect(screen.getByRole('button', { name: '升级中' })).toBeEnabled()
})
