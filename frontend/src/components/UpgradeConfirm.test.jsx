import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { DEFAULT_GITHUB_PROXY, UpgradeConfirm } from './UpgradeConfirm.jsx'

it('keeps a changed proxy for the next confirmation and reset restores the default', () => {
  localStorage.clear()
  const onConfirm = vi.fn()
  const { rerender } = render(<UpgradeConfirm open current="abc1234" target="def5678" onCancel={vi.fn()} onConfirm={onConfirm} />)
  const input = screen.getByLabelText('GitHub 代理前缀')
  expect(input).toHaveValue(DEFAULT_GITHUB_PROXY)
  fireEvent.change(input, { target: { value: 'http://example.test/gh/' } })
  fireEvent.click(screen.getByRole('button', { name: '确认升级' }))
  expect(onConfirm).not.toHaveBeenCalled()
  expect(screen.getByRole('alert')).toHaveTextContent('HTTPS')
  fireEvent.change(input, { target: { value: 'https://example.test/gh' } })
  fireEvent.click(screen.getByRole('button', { name: '确认升级' }))
  expect(onConfirm).toHaveBeenCalledWith('https://example.test/gh')
  expect(localStorage.getItem('miao.upgrade-proxy')).toBe('https://example.test/gh/')

  rerender(<UpgradeConfirm open={false} current="abc1234" target="def5678" onCancel={vi.fn()} onConfirm={onConfirm} />)
  rerender(<UpgradeConfirm open current="abc1234" target="def5678" onCancel={vi.fn()} onConfirm={onConfirm} />)
  expect(screen.getByLabelText('GitHub 代理前缀')).toHaveValue('https://example.test/gh/')
  fireEvent.click(screen.getByRole('button', { name: '重置为默认' }))
  expect(screen.getByLabelText('GitHub 代理前缀')).toHaveValue(DEFAULT_GITHUB_PROXY)
  expect(localStorage.getItem('miao.upgrade-proxy')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: '确认升级' }))
  expect(onConfirm).toHaveBeenLastCalledWith(DEFAULT_GITHUB_PROXY)
})
