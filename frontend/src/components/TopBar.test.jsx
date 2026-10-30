import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { TopBar } from './TopBar.jsx'

it('keeps standalone upgrades available and prevents upgrades managed by iVnc', () => {
  const onUpgradeClick = vi.fn()
  const props = { status: { running: false, initializing: false }, versionInfo: { current: 'abc1234' }, onUpgradeClick }
  const { rerender } = render(<TopBar {...props} />)
  fireEvent.click(screen.getByRole('button', { name: '升级' }))
  expect(onUpgradeClick).toHaveBeenCalledTimes(1)
  rerender(<TopBar {...props} versionInfo={{ ...props.versionInfo, managed_by: 'ivnc' }} />)
  const managed = screen.getByRole('button', { name: '随 iVnc 更新' })
  expect(managed).toBeDisabled()
  fireEvent.click(managed)
  expect(onUpgradeClick).toHaveBeenCalledTimes(1)
})
