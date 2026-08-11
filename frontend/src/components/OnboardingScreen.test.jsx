import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { OnboardingScreen } from './OnboardingScreen.jsx'

function renderOnboarding(props = {}) {
  return render(
    <OnboardingScreen
      onAddSub={vi.fn()}
      loadingAction=""
      onOpenAddNode={vi.fn()}
      {...props}
    />
  )
}

describe('OnboardingScreen', () => {
  it('submits a trimmed subscription URL', async () => {
    const user = userEvent.setup()
    const onAddSub = vi.fn().mockResolvedValue(true)

    renderOnboarding({ onAddSub })

    await user.click(screen.getByRole('button', { name: /添加订阅/ }))
    await user.type(
      screen.getByPlaceholderText('https://example.com/subscription'),
      '  https://example.com/sub  '
    )
    await user.click(screen.getByRole('button', { name: '添加' }))

    expect(onAddSub).toHaveBeenCalledWith({ mode: 'url', url: 'https://example.com/sub' })
  })

  it('submits pasted content with an optional display name', async () => {
    const user = userEvent.setup()
    const onAddSub = vi.fn().mockResolvedValue(true)

    renderOnboarding({ onAddSub })

    await user.click(screen.getByRole('button', { name: /添加订阅/ }))
    await user.click(screen.getByRole('button', { name: /粘贴内容/ }))
    await user.type(screen.getByLabelText('显示名称（可选）'), '本地备用')
    await user.type(screen.getByLabelText('订阅内容'), 'c3M6Ly9leGFtcGxl')
    await user.click(screen.getByRole('button', { name: '添加' }))

    expect(onAddSub).toHaveBeenCalledWith({
      mode: 'content',
      name: '本地备用',
      content: 'c3M6Ly9leGFtcGxl',
    })
  })

  it('opens the manual node modal', async () => {
    const user = userEvent.setup()
    const onOpenAddNode = vi.fn()

    renderOnboarding({ onOpenAddNode })

    await user.click(screen.getByRole('button', { name: /手动添加节点/ }))

    expect(onOpenAddNode).toHaveBeenCalledTimes(1)
  })
})
