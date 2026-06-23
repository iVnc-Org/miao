import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TunProcessCard } from './TunProcessCard.jsx'

function renderTunProcessCard(props = {}) {
  return render(
    <TunProcessCard
      config={{
        enabled: false,
        mode: 'global_bypass',
        match: { names: [], paths: [], path_regex: [] },
        dns_follow_process: true,
        bypass_action: 'bypass',
      }}
      loading={false}
      disabled={false}
      onSave={vi.fn()}
      showToast={vi.fn()}
      {...props}
    />
  )
}

describe('TunProcessCard', () => {
  it('submits process names as a normalized list', async () => {
    const user = userEvent.setup()
    const onSave = vi.fn()

    renderTunProcessCard({ onSave })

    await user.click(screen.getByLabelText('启用 TUN 进程代理'))
    await user.type(screen.getByLabelText('进程/命令名'), 'curl, git-remote-https')
    await user.click(screen.getByRole('button', { name: /保存/ }))

    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({
      enabled: true,
      mode: 'global_bypass',
      match: expect.objectContaining({
        names: ['curl', 'git-remote-https'],
      }),
      dns_follow_process: true,
      bypass_action: 'bypass',
    }))
  })

  it('rejects command lines in the process name field', async () => {
    const user = userEvent.setup()
    const onSave = vi.fn()
    const showToast = vi.fn()

    renderTunProcessCard({ onSave, showToast })

    await user.click(screen.getByLabelText('启用 TUN 进程代理'))
    await user.type(screen.getByLabelText('进程/命令名'), 'git clone https://example.com/repo.git')
    await user.click(screen.getByRole('button', { name: /保存/ }))

    expect(onSave).not.toHaveBeenCalled()
    expect(showToast).toHaveBeenCalledWith(
      '进程名不支持命令参数或空格：git clone https://example.com/repo.git',
      'error',
    )
  })
})
