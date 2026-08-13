import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { PoolCard } from './PoolCard.jsx'
import { PoolTestResultModal } from './modals.jsx'

const endpoint = {
  tag: 'subscription-node',
  port: 51000,
  listen: '0.0.0.0',
  url: 'socks5://0.0.0.0:51000',
}

function renderPoolCard(props = {}) {
  return render(
    <PoolCard
      proxyMode="pool"
      config={{ listen: '0.0.0.0', base_port: 50000, username: '', password: '' }}
      endpoints={[endpoint]}
      loading={false}
      disabled={false}
      testingPort={null}
      onSave={vi.fn()}
      onTestEndpoint={vi.fn().mockResolvedValue(undefined)}
      showToast={vi.fn()}
      {...props}
    />
  )
}

describe('PoolCard', () => {
  it('keeps listen and credential fields collapsed until configure is clicked', async () => {
    const user = userEvent.setup()
    renderPoolCard()

    expect(screen.queryByPlaceholderText('0.0.0.0')).not.toBeInTheDocument()
    expect(screen.getByText('0.0.0.0:50000 · 无认证')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '配置' }))

    expect(screen.getByPlaceholderText('0.0.0.0')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('50000')).toBeInTheDocument()
  })

  it('starts a test for the endpoint beside the copy button', async () => {
    const user = userEvent.setup()
    const onTestEndpoint = vi.fn().mockResolvedValue(undefined)
    renderPoolCard({ onTestEndpoint })

    await user.click(screen.getByRole('button', { name: '测试 subscription-node' }))

    expect(onTestEndpoint).toHaveBeenCalledWith(endpoint)
    expect(screen.getByRole('button', { name: '复制 subscription-node 的 SOCKS 地址' }))
      .toBeInTheDocument()
  })
})

describe('PoolTestResultModal', () => {
  it('shows the HTTP status and pretty-printed JSON body', () => {
    const body = { ip: '3.0.3.0', nested: { ok: true } }
    render(
      <PoolTestResultModal
        result={{
          tag: 'subscription-node',
          status_code: 404,
          status_text: 'Not Found',
          body,
        }}
        onClose={vi.fn()}
      />
    )

    expect(screen.getByText('HTTP 404 Not Found')).toBeInTheDocument()
    expect(screen.getByLabelText('响应 JSON').textContent).toBe(JSON.stringify(body, null, 2))
  })
})
