import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { SubsCard } from './SubsCard.jsx'

describe('SubsCard', () => {
  it('renders local subscriptions by display name without exposing the internal id', () => {
    render(
      <SubsCard
        subs={[{
          url: 'content://private-digest',
          name: '本地备用',
          local: true,
          state: 'cached',
          node_count: 12,
        }]}
        loadingAction=""
        onAddSub={vi.fn()}
        onDeleteSub={vi.fn()}
        onReplaceSub={vi.fn()}
        onRefreshSubs={vi.fn()}
        isInitializing={false}
      />
    )

    expect(screen.getByText('本地备用')).toBeInTheDocument()
    expect(screen.getByText('12 个节点 · 使用本地内容')).toBeInTheDocument()
    expect(screen.queryByText('content://private-digest')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('替换订阅链接')).not.toBeInTheDocument()

    const refresh = screen.getByRole('button', { name: '刷新' })
    const add = screen.getByRole('button', { name: '添加订阅' })
    expect(refresh.compareDocumentPosition(add) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })
  it('shows genuine parsing failures as warnings while retaining successful nodes', () => {
    render(<SubsCard
      subs={[{ url: 'content://test', local: true, state: 'ok', node_count: 13, error: '1 invalid entry' }]}
      loadingAction="" onAddSub={vi.fn()} onDeleteSub={vi.fn()} onReplaceSub={vi.fn()}
      onRefreshSubs={vi.fn()} isInitializing={false}
    />)
    expect(screen.getByText('1 invalid entry')).toHaveClass('warning')
  })

  it('keeps compatibility details separate from the successful subscription status', () => {
    render(<SubsCard
      subs={[{ url: 'content://test', local: true, state: 'ok', node_count: 37, details: [
        'URI line #13: fastopen is not applicable to QUIC and was ignored',
        '2 ordinary or ambiguous HTTP(S) web links skipped',
      ] }]}
      loadingAction="" onAddSub={vi.fn()} onDeleteSub={vi.fn()} onReplaceSub={vi.fn()}
      onRefreshSubs={vi.fn()} isInitializing={false}
    />)
    expect(screen.getByText('成功解析 37 个节点 · 本地内容')).toHaveClass('success')
    expect(screen.getByText('解析详情')).toBeInTheDocument()
    expect(screen.getByText(/第 13 行/)).toBeInTheDocument()
    expect(screen.getByText(/已跳过 2 条/)).toBeInTheDocument()
    expect(screen.getByText('解析详情').closest('details')).not.toHaveAttribute('open')
  })

})
