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
  })
})
