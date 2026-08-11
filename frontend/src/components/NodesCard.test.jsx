import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { NodesCard } from './NodesCard.jsx'

describe('NodesCard', () => {
  it('passes the selected manual node to the edit handler', async () => {
    const user = userEvent.setup()
    const node = {
      tag: 'edge-node',
      server: '127.0.0.1',
      server_port: 1080,
      node_type: 'socks',
      outbound: {
        type: 'socks',
        tag: 'edge-node',
        server: '127.0.0.1',
        server_port: 1080,
      },
    }
    const onEditNode = vi.fn()

    render(
      <NodesCard
        nodes={[node]}
        onDeleteNode={vi.fn()}
        onEditNode={onEditNode}
        onOpenAddNode={vi.fn()}
      />
    )

    await user.click(screen.getByRole('button', { name: '编辑节点 edge-node' }))

    expect(onEditNode).toHaveBeenCalledWith(node)
  })
})
