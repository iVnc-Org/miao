import { useState } from 'react'
import { Plus, Settings } from 'lucide-react'
import { Button, LogoIcon } from './ui.jsx'
import { SubscriptionModal } from './modals.jsx'

export function OnboardingScreen({ onAddSub, loadingAction, onOpenAddNode }) {
  const [showSubscriptionModal, setShowSubscriptionModal] = useState(false)
  const isLoading = loadingAction === 'addSub'

  return (
    <div className="onboarding">
      <div className="onboarding-card">
        <div className="onboarding-header">
          <LogoIcon size={40} />
          <h1 className="onboarding-title">Miao</h1>
          <p className="onboarding-subtitle">添加订阅或手动节点以开始使用</p>
        </div>

        <div className="onboarding-section">
          <Button
            tone="primary"
            icon={<Plus size={14} />}
            loading={isLoading}
            onClick={() => setShowSubscriptionModal(true)}
            className="onboarding-node-btn"
          >
            添加订阅
          </Button>
        </div>

        <div className="onboarding-divider">
          <span>或</span>
        </div>

        <div className="onboarding-section">
          <Button
            tone="secondary"
            icon={<Settings size={14} />}
            onClick={onOpenAddNode}
            className="onboarding-node-btn"
          >
            手动添加节点
          </Button>
        </div>
      </div>
      {showSubscriptionModal && (
        <SubscriptionModal
          open
          loading={isLoading}
          onClose={() => setShowSubscriptionModal(false)}
          onSubmit={onAddSub}
        />
      )}
    </div>
  )
}
