import { useState } from 'react'
import { Languages, Moon, Plus, Settings, Sun } from 'lucide-react'
import { Button, LogoIcon } from './ui.jsx'
import { SubscriptionModal } from './modals.jsx'
import { useI18n } from '../i18n.jsx'

export function OnboardingScreen({ onAddSub, loadingAction, onOpenAddNode }) {
  const { t, theme, locale, setTheme, setLocale } = useI18n()
  const [showSubscriptionModal, setShowSubscriptionModal] = useState(false)
  const isLoading = loadingAction === 'addSub'
  const nextTheme = theme === 'dark' ? 'light' : 'dark'
  const nextLocale = locale === 'zh' ? 'en' : 'zh'

  return (
    <div className="onboarding">
      <div className="onboarding-card">
        <div className="onboarding-prefs">
          <button
            type="button"
            className="pref-chip"
            onClick={(event) => setTheme(nextTheme, event)}
            title={theme === 'dark' ? t('prefs.themeToLight') : t('prefs.themeToDark')}
            aria-label={theme === 'dark' ? t('prefs.themeToLight') : t('prefs.themeToDark')}
          >
            {theme === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
          </button>
          <button
            type="button"
            className="pref-chip"
            onClick={() => setLocale(nextLocale)}
            title={locale === 'zh' ? t('prefs.langToEn') : t('prefs.langToZh')}
            aria-label={locale === 'zh' ? t('prefs.langToEn') : t('prefs.langToZh')}
          >
            <Languages size={13} />
            <span>{locale === 'zh' ? t('prefs.en') : t('prefs.zh')}</span>
          </button>
        </div>
        <div className="onboarding-header">
          <LogoIcon size={40} />
          <h1 className="onboarding-title">{t('app.brand')}</h1>
          <p className="onboarding-subtitle">{t('onboarding.subtitle')}</p>
        </div>

        <div className="onboarding-section">
          <Button
            tone="primary"
            icon={<Plus size={14} />}
            loading={isLoading}
            onClick={() => setShowSubscriptionModal(true)}
            className="onboarding-node-btn"
          >
            {t('onboarding.addSub')}
          </Button>
        </div>

        <div className="onboarding-divider">
          <span>{t('onboarding.or')}</span>
        </div>

        <div className="onboarding-section">
          <Button
            tone="secondary"
            icon={<Settings size={14} />}
            onClick={onOpenAddNode}
            className="onboarding-node-btn"
          >
            {t('onboarding.addNode')}
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
