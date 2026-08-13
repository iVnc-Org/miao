import { Languages, LoaderCircle, Moon, Sun } from 'lucide-react'
import { classNames } from '../utils.js'
import { useI18n } from '../i18n.jsx'
import { LogoIcon } from './ui.jsx'

export function TopBar({ status, versionInfo, upgrading, onUpgradeClick }) {
  const { t, theme, locale, setTheme, setLocale } = useI18n()
  const nextTheme = theme === 'dark' ? 'light' : 'dark'
  const nextLocale = locale === 'zh' ? 'en' : 'zh'
  const versionLabel = versionInfo.has_update
    ? (versionInfo.latest || versionInfo.current || '----')
    : (versionInfo.current || '----')

  return (
    <header className="topbar">
      <div className="brand">
        <LogoIcon size={36} />
        <span className="brand-name">{t('app.brand')}</span>
      </div>
      <div className="topbar-spacer" />
      <div className="topbar-prefs">
        <button
          type="button"
          className="pref-chip"
          onClick={() => setTheme(nextTheme)}
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
      <div className={classNames('run-badge', status.running ? 'running' : 'stopped')}>
        <span className="run-dot" />
        {status.running ? t('status.running') : t('status.stopped')}
      </div>
      <button
        className={classNames('version-chip', versionInfo.has_update && 'has-update')}
        onClick={onUpgradeClick}
        disabled={upgrading || status.initializing}
      >
        {upgrading && <LoaderCircle size={12} className="spin" />}
        {!upgrading && versionInfo.has_update && <span className="version-dot" />}
        <span>{versionLabel}</span>
      </button>
    </header>
  )
}
