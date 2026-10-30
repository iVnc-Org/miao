import { KeyRound, Languages, LoaderCircle, LogOut, Moon, Sun } from 'lucide-react'
import { classNames } from '../utils.js'
import { useI18n } from '../i18n.jsx'
import { LogoIcon } from './ui.jsx'

function commitLabel(versionInfo) {
  if (versionInfo.has_update && versionInfo.latest) return versionInfo.latest
  return versionInfo.commit_short || versionInfo.current || 'unknown'
}

function commitHref(versionInfo, label) {
  const current = versionInfo.commit_full || versionInfo.commit_short
  if (versionInfo.commit_url && current && label && label !== 'unknown') {
    return versionInfo.commit_url.replace(current, label)
  }
  return versionInfo.commit_url || null
}

export function CommitBadge({ versionInfo }) {
  const { t } = useI18n()
  const label = commitLabel(versionInfo)
  const href = commitHref(versionInfo, label)
  const commitTitle = versionInfo.has_update
    ? (versionInfo.latest || label)
    : (versionInfo.commit_full || label)
  const title = versionInfo.sing_box_version
    ? `${commitTitle}\nsing-box ${versionInfo.sing_box_version}\n${versionInfo.sing_box_revision || ''}\n${versionInfo.sing_box_tags || ''}`
    : commitTitle

  if (href) {
    return (
      <a
        className="commit-badge"
        href={href}
        target="_blank"
        rel="noreferrer"
        title={title}
        aria-label={versionInfo.has_update ? t('prefs.openLatestCommit') : t('prefs.openCommit')}
      >
        {label}
      </a>
    )
  }

  return (
    <div className="commit-badge" title={title}>
      {label}
    </div>
  )
}

export function TopBar({ status, versionInfo, upgrading, checkingVersion = false, onUpgradeClick, onChangePassword, onSignOut, signingOut = false }) {
  const { t, theme, locale, setTheme, setLocale } = useI18n()
  const nextTheme = theme === 'dark' ? 'light' : 'dark'
  const nextLocale = locale === 'zh' ? 'en' : 'zh'
  const busy = upgrading || checkingVersion
  const upgradeLabel = upgrading ? (locale === 'zh' ? '升级中' : 'Upgrading') : versionInfo.has_update ? t('prefs.upgradePending') : t('prefs.upgrade')

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <div className="brand">
          <LogoIcon size={36} />
          <span className="brand-name">{t('app.brand')}</span>
        </div>
        <div className="topbar-spacer" />
        <div className="topbar-prefs">
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
          <button
            type="button"
            className="pref-chip"
            onClick={(event) => onChangePassword?.(event.currentTarget)}
            title={t('prefs.changePassword')}
            aria-label={t('prefs.changePassword')}
          >
            <KeyRound size={13} />
            <span>{t('prefs.changePassword')}</span>
          </button>
          <button
            type="button"
            className="pref-chip"
            onClick={onSignOut}
            disabled={signingOut}
            title={t('prefs.signOut')}
            aria-label={t('prefs.signOut')}
          >
            <LogOut size={13} />
            <span>{t('prefs.signOut')}</span>
          </button>
        </div>
        <div className={classNames('run-badge', status.running ? 'running' : 'stopped')}>
          <span className="run-dot" />
          {status.running ? t('status.running') : t('status.stopped')}
        </div>
        <div className="topbar-version">
          <button
            className={classNames('version-chip', versionInfo.has_update && 'has-update')}
            onClick={onUpgradeClick}
            disabled={!upgrading && (checkingVersion || status.initializing)}
          >
            {busy && <LoaderCircle size={12} className="spin" />}
            {!busy && versionInfo.has_update && <span className="version-dot" />}
            <span>{upgradeLabel}</span>
          </button>
          <CommitBadge versionInfo={versionInfo} />
        </div>
      </div>
    </header>
  )
}
