import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { LOCALE_STORAGE_KEY, PrefsProvider, THEME_STORAGE_KEY, revealThemeChange, translate } from './i18n.jsx'
import { TopBar } from './components/TopBar.jsx'

beforeEach(() => {
  window.localStorage.clear()
  window.localStorage.setItem(LOCALE_STORAGE_KEY, 'zh')
  window.localStorage.setItem(THEME_STORAGE_KEY, 'dark')
  document.documentElement.removeAttribute('data-theme')
})

afterEach(() => {
  window.localStorage.clear()
})

describe('i18n and theme prefs', () => {
  it('translates the same key in Chinese and English', () => {
    expect(translate('zh', 'pool.configure')).toBe('配置')
    expect(translate('en', 'pool.configure')).toBe('Configure')
  })

  it('persists theme and locale from the top bar', async () => {
    const user = userEvent.setup()
    render(
      <PrefsProvider>
        <TopBar
          status={{ running: false, initializing: false }}
          versionInfo={{ current: 'abc1234', has_update: false }}
          upgrading={false}
          onUpgradeClick={() => {}}
        />
      </PrefsProvider>
    )

    expect(screen.getByRole('button', { name: '升级' })).toBeInTheDocument()
    expect(screen.getByText('abc1234')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '切换到浅色' }))
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')

    await user.click(screen.getByRole('button', { name: 'Switch to English' }))
    expect(document.documentElement.lang).toBe('en')
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('en')
    expect(screen.getByText('Stopped')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Upgrade' })).toBeInTheDocument()
  })

  it('shows a pending upgrade label and the latest commit after an update is found', () => {
    render(
      <PrefsProvider>
        <TopBar
          status={{ running: true, initializing: false }}
          versionInfo={{
            current: 'abc1234',
            commit_short: 'abc1234',
            latest: 'def5678',
            has_update: true,
            commit_url: 'https://github.com/iVnc-Org/miao/commit/abc1234',
          }}
          upgrading={false}
          onUpgradeClick={() => {}}
        />
      </PrefsProvider>
    )

    expect(screen.getByRole('button', { name: '待升级' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '查看待升级版本提交' })).toHaveAttribute(
      'href',
      'https://github.com/iVnc-Org/miao/commit/def5678'
    )
    expect(screen.getByText('def5678')).toBeInTheDocument()
  })

  it('covers the old theme and then reveals the new one from the toggle', () => {
    document.documentElement.setAttribute('data-theme', 'dark')
    document.body.innerHTML = ''

    const veil = revealThemeChange('light', {
      currentTarget: {
        getBoundingClientRect: () => ({ left: 10, top: 8, width: 20, height: 16 }),
      },
    }, 'dark')

    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(veil).toBeTruthy()
    expect(veil.className).toContain('theme-reveal-veil')
    expect(veil.getAttribute('data-theme')).toBe('dark')
    expect(veil.style.getPropertyValue('--theme-reveal-x')).toBe('20px')
    expect(veil.style.getPropertyValue('--theme-reveal-y')).toBe('16px')
    veil.remove()
  })
})
