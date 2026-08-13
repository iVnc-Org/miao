import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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

    await user.click(screen.getByRole('button', { name: '切换到浅色' }))
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')

    await user.click(screen.getByRole('button', { name: 'Switch to English' }))
    expect(document.documentElement.lang).toBe('en')
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('en')
    expect(screen.getByText('Stopped')).toBeInTheDocument()
  })

  it('reveals the next theme through a view transition when available', async () => {
    const apply = vi.fn()
    const finished = Promise.resolve()
    document.startViewTransition = vi.fn((callback) => {
      callback()
      apply()
      return { finished }
    })

    revealThemeChange('light', {
      currentTarget: {
        getBoundingClientRect: () => ({ left: 10, top: 8, width: 20, height: 16 }),
      },
    })

    expect(document.startViewTransition).toHaveBeenCalledTimes(1)
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(document.documentElement.classList.contains('theme-revealing')).toBe(true)
    await finished
    await Promise.resolve()
    expect(document.documentElement.classList.contains('theme-revealing')).toBe(false)
    delete document.startViewTransition
  })
})
