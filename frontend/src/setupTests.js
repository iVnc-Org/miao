import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import { LOCALE_STORAGE_KEY, THEME_STORAGE_KEY } from './i18n.jsx'

beforeEach(() => {
  window.localStorage.setItem(LOCALE_STORAGE_KEY, 'zh')
  window.localStorage.setItem(THEME_STORAGE_KEY, 'dark')
})

afterEach(() => {
  cleanup()
})
