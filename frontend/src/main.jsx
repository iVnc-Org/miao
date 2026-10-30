import { AuthGate } from './components/AuthGate.jsx'
import { installAuthFetch } from './authFetch.js'
import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { PrefsProvider } from './i18n.jsx'
import './styles.css'

installAuthFetch()

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <PrefsProvider>
      <AuthGate><App /></AuthGate>
    </PrefsProvider>
  </React.StrictMode>,
)
