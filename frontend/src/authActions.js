import { createContext, useContext } from 'react'

export const AuthActionsContext = createContext(null)

export function useAuthActions() {
  const actions = useContext(AuthActionsContext)
  if (!actions) throw new Error('Panel auth actions are only available after sign-in')
  return actions
}
