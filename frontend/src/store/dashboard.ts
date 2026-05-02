import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { TabId, Incident } from '../types'

interface DashboardState {
  // UI State
  activeTab: TabId
  sidebarCollapsed: boolean
  theme: 'dark' | 'light'

  // Live feed
  liveEvents: Incident[]
  wsConnected: boolean

  // Critical alert toast
  criticalAlert: (Incident & { _alertId: string }) | null

  // Selected entities (for cross-tab navigation)
  selectedThreatId: string | null
  selectedActorId: string | null

  // Actions
  setActiveTab: (tab: TabId) => void
  toggleSidebar: () => void
  toggleTheme: () => void
  addLiveEvent: (event: Incident) => void
  setWsConnected: (connected: boolean) => void
  setCriticalAlert: (event: Incident) => void
  dismissCriticalAlert: () => void
  setSelectedThreat: (id: string | null) => void
  setSelectedActor: (id: string | null) => void
}

export const useDashboard = create<DashboardState>()(
  persist(
    (set) => ({
      activeTab: 'overview',
      sidebarCollapsed: false,
      theme: 'dark',
      liveEvents: [],
      wsConnected: false,
      criticalAlert: null,
      selectedThreatId: null,
      selectedActorId: null,

      setActiveTab: (tab) => set({ activeTab: tab }),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      toggleTheme: () => set((s) => ({ theme: s.theme === 'dark' ? 'light' : 'dark' })),

      addLiveEvent: (event) =>
        set((s) => ({
          liveEvents: [event, ...s.liveEvents].slice(0, 100),
        })),

      setWsConnected: (connected) => set({ wsConnected: connected }),
      setCriticalAlert: (event) =>
        set({ criticalAlert: { ...event, _alertId: `${Date.now()}` } }),
      dismissCriticalAlert: () => set({ criticalAlert: null }),
      setSelectedThreat: (id) => set({ selectedThreatId: id }),
      setSelectedActor: (id) => set({ selectedActorId: id }),
    }),
    {
      name: 'cps-dashboard',
      partialize: (s) => ({
        activeTab: s.activeTab,
        sidebarCollapsed: s.sidebarCollapsed,
        theme: s.theme,
      }),
    },
  ),
)
