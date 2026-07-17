import { useEffect, useState } from 'react'
import { Database, Sparkles } from 'lucide-react'
import { api, type HealthStatus, type Stats } from '../api/client'
import type { View } from '../App'
import Button from './Button'
import AccountMenu from './AccountMenu'

interface UserIdentity {
  email: string
  role: 'admin' | 'user'
  tenant: Record<string, unknown> | null
}

interface Props {
  view: View
  onViewChange: (v: View) => void
  onToggleAI?: () => void
  user?: UserIdentity | null
  onSignOut?: () => void
  isAdmin?: boolean
  impersonating?: string | null
  onStopImpersonating?: () => void
}

const NAV: { id: View; label: string; adminOnly?: boolean }[] = [
  { id: 'overview',  label: 'Overview' },
  { id: 'hunt',      label: 'Threat Hunt' },
  { id: 'firehose',  label: 'Firehose' },
  { id: 'rules',     label: 'Rules Engine' },
  { id: 'admin',     label: 'Admin', adminOnly: true },
]

function statusTone(status?: HealthStatus['status']): string {
  if (status === 'healthy')  return '#22C55E'
  if (status === 'degraded') return 'var(--high)'
  return 'var(--text-3)'
}

function statusLabel(status?: HealthStatus['status']): string {
  if (!status) return 'Unknown'
  return status.replace('_', ' ').toUpperCase()
}

export default function Topbar({
  view, onViewChange, onToggleAI,
  user, onSignOut, isAdmin,
  impersonating, onStopImpersonating,
}: Props) {
  const [stats,  setStats]  = useState<Stats | null>(null)
  const [health, setHealth] = useState<HealthStatus | null>(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [s, h] = await Promise.all([api.getStats(), api.getHealth()])
        setStats(s)
        setHealth(h)
      } catch {
        // backend may still be starting
      }
    }
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  const rc = stats?.row_counts ?? {}
  const totalAlerts = rc.alerts ?? 0
  const totalEvents = (rc.process_events ?? 0) + (rc.network_events ?? 0) + (rc.file_events ?? 0) + (rc.registry_events ?? 0) + (rc.amsi_events ?? 0)

  // Filter nav tabs based on role
  const visibleNav = NAV.filter(n => !n.adminOnly || isAdmin)

  return (
    <div className="topbar" style={{
      margin: 16,
      borderRadius: 12,
      background: '#18191c',
      border: '1px solid rgba(255,255,255,0.06)',
      boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
      height: 52,
      position: 'sticky',
      top: 16,
      zIndex: 100,
      boxSizing: 'border-box'
    }}>
      {/* Logo */}
      <div style={{
        display: 'flex', alignItems: 'center',
        paddingRight: 24, borderRight: '1px solid rgba(255,255,255,0.06)', marginRight: 8,
      }}>
        <div style={{
          fontSize: 18, fontWeight: 900, letterSpacing: '1px',
          color: '#ef4444', textShadow: '0 0 12px rgba(239, 68, 68, 0.6)',
          fontStyle: 'italic',
        }}>
          ISHA-X
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '0 8px' }}>
        {visibleNav.map(n => {
          const active = view === n.id
          const adminTab = n.id === 'admin'
          return (
            <button
              key={n.id}
              onClick={() => onViewChange(n.id)}
              style={{
                display: 'flex', alignItems: 'center',
                padding: '6px 12px',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: active ? 600 : 500,
                whiteSpace: 'nowrap',
                flexShrink: 0,
                color: active ? '#fff' : 'var(--text-3)',
                position: 'relative',
                transition: 'color 0.15s ease',
              }}
            >
              {n.label}
              {active && (
                <div style={{
                  position: 'absolute', bottom: -2, left: 12, right: 12, height: 2,
                  background: '#ef4444',
                  boxShadow: '0 -2px 10px rgba(239, 68, 68, 0.8)',
                  borderRadius: '2px 2px 0 0'
                }} />
              )}
            </button>
          )
        })}
      </nav>

      <div style={{ flex: 1 }} />

      {/* Right side: status pills + AccountMenu */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Health status */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '4px 10px',
            whiteSpace: 'nowrap', flexShrink: 0,
            background: 'transparent',
            border: `1px solid ${health?.status === 'healthy' ? 'rgba(34,197,94,0.4)' : health?.status === 'degraded' ? 'rgba(234,179,8,0.4)' : 'rgba(255,255,255,0.1)'}`,
            borderRadius: 6,
          }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: health?.status === 'healthy' ? '#22C55E' : health?.status === 'degraded' ? '#eab308' : 'var(--text-3)' }}>
              {health?.status === 'healthy' ? '✓' : '⚠️'} {statusLabel(health?.status)}
            </span>
          </div>

          {/* Events count pill */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '4px 10px', whiteSpace: 'nowrap', flexShrink: 0,
            background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.4)', borderRadius: 6,
          }}>
            <Database size={12} color="#60a5fa" />
            <span style={{ fontSize: 12, color: '#60a5fa', fontWeight: 600 }}>{totalEvents.toLocaleString()} Events</span>
          </div>
        </div>

        {/* Divider before Account & AI */}
        <div style={{ width: 1, height: 24, background: 'rgba(255,255,255,0.06)' }} />

        {/* Ask AI button */}
        {onToggleAI && (
          <Button
            variant="custom"
            customColor="var(--accent)"
            onClick={onToggleAI}
            style={{ padding: '6px 12px', borderRadius: 99, fontSize: 12, marginLeft: 4 }}
            icon={<Sparkles size={14} />}
          >
            Ask AI
          </Button>
        )}

        {/* Account Menu — shown only when user is loaded */}
        {user && (
          <AccountMenu
            email={user.email}
            role={user.role}
            onSignOut={onSignOut}
          />
        )}
      </div>
    </div>
  )
}
