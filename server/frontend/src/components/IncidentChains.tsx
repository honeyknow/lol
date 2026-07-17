import { useEffect, useState } from 'react'
import { api, type AlertChain } from '../api/client'
import { GitBranch, Loader } from 'lucide-react'

function relativeTime(val: string | number | null | undefined): string {
  if (!val) return 'Never'
  const ts = typeof val === 'number' ? val * 1000 : new Date(val).getTime()
  if (isNaN(ts)) return 'Unknown'
  const diff = Date.now() - ts
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function severityClass(score: number): string {
  if (score >= 9) return 'crit'
  if (score >= 7) return 'high'
  if (score >= 5) return 'med'
  return 'low'
}

export default function IncidentChains({ hostId }: { hostId?: string | null }) {
  const [chains, setChains] = useState<AlertChain[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const c = await api.getAlertCorrelations()
        let allChains = c.chains ?? []
        if (hostId) {
          allChains = allChains.filter(chain => chain.host_id === hostId)
        }
        setChains(allChains)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [hostId])

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Loader size={24} style={{ animation: 'spin 1s linear infinite', color: 'var(--text-3)' }} />
      </div>
    )
  }

  if (chains.length === 0) {
    return (
      <div className="empty-state">
        <GitBranch size={48} color="var(--border-2)" />
        <h3>No correlated chains</h3>
        <p>No multi-alert incidents detected within a 5-minute window for this host.</p>
      </div>
    )
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 800, margin: '0 auto' }}>
        {chains.map((chain, idx) => (
          <div key={idx} style={{
            background: 'var(--bg-2)',
            border: '1px solid var(--border)',
            borderRadius: 8,
            overflow: 'hidden'
          }}>
            <div style={{
              padding: '12px 16px',
              borderBottom: '1px solid var(--border)',
              background: 'var(--bg)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <GitBranch size={16} color="var(--accent)" />
                <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Host: {chain.host_id}</span>
              </div>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{relativeTime(chain.end)}</span>
            </div>
            
            <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
              {chain.alerts.map((a, i) => {
                const sev = severityClass(a.severity_score)
                return (
                  <div key={a.alert_id} style={{ display: 'flex', gap: 12 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 20 }}>
                      <div style={{ width: 10, height: 10, borderRadius: 5, background: `var(--${sev})`, zIndex: 2 }} />
                      {i < chain.alerts.length - 1 && (
                        <div style={{ width: 2, flex: 1, background: 'var(--border)', marginTop: 4, marginBottom: 4 }} />
                      )}
                    </div>
                    <div style={{ flex: 1, paddingBottom: i < chain.alerts.length - 1 ? 16 : 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 4 }}>{a.rule_name}</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 12, color: 'var(--text-3)' }}>
                        <span style={{ color: `var(--${sev})` }}>Severity: {severityClass(a.severity_score).toUpperCase()} ({a.severity_score})</span>
                        <span>{relativeTime(a.created_at)}</span>
                        {a.technique_id && <span style={{ padding: '2px 6px', background: 'var(--bg-3)', borderRadius: 4, fontSize: 10 }}>{a.technique_id}</span>}
                      </div>
                      {a.summary && <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-2)' }}>{a.summary}</div>}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
