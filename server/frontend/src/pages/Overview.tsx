import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Database,
  Monitor,
  Search,
  ShieldCheck,
  Wifi,
  ChevronRight,
} from 'lucide-react'
import { api, type Alert, type HealthStatus, type RegisteredEndpoint, type Stats } from '../api/client'


function relativeTime(val: string | number | null | undefined): string {
  if (!val) return 'Never'
  let ts: number
  if (typeof val === 'number') {
    ts = val > 1e11 ? val : val * 1000 // Handle ms or s epoch
  } else if (typeof val === 'string' && /^\d+(\.\d+)?$/.test(val)) {
    const num = parseFloat(val)
    ts = num > 1e11 ? num : num * 1000
  } else {
    ts = new Date(val as string).getTime()
  }
  if (Number.isNaN(ts)) return 'Unknown'
  const diff = Date.now() - ts
  if (diff < 0) return 'Just now'
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`
  return `${Math.floor(mins / 1440)}d ago`
}

function isLive(iso: string | null): boolean {
  if (!iso) return false
  return Date.now() - new Date(iso).getTime() < 5 * 60 * 1000
}

function labelFromRecord(value: unknown): string {
  if (!value || typeof value !== 'object') return 'Unknown'
  const row = value as Record<string, unknown>
  const host = typeof row.agent_name === 'string' ? row.agent_name : typeof row.host_id === 'string' ? row.host_id : null
  const channel = typeof row.channel === 'string' ? row.channel : null
  const eventId = row.event_id != null ? `EID ${row.event_id}` : null
  return [host, channel, eventId].filter(Boolean).join(' | ') || 'Unknown'
}

function severityLabel(score: number): string {
  if (score >= 9) return 'Critical'
  if (score >= 7) return 'High'
  if (score >= 5) return 'Medium'
  return 'Low'
}

function severityClass(score: number): string {
  if (score >= 9) return 'crit'
  if (score >= 7) return 'high'
  if (score >= 5) return 'med'
  return 'low'
}

function sourceLabel(alert: Alert): string {
  return [alert.host_id, alert.source_layer, alert.event_id ? `EID ${alert.event_id}` : null].filter(Boolean).join(' | ')
}

export default function Overview({ onHostClick, impersonateTenantId }: {
  onHostClick?: (hostId: string) => void
  impersonateTenantId?: string
}) {
  const [stats, setStats] = useState<Stats | null>(null)
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [hosts, setHosts] = useState<RegisteredEndpoint[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState<string | null>(null)
  const [downloadSuccess, setDownloadSuccess] = useState(false)

  const handleDownloadAgent = async () => {
    setDownloading(true)
    setDownloadError(null)
    setDownloadSuccess(false)
    try {
      await api.downloadAgent()
      setDownloadSuccess(true)
      setTimeout(() => setDownloadSuccess(false), 5000)
    } catch (e: unknown) {
      setDownloadError(e instanceof Error ? e.message : 'Download failed.')
    } finally {
      setDownloading(false)
    }
  }

  useEffect(() => {
    const load = async () => {
      try {
        const [s, h, he, a] = await Promise.all([
          api.getStats(),
          api.getHosts(),
          api.getHealth(),
          api.getAlerts({ limit: 8 }),
        ])
        setStats(s)
        setHosts(h.hosts ?? [])
        setHealth(he)
        setAlerts(a.alerts ?? [])
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }

    load()
    const t = setInterval(load, 20000)
    return () => clearInterval(t)
  }, [])

  const rc = stats?.row_counts ?? {}
  const totalAlerts = rc.alerts ?? 0
  const totalHosts = hosts.length
  const liveHosts = hosts.filter(h => isLive(h.last_seen)).length
  const filteredHosts = hosts.filter(h => {
    const q = search.trim().toLowerCase()
    if (!q) return true
    return (h.pc_name || h.host_id).toLowerCase().includes(q) || h.host_id.toLowerCase().includes(q)
  })

  const severityCounts = stats?.severity_counts ?? { crit: 0, high: 0, med: 0, low: 0 }

  const techniqueCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const alert of alerts) {
      if (!alert.technique_id) continue
      counts.set(alert.technique_id, (counts.get(alert.technique_id) ?? 0) + 1)
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
  }, [alerts])

  const processCount = rc.process_events ?? 0
  const networkCount = rc.network_events ?? 0
  const fileCount = rc.file_events ?? 0
  const registryCount = rc.registry_events ?? 0
  const amsiCount = rc.amsi_events ?? 0

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="spinner" />
      </div>
    )
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="card" style={{
          padding: 18,
        }}>

            <div style={{ padding: '8px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <ShieldCheck size={16} color="var(--accent)" />
                <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--text-3)' }}>
                  Ops dashboard
                </span>
              </div>
              <h1 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)', letterSpacing: '-0.5px' }}>
                Security overview
              </h1>
              <p style={{ marginTop: 6, fontSize: 13, color: 'var(--text-3)', maxWidth: 760 }}>
                Live telemetry, endpoint freshness, and detection state. Only signals backed by ingested events are shown here.
              </p>
            </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 12, marginTop: 16 }}>
            <SummaryCard
              icon={AlertTriangle}
              label="Total Alerts"
              value={totalAlerts}
              tone="var(--crit)"
              detail={`${severityCounts.crit} critical, ${severityCounts.high} high, ${severityCounts.med} med`}
            />
            <SummaryCard
              icon={Monitor}
              label="Endpoints"
              value={`${liveHosts}/${totalHosts}`}
              tone="var(--accent)"
              detail={liveHosts > 0 ? `${liveHosts} host${liveHosts === 1 ? '' : 's'} live now` : 'No live hosts'}
            />
            <SummaryCard
              icon={Database}
              label="Pipeline lag"
              value={health?.lag_seconds != null ? `${health.lag_seconds}s` : 'n/a'}
              tone="var(--info)"
              detail={health?.last_event ? `Last event ${relativeTime((health.last_event as Record<string, unknown>).wazuh_ts as string | null | undefined)}` : 'No last event'}
            />
          </div>
        </div>

        {health?.warnings?.length ? (
          <div className="card" style={{ padding: 14, borderColor: 'rgba(245,158,11,0.35)', background: 'rgba(245,158,11,0.08)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <AlertTriangle size={14} color="var(--high)" />
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>Data quality warnings</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {health.warnings.map(w => (
                <span key={w} style={{ fontSize: 12, color: 'var(--text-2)' }}>{w}</span>
              ))}
            </div>
          </div>
        ) : null}

        {/* Download Agent Card — shown to all users, prominent when no hosts connected */}
        {!impersonateTenantId && (
          <div className="card" style={{
            padding: '18px 20px',
            borderColor: totalHosts === 0 ? 'rgba(99,102,241,0.5)' : 'rgba(99,102,241,0.2)',
            background: totalHosts === 0
              ? 'linear-gradient(135deg, rgba(99,102,241,0.12) 0%, rgba(139,92,246,0.08) 100%)'
              : 'rgba(99,102,241,0.04)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 16,
            flexWrap: 'wrap',
          }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
                {totalHosts === 0 ? '🚀 No endpoints connected yet' : '⬇️ Add another endpoint'}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                {totalHosts === 0
                  ? 'Download your personalised agent installer. Double-click to silently deploy on any Windows PC.'
                  : 'Generate a new installer to connect an additional device to your account.'}
              </div>
              {downloadError && (
                <div style={{ marginTop: 8, fontSize: 12, color: 'var(--crit)', fontWeight: 600 }}>
                  ⚠ {downloadError}
                </div>
              )}
              {downloadSuccess && (
                <div style={{ marginTop: 8, fontSize: 12, color: '#22c55e', fontWeight: 600 }}>
                  ✓ Download started! Run ISHAX_Setup.exe as Administrator on your target PC.
                </div>
              )}
            </div>
            <button
              id="download-agent-btn"
              onClick={handleDownloadAgent}
              disabled={downloading}
              style={{
                padding: '10px 24px',
                borderRadius: 8,
                background: downloading ? 'rgba(99,102,241,0.3)' : 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                border: 'none',
                color: '#fff',
                fontWeight: 700,
                fontSize: 13,
                cursor: downloading ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                whiteSpace: 'nowrap',
                transition: 'opacity 0.2s',
                opacity: downloading ? 0.7 : 1,
                boxShadow: downloading ? 'none' : '0 4px 12px rgba(99,102,241,0.35)',
              }}
            >
              {downloading ? (
                <>
                  <div style={{ width: 14, height: 14, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                  Compiling... (~5s)
                </>
              ) : (
                <>⬇ Download My Agent</>
              )}
            </button>
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          <div className="card" style={{ overflow: 'hidden' }}>
            <div style={{
              padding: '14px 18px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 12,
              flexWrap: 'wrap',
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Monitor size={15} color="var(--accent)" />
                  <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Managed endpoints</span>
                  <span style={{
                    background: 'var(--bg-3)',
                    border: '1px solid var(--border)',
                    borderRadius: 99,
                    padding: '1px 8px',
                    fontSize: 11,
                    color: 'var(--text-3)',
                  }}>
                    {hosts.length}
                  </span>
                </div>
                <p style={{ marginTop: 4, fontSize: 12, color: 'var(--text-3)' }}>
                  Registration and last-seen freshness only. No synthetic host data is shown.
                </p>
              </div>

              <div style={{ position: 'relative' }}>
                <Search size={13} style={{
                  position: 'absolute',
                  left: 10,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-3)',
                }} />
                <input
                  placeholder="Search hosts..."
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  style={{ paddingLeft: 30, paddingRight: 12, paddingTop: 7, paddingBottom: 7, width: 230, fontSize: 13 }}
                />
              </div>
            </div>

            {filteredHosts.length === 0 ? (
              <div className="empty-state" style={{ padding: 54 }}>
                <Monitor size={38} />
                <h3>{search ? 'No hosts match your search' : 'No endpoint telemetry observed'}</h3>
                <p style={{ marginBottom: 16 }}>Hosts appear only after real Wazuh/Sysmon events are ingested.</p>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 140 }}>Endpoint</th>
                    <th style={{ width: 120 }}>Status</th>
                    <th style={{ width: 120 }}>Host ID</th>
                    <th style={{ width: 140 }}>Registered</th>
                    <th style={{ width: 140 }}>Last Seen</th>
                    <th style={{ width: 40 }}></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHosts.map(host => {
                    const live = isLive(host.last_seen)
                    return (
                      <tr key={host.host_id} className="interactive-row">
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{
                              width: 32,
                              height: 32,
                              background: 'var(--bg-3)',
                              border: '1px solid var(--border)',
                              borderRadius: 4,
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontSize: 12,
                              fontWeight: 700,
                              color: 'var(--text-2)'
                            }}>
                              {(host.pc_name || host.host_id).slice(0, 2).toUpperCase()}
                            </div>
                            <div>
                              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>
                                {host.pc_name || host.host_id}
                              </div>
                              <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>
                                Windows endpoint
                              </div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <div style={{
                              width: 8,
                              height: 8,
                              borderRadius: '50%',
                              background: live ? '#22C55E' : 'var(--text-3)',
                              animation: live ? 'pulse 2s infinite' : 'none',
                            }} />
                            <span style={{ fontSize: 12, color: live ? '#22C55E' : 'var(--text-3)', fontWeight: 600 }}>
                              {live ? 'Live' : 'Offline'}
                            </span>
                          </div>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-2)' }}>
                            {host.host_id}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: 12, color: 'var(--text-3)' }}>
                            {relativeTime(host.registered_at)}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-3)', fontSize: 12 }}>
                            <Wifi size={11} />
                            {relativeTime(host.last_seen)}
                          </div>
                        </td>
                        <td>
                          <ChevronRight size={14} color="var(--text-3)" />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            <div className="card" style={{ padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Telemetry mix</div>
                  <div style={{ marginTop: 4, fontSize: 12, color: 'var(--text-3)' }}>Ingested event families from the current pipeline.</div>
                </div>
                <Database size={15} color="var(--accent)" />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10, marginTop: 14 }}>
                <MetricChip label="Process" value={processCount} />
                <MetricChip label="Network" value={networkCount} />
                <MetricChip label="File" value={fileCount} />
                <MetricChip label="Registry" value={registryCount} />
                <MetricChip label="AMSI" value={amsiCount} />
                <MetricChip label="Alerts" value={totalAlerts} />
              </div>


            </div>

            <div className="card" style={{ padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 10 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Data quality</div>
                  <div style={{ marginTop: 4, fontSize: 12, color: 'var(--text-3)' }}>Fields that directly affect alert fidelity.</div>
                </div>
                <ShieldCheck size={15} color="var(--accent)" />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <QualityRow label="Last alert" value={health?.last_alert ? relativeTime((health.last_alert as Record<string, unknown>).fired_at as string | null | undefined) : 'None'} />
                <QualityRow label="Last event" value={health?.last_event ? relativeTime((health.last_event as Record<string, unknown>).wazuh_ts as string | null | undefined) : 'None'} />
                <QualityRow label="Source" value={health?.last_event ? labelFromRecord(health.last_event) : 'Unknown'} />
                <QualityRow label="Missing fields" value={health?.missing_fields ? Object.entries(health.missing_fields).filter(([, v]) => (v ?? 0) > 0).length.toString() : '0'} />
              </div>
              
              <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-3)', marginBottom: 8, textTransform: 'uppercase' }}>System Stats</div>
                <div style={{ display: 'flex', gap: 12 }}>
                  <div style={{ flex: 1 }}><QualityRow label="CPU" value={health?.system_stats ? `${health.system_stats.cpu.toFixed(1)}%` : 'N/A'} /></div>
                  <div style={{ flex: 1 }}><QualityRow label="RAM" value={health?.system_stats ? `${health.system_stats.ram.toFixed(1)}%` : 'N/A'} /></div>
                  <div style={{ flex: 1 }}><QualityRow label="Disk" value={health?.system_stats ? `${health.system_stats.disk.toFixed(1)}%` : 'N/A'} /></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{
            padding: '14px 18px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={15} color="var(--crit)" />
                <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>Recent alerts</span>
              </div>
              <p style={{ marginTop: 4, fontSize: 12, color: 'var(--text-3)' }}>The most recent detections from the live alert queue.</p>
            </div>
            <span style={{
              background: 'var(--bg-3)',
              border: '1px solid var(--border)',
              borderRadius: 99,
              padding: '2px 9px',
              fontSize: 11,
              color: 'var(--text-3)',
            }}>
              {alerts.length}
            </span>
          </div>

          {alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: 48 }}>
              <AlertTriangle size={38} />
              <h3>No alerts detected</h3>
              <p>The system is waiting for real telemetry to trip a rule.</p>
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Technique</th>
                  <th>Host</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(alert => {
                  const sevClass = severityClass(alert.severity_score)
                  return (
                  <tr key={alert.alert_id} style={{
                    borderLeft: `3px solid var(--${sevClass})`
                  }}>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text)', fontSize: 13 }}>{alert.rule_name}</div>
                      <div style={{ marginTop: 2, fontSize: 11, color: 'var(--text-3)', fontFamily: "'Courier New', monospace" }}>
                        {sourceLabel(alert)}
                      </div>
                    </td>
                    <td>
                      <span className={`badge badge-${severityClass(alert.severity_score)}`}>
                        {severityLabel(alert.severity_score)}
                      </span>
                    </td>
                    <td>
                      <span className="tag">{alert.technique_id ?? '-'}</span>
                    </td>
                    <td>
                      <span
                        onClick={() => {
                          if (onHostClick && alert.host_id) {
                            onHostClick(alert.host_id)
                          }
                        }}
                        style={{ 
                          color: 'var(--accent)', 
                          cursor: 'pointer',
                          textDecoration: 'underline'
                        }}
                      >
                        {alert.host_id ?? 'Unknown'}
                      </span>
                    </td>
                    <td>
                      <span style={{ color: 'var(--text-3)' }}>{relativeTime(alert.created_at)}</span>
                    </td>
                  </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  tone,
  detail,
  bg = 'var(--bg-3)',
  borderColor = 'var(--border)',
}: {
  icon: typeof Activity
  label: string
  value: string | number
  tone: string
  detail: string
  bg?: string
  borderColor?: string
}) {
  return (
    <div style={{ padding: 16, minHeight: 98, background: bg, border: `1px solid ${borderColor}`, borderRadius: 12 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.9px', textTransform: 'uppercase', color: 'var(--text-3)' }}>
            {label}
          </div>
          <div style={{ marginTop: 8, fontSize: 28, fontWeight: 900, color: tone, lineHeight: 1 }}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </div>
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-3)' }}>{detail}</div>
        </div>
        <div style={{
          width: 38,
          height: 38,
          borderRadius: 8,
          background: `${tone}18`,
          border: `1px solid ${tone}22`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Icon size={18} color={tone} />
        </div>
      </div>
    </div>
  )
}

function MetricChip({ label, value }: { label: string; value: number }) {
  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 8,
      background: 'var(--bg-3)',
      padding: '10px 12px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: 10,
    }}>
      <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{label}</span>
      <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>{value.toLocaleString()}</span>
    </div>
  )
}

function QualityRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: 12,
      padding: '8px 10px',
      borderRadius: 8,
      background: 'var(--bg-3)',
      border: '1px solid var(--border)',
    }}>
      <span style={{ fontSize: 12, color: 'var(--text-3)' }}>{label}</span>
      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>{value}</span>
    </div>
  )
}
