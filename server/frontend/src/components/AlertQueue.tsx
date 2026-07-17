import { useEffect, useState, useCallback, useRef } from 'react'
import { Shield, AlertTriangle, CheckCircle2, RotateCcw, Tag } from 'lucide-react'
import { api, type Alert } from '../api/client'

interface Props {
  selectedId: string | null
  onSelect: (alert: Alert) => void
}

function sevClass(score: number): string {
  if (score >= 9) return 'crit'
  if (score >= 7) return 'high'
  if (score >= 5) return 'med'
  return 'low'
}

function sevLabel(score: number): string {
  if (score >= 9) return 'Critical'
  if (score >= 7) return 'High'
  if (score >= 5) return 'Medium'
  return 'Low'
}

function relTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`
  return `${Math.floor(mins / 1440)}d ago`
}

function alertImage(alert: Alert): string | null {
  const img = alert.process_chain?.self?.image
  if (typeof img !== 'string' || !img) return null
  return img.split(/[/\\]/).pop() ?? null
}

function alertCmdLine(alert: Alert): string | null {
  const cmd = alert.process_chain?.self?.command_line
  if (typeof cmd !== 'string' || !cmd) return null
  return cmd.length > 60 ? `${cmd.slice(0, 60)}...` : cmd
}

function alertMeta(alert: Alert): string {
  return [
    alert.host_id,
    alert.source_layer,
    alert.event_id ? `EID ${alert.event_id}` : null,
  ].filter(Boolean).join(' | ')
}

export default function AlertQueue({ selectedId, onSelect }: Props) {
  const [tab, setTab] = useState<'open' | 'investigated'>('open')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [limit, setLimit] = useState<number>(100)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [actionId, setActionId] = useState<string | null>(null)
  const [investigatedIds, setInvestigatedIds] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem('ishax_investigated_alerts')
      return stored ? new Set(JSON.parse(stored)) : new Set()
    } catch {
      return new Set()
    }
  })

  // Tagging State
  const [tagsByAlert, setTagsByAlert] = useState<Record<string, string[]>>(() => {
    try { return JSON.parse(localStorage.getItem('ishax_tags') || '{}') } catch { return {} }
  })
  const [taggingId, setTaggingId] = useState<string | null>(null)
  const [tagInput, setTagInput] = useState('')
  const tagInputRef = useRef<HTMLInputElement>(null)
  const TAG_REC = ['#falsepositive', '#important', '#ignore']

  const load = useCallback(async () => {
    try {
      // Fetch ALL alerts without status filter
      const data = await api.getAlerts({ limit })
      setAlerts(data.alerts)
    } catch {
      // Backend may still be starting.
    } finally {
      setLoading(false)
    }
  }, [limit])

  useEffect(() => { setLoading(true); load() }, [load])
  useEffect(() => {
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [load])

  const handleInvestigate = (e: React.MouseEvent, alert: Alert) => {
    e.stopPropagation()
    setInvestigatedIds(prev => {
      const next = new Set(prev)
      if (tab === 'open') {
        next.add(alert.alert_id)
      } else {
        next.delete(alert.alert_id)
      }
      localStorage.setItem('ishax_investigated_alerts', JSON.stringify(Array.from(next)))
      return next
    })
  }

  const handleAddTag = (alertId: string, tag: string) => {
    if (!tag.trim()) return
    const cleanTag = tag.trim().replace(/\s+/g, '')
    setTagsByAlert(prev => {
      const next = { ...prev }
      if (!next[alertId]) next[alertId] = []
      if (!next[alertId].includes(cleanTag)) next[alertId] = [...next[alertId], cleanTag]
      localStorage.setItem('ishax_tags', JSON.stringify(next))
      return next
    })
    setTaggingId(null)
    setTagInput('')
  }

  const handleRemoveTag = (alertId: string, tag: string) => {
    setTagsByAlert(prev => {
      const next = { ...prev }
      if (next[alertId]) {
        next[alertId] = next[alertId].filter(t => t !== tag)
        if (next[alertId].length === 0) delete next[alertId]
      }
      localStorage.setItem('ishax_tags', JSON.stringify(next))
      return next
    })
  }

  // Filter alerts based on the selected tab
  const visibleAlerts = alerts.filter(a => {
    const isInvestigated = investigatedIds.has(a.alert_id)
    return tab === 'open' ? !isInvestigated : isInvestigated
  })
  
  // Update total based on the filtered list
  const displayTotal = visibleAlerts.length

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', overflow: 'hidden' }}>
      {/* ── Tabs Header ── */}
      <div style={{ flexShrink: 0, borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex' }}>
          {(['open', 'investigated'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                flex: 1,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                padding: '10px 0',
                background: 'transparent',
                border: 'none',
                borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
                cursor: 'pointer',
                fontSize: 12, fontWeight: tab === t ? 700 : 500,
                color: tab === t ? 'var(--text)' : 'var(--text-3)',
                transition: 'all 0.15s',
              }}
            >
              {t === 'open'
                ? <AlertTriangle size={13} color={tab === 'open' ? 'var(--crit)' : 'var(--text-3)'} />
                : <CheckCircle2 size={13} color={tab === 'investigated' ? '#22C55E' : 'var(--text-3)'} />
              }
              {t === 'open' ? 'Live Alerts' : 'Investigated'}
              <span style={{
                background: t === 'open' && displayTotal > 0 ? 'var(--crit-bg)' : 'var(--bg-3)',
                border: `1px solid ${t === 'open' && displayTotal > 0 ? 'rgba(204,0,0,0.2)' : 'var(--border)'}`,
                color: t === 'open' && displayTotal > 0 ? 'var(--crit)' : 'var(--text-3)',
                borderRadius: 99, padding: '0px 6px', fontSize: 10, fontWeight: 600,
              }}>{tab === t ? displayTotal : ''}</span>
            </button>
          ))}
        </div>
      </div>


      <div className="scroll-y" style={{ flex: 1 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 32 }}>
            <div className="spinner" />
          </div>
        ) : visibleAlerts.length === 0 ? (
          <div className="empty-state">
            <Shield size={36} />
            <h3>No alerts detected</h3>
            <p>{tab === 'open' ? 'The system is monitoring real telemetry. Alerts will appear here when a rule fires.' : 'No alerts have been marked as investigated.'}</p>
          </div>
        ) : (
          visibleAlerts.map(alert => {
            const sev = sevClass(alert.severity_score)
            const selected = alert.alert_id === selectedId
            const image = alertImage(alert)
            const cmd = alertCmdLine(alert)
            return (
              <div
                key={alert.alert_id}
                id={`alert-${alert.alert_id}`}
                onClick={() => onSelect(alert)}
                style={{
                  padding: '10px 14px',
                  borderBottom: '1px solid var(--border)',
                  cursor: 'pointer',
                  background: selected ? 'var(--bg-3)' : 'transparent',
                  borderLeft: `3px solid var(--${sev})`,
                  transition: 'all 0.12s',
                  position: 'relative',
                  opacity: alert.suppressed ? 0.55 : 1,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                  <div style={{ paddingTop: 4, flexShrink: 0 }}>
                    <div className={`sev-dot sev-dot-${sev}`} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginBottom: 4 }}>
                      {alert.rule_name}
                    </p>
                    {image && (
                      <p style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 3, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: "'Courier New', monospace" }}>
                        {image}
                      </p>
                    )}
                    {cmd && (
                      <p style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: "'Courier New', monospace" }}>
                        {cmd}
                      </p>
                    )}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }}>
                      <span className={`badge badge-${sev}`}>{sevLabel(alert.severity_score)}</span>
                      <span 
                        onClick={(e) => {
                          e.stopPropagation()
                          navigator.clipboard.writeText(alert.alert_id)
                          setCopiedId(alert.alert_id)
                          setTimeout(() => setCopiedId(null), 2000)
                        }}
                        title={`Click to copy Alert ID: ${alert.alert_id}`} 
                        style={{ 
                          fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 4, 
                          background: copiedId === alert.alert_id ? 'var(--info)' : 'var(--bg-3)', 
                          color: copiedId === alert.alert_id ? '#fff' : 'var(--text-2)', 
                          border: '1px solid var(--border)', fontFamily: 'monospace', cursor: 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        {copiedId === alert.alert_id ? 'Copied ✓' : `Alert ID ${alert.alert_id}`}
                      </span>
                      {alert.technique_id && <span className="tag">{alert.technique_id}</span>}
                      {alert.suppressed && (
                        <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3, background: 'var(--bg-3)', color: 'var(--text-3)', border: '1px solid var(--border)', textTransform: 'uppercase' }}>
                          Suppressed
                        </span>
                      )}
                      {(tagsByAlert[alert.alert_id] || []).map(tag => (
                        <span key={tag} style={{ 
                          fontSize: 10, fontWeight: 600, padding: '1px 6px', borderRadius: 4, 
                          background: 'rgba(139, 92, 246, 0.1)', color: '#a78bfa', 
                          border: '1px solid rgba(139, 92, 246, 0.3)', display: 'inline-flex', alignItems: 'center', gap: 4
                        }}>
                          {tag}
                          <span onClick={(e) => { e.stopPropagation(); handleRemoveTag(alert.alert_id, tag) }} style={{ cursor: 'pointer', opacity: 0.6 }}>&times;</span>
                        </span>
                      ))}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 5, gap: 8 }}>
                      <span style={{ fontSize: 10, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {alertMeta(alert)}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--text-3)', flexShrink: 0 }}>
                        {relTime(alert.created_at)}
                      </span>
                    </div>
                    {/* Investigate / Reopen button & Tagging */}
                    <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <button
                        onClick={(e) => handleInvestigate(e, alert)}
                        disabled={actionId === alert.alert_id}
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 5,
                          padding: '3px 9px',
                          fontSize: 10, fontWeight: 700,
                          borderRadius: 5, cursor: 'pointer',
                          transition: 'all 0.15s',
                          opacity: actionId === alert.alert_id ? 0.5 : 1,
                          background: tab === 'open' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.08)',
                          border: tab === 'open' ? '1px solid rgba(34,197,94,0.35)' : '1px solid rgba(239,68,68,0.25)',
                          color: tab === 'open' ? '#22C55E' : '#ef4444',
                        }}
                      >
                        {tab === 'open'
                          ? <><CheckCircle2 size={11} /> Mark Investigated</>
                          : <><RotateCcw size={11} /> Reopen</>
                        }
                      </button>
                      
                      {taggingId === alert.alert_id ? (
                        <div style={{ position: 'relative' }} onClick={e => e.stopPropagation()}>
                          <input 
                            ref={tagInputRef}
                            value={tagInput}
                            onChange={e => setTagInput(e.target.value)}
                            onKeyDown={e => {
                              if (e.key === 'Enter') handleAddTag(alert.alert_id, tagInput)
                              if (e.key === 'Escape') setTaggingId(null)
                            }}
                            onBlur={() => setTimeout(() => setTaggingId(null), 200)}
                            placeholder="#tag"
                            autoFocus
                            style={{
                              background: 'var(--bg-1)', color: 'var(--text)', border: '1px solid var(--border)',
                              borderRadius: 4, padding: '2px 6px', fontSize: 10, width: 100, outline: 'none'
                            }}
                          />
                          {tagInput && TAG_REC.filter(t => t.includes(tagInput.toLowerCase())).length > 0 && (
                            <div style={{
                              position: 'absolute', bottom: '100%', left: 0, marginBottom: 4,
                              background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 4,
                              padding: 4, zIndex: 10, display: 'flex', flexDirection: 'column', gap: 2, minWidth: 120,
                              boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
                            }}>
                              {TAG_REC.filter(t => t.includes(tagInput.toLowerCase())).map(t => (
                                <div 
                                  key={t} 
                                  onMouseDown={(e) => { e.preventDefault(); handleAddTag(alert.alert_id, t) }}
                                  style={{ padding: '4px 6px', fontSize: 10, cursor: 'pointer', borderRadius: 3, color: 'var(--text-2)' }}
                                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-3)'}
                                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                                >
                                  {t}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (
                        <button
                          onClick={(e) => { e.stopPropagation(); setTaggingId(alert.alert_id); setTagInput('#') }}
                          style={{
                            display: 'inline-flex', alignItems: 'center', gap: 4,
                            padding: '3px 8px', fontSize: 10, fontWeight: 600,
                            background: 'transparent', border: '1px dashed var(--border)',
                            color: 'var(--text-3)', borderRadius: 5, cursor: 'pointer'
                          }}
                        >
                          <Tag size={10} /> Add Tag
                        </button>
                      )}

                      {tab === 'investigated' && (
                        <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--text-3)' }}>
                          Investigated
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>

      <div style={{
        padding: '8px 14px',
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-2)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        flexShrink: 0
      }}>
        <span style={{ fontSize: 10, color: 'var(--text-3)' }}>Show:</span>
        {[10, 20, 50, 100].map(val => (
          <button
            key={val}
            onClick={() => setLimit(val)}
            style={{
              background: limit === val ? 'var(--bg-3)' : 'transparent',
              color: limit === val ? 'var(--text)' : 'var(--text-3)',
              border: `1px solid ${limit === val ? 'var(--border)' : 'transparent'}`,
              borderRadius: 4,
              padding: '2px 6px',
              fontSize: 10,
              fontWeight: limit === val ? 600 : 500,
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            {val}
          </button>
        ))}
        <input
          type="number"
          value={limit}
          onChange={e => setLimit(Math.max(1, parseInt(e.target.value) || 100))}
          style={{
            width: 44,
            background: 'transparent',
            color: 'var(--text)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            padding: '1px 4px',
            fontSize: 10,
            textAlign: 'center',
            outline: 'none'
          }}
          title="Custom Limit"
        />
      </div>
    </div>
  )
}
