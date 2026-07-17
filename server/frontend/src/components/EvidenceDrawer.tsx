import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, AlertTriangle, Database, FileText, GitBranch, HardDrive, Network, Shield, Terminal, Sparkles } from 'lucide-react'
import { api, type Alert, type AlertEvidence, type EvidenceArtifact } from '../api/client'
import Button from './Button'

interface Props {
  alert: Alert | null
}

function basename(path?: string | null): string {
  if (!path) return 'Unknown'
  return path.split(/[/\\]/).pop() || path
}

function EvidenceSection({ title, icon, count, children, onCopy }: {
  title: string
  icon: ReactNode
  count?: number
  children: ReactNode
  onCopy?: () => void
}) {
  return (
    <section style={{ borderBottom: '1px solid var(--border)', padding: '14px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        {icon}
        <h3 style={{ fontSize: 12, fontWeight: 800, color: 'var(--text)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{title}</h3>
        {typeof count === 'number' && (
          <span className="tag" style={{ marginLeft: 'auto' }}>{count}</span>
        )}
        {onCopy && (
          <CopyButton 
            onCopy={onCopy}
            style={{ marginLeft: typeof count === 'number' ? 8 : 'auto' }}
          />
        )}
      </div>
      {children}
    </section>
  )
}

function EmptyLine({ text }: { text: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 12px', background: 'var(--bg-2)', borderRadius: 6, border: '1px dashed var(--border)' }}>
      <span style={{ color: 'var(--text-3)' }}>✓</span>
      <p style={{ fontSize: 12, color: 'var(--text-3)', lineHeight: 1.5, margin: 0 }}>{text}</p>
    </div>
  )
}

function MissingLine({ text }: { text: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 12px', background: 'var(--high-bg)', borderRadius: 6, border: '1px solid var(--high)' }}>
      <AlertTriangle size={14} color="var(--high)" />
      <p style={{ fontSize: 12, color: 'var(--high)', lineHeight: 1.5, margin: 0, fontWeight: 500 }}>{text}</p>
    </div>
  )
}

function ArtifactList({ items, kind, missing }: { items: EvidenceArtifact[]; kind: 'network' | 'file' | 'registry'; missing?: boolean }) {
  if (items.length === 0) {
    if (missing) return <MissingLine text={`⚠ Linking issue detected — ${kind} activity exists in raw logs but failed to link.`} />
    return <EmptyLine text={`No ${kind} activity for this process.`} />
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {items.slice(0, 80).map((item, i) => (
        <div key={`${item.process_guid}-${item.target_label}-${i}`} style={{
          background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6,
          padding: 9, minWidth: 0,
        }}>
          <div style={{ fontSize: 12, color: 'var(--text)', fontWeight: 650, wordBreak: 'break-all' }}>
            {kind === 'network'
              ? `${item.destination_ip || item.target_label || 'Unknown'}${item.destination_port ? `:${item.destination_port}` : ''}`
              : item.target_filename || item.target_object || item.target_label || 'Unknown'}
          </div>
          <div style={{ marginTop: 4, fontSize: 10, color: 'var(--text-3)', wordBreak: 'break-all' }}>
            {basename(item.process_image)} | {item.timestamp || 'no timestamp'}
          </div>
        </div>
      ))}
      {items.length > 80 && <EmptyLine text={`Showing first 80 of ${items.length} artifacts.`} />}
    </div>
  )
}

function isTimestamp(val: unknown): boolean {
  if (typeof val === 'string' && val.length > 18) {
    if (val.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)) return true
  }
  return false
}

function ExpandableString({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false)
  const isLong = text.length > 100
  return (
    <span style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>
      "{isLong && !expanded ? text.substring(0, 100) + '...' : text}"
      {isLong && (
        <span 
          onClick={() => setExpanded(!expanded)} 
          style={{ cursor: 'pointer', marginLeft: 6, color: 'var(--text-3)', fontSize: 9, textDecoration: 'underline' }}>
          {expanded ? 'collapse' : 'expand'}
        </span>
      )}
    </span>
  )
}

function StructuredValue({ val }: { val: unknown }) {
  if (val === null) return <span style={{ color: 'var(--text-3)' }}>null</span>
  if (typeof val === 'boolean') return <span style={{ color: 'var(--crit)' }}>{val ? 'true' : 'false'}</span>
  if (typeof val === 'number') return <span style={{ color: 'var(--high)' }}>{val}</span>
  if (typeof val === 'string') {
    if (isTimestamp(val)) return <span style={{ color: 'var(--info)' }}>"{val}"</span>
    return <ExpandableString text={val} />
  }
  return <span>{String(val)}</span>
}

function StructuredRow({ k, v, isArray }: { k: string, v: unknown, isArray: boolean }) {
  const isObj = typeof v === 'object' && v !== null
  const isEmpty = isObj && Object.keys(v).length === 0
  const [open, setOpen] = useState(false)
  
  return (
    <div style={{ marginTop: 2, fontSize: 11, fontFamily: 'monospace' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start' }}>
        {isObj && !isEmpty ? (
          <span onClick={() => setOpen(!open)} style={{ cursor: 'pointer', marginRight: 4, color: 'var(--text-3)', width: 12, textAlign: 'center', userSelect: 'none' }}>
            {open ? '▼' : '▶'}
          </span>
        ) : (
          <span style={{ width: 12, marginRight: 4 }}></span>
        )}
        <span style={{ color: 'var(--text)', fontWeight: 650, marginRight: 8, whiteSpace: 'nowrap' }}>
          {isArray ? `[${k}]` : k}:
        </span>
        {!isObj || isEmpty ? (
          <StructuredValue val={v} />
        ) : (
          <span style={{ color: 'var(--text-3)', fontSize: 10, alignSelf: 'center', cursor: 'pointer', userSelect: 'none' }} onClick={() => setOpen(!open)}>
            {Array.isArray(v) ? `Array(${v.length})` : 'Object'} {open ? '' : '...'}
          </span>
        )}
      </div>
      {isObj && !isEmpty && open && (
        <div style={{ paddingLeft: 16 }}>
          <StructuredNode value={v} />
        </div>
      )}
    </div>
  )
}

function StructuredNode({ value }: { value: unknown }) {
  if (typeof value !== 'object' || value === null) {
    return <StructuredValue val={value} />
  }
  const isArray = Array.isArray(value)
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {Object.entries(value).map(([k, v]) => (
        <StructuredRow key={k} k={k} v={v} isArray={isArray} />
      ))}
    </div>
  )
}

function CopyButton({ textToCopy, onCopy, style }: { textToCopy?: string, onCopy?: () => void, style?: React.CSSProperties }) {
  const [copied, setCopied] = useState(false)
  return (
    <button 
      onClick={() => {
        if (textToCopy) navigator.clipboard.writeText(textToCopy)
        if (onCopy) onCopy()
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      }}
      style={{ 
        background: copied ? 'var(--info-bg, rgba(59, 130, 246, 0.15))' : 'none', 
        border: `1px solid ${copied ? 'var(--info, #3B82F6)' : 'var(--border)'}`, 
        borderRadius: 4, 
        padding: '2px 8px', 
        color: copied ? 'var(--info, #3B82F6)' : 'var(--text-3)', 
        fontSize: 9, 
        cursor: 'pointer', 
        textTransform: 'uppercase', 
        transition: 'all 0.2s ease',
        ...style
      }}
    >
      {copied ? 'Copied ✓' : 'Copy JSON'}
    </button>
  )
}

function JsonBlock({ value }: { value: unknown }) {
  const [showRaw, setShowRaw] = useState(false)

  return (
    <div style={{
      background: '#050505',
      border: '1px solid var(--border)',
      borderRadius: 6,
      padding: 10,
    }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginBottom: 8 }}>
        <CopyButton textToCopy={JSON.stringify(value, null, 2)} />
        <Button 
          variant="outline"
          size="sm"
          onClick={() => setShowRaw(!showRaw)} 
          style={{ fontSize: 9, padding: '2px 8px', textTransform: 'uppercase' }}
        >
          {showRaw ? 'View Structured' : 'View Raw JSON'}
        </Button>
      </div>
      
      <div style={{ maxHeight: 260, overflow: 'auto' }}>
        {showRaw ? (
          <pre style={{
            margin: 0,
            color: 'var(--text-2)',
            fontSize: 10,
            lineHeight: 1.45,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}>
            {JSON.stringify(value, null, 2)}
          </pre>
        ) : (
          <StructuredNode value={value} />
        )}
      </div>
    </div>
  )
}

export default function EvidenceDrawer({ alert }: Props) {
  const [evidence, setEvidence] = useState<AlertEvidence | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!alert) {
      setEvidence(null)
      return
    }
    setLoading(true)
    api.getAlertEvidence(alert.alert_id)
      .then(setEvidence)
      .catch(() => setEvidence(null))
      .finally(() => setLoading(false))
  }, [alert])

  if (!alert) {
    return (
      <aside style={{ flex: 1, display: 'flex', background: 'var(--bg)' }}>
        <div className="empty-state">
          <Database size={34} />
          <h3>Evidence Drawer</h3>
          <p>Select an alert to list its source event and linked process artifacts.</p>
        </div>
      </aside>
    )
  }

  return (
    <aside style={{
      flex: 1,
      background: 'var(--bg)',
      display: 'flex',
      flexDirection: 'column',
      minWidth: 0,
    }}>
      <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={15} color="var(--accent)" />
            <h2 style={{ fontSize: 14, fontWeight: 850, color: 'var(--text)' }}>Evidence Drawer</h2>
          </div>
          <Button 
            variant="outline" 
            size="sm"
            onClick={() => window.dispatchEvent(new CustomEvent('open-ai', { detail: { alert_id: alert.alert_id } }))}
            icon={<Sparkles size={12} />}
            style={{ fontSize: 11, padding: '4px 10px', color: 'var(--accent)', borderColor: 'var(--accent-border)', background: 'var(--accent-bg)' }}
          >
            Analyze with AI
          </Button>
        </div>
        <p style={{ marginTop: 5, fontSize: 11, color: 'var(--text-3)', lineHeight: 1.45 }}>
          Direct evidence from SQLite. No enrichment or inferred artifacts.
        </p>
      </div>

      {loading ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="spinner" />
        </div>
      ) : !evidence ? (
        <div className="empty-state">
          <AlertTriangle size={34} />
          <h3>Evidence unavailable</h3>
          <p>The backend could not load this alert evidence.</p>
        </div>
      ) : (
        <div className="scroll-y" style={{ flex: 1 }}>
          <EvidenceSection 
            title="Alert" 
            icon={<AlertTriangle size={14} color="var(--crit)" />}
            onCopy={() => navigator.clipboard.writeText(JSON.stringify(evidence.alert, null, 2))}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 700 }}>{evidence.alert.rule_name}</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {evidence.alert.technique_id && <span className="tag">{evidence.alert.technique_id}</span>}
                {evidence.alert.event_id && <span className="tag">EID {evidence.alert.event_id}</span>}
                {evidence.alert.source_layer && <span className="tag">{evidence.alert.source_layer}</span>}
                {evidence.alert.severity_score !== undefined && <span className="tag" style={{ color: 'var(--crit)', borderColor: 'var(--crit)' }}>Sev: {evidence.alert.severity_score}</span>}
                {evidence.alert.host_id && <span className="tag" style={{ color: 'var(--info)', borderColor: 'var(--info)' }}>Host: {evidence.alert.host_id}</span>}
                {evidence.alert.created_at && <span className="tag">Time: {evidence.alert.created_at}</span>}
              </div>
              {evidence.alert.summary && <p style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>{evidence.alert.summary}</p>}
            </div>
          </EvidenceSection>

          <EvidenceSection 
            title="Coverage" 
            icon={<Database size={14} color="var(--info)" />}
            onCopy={() => navigator.clipboard.writeText(JSON.stringify({ completeness: evidence.completeness, counts: evidence.counts }, null, 2))}
          >
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
              <span className="tag">{evidence.completeness.level}</span>
              <span className="tag">{evidence.completeness.host_scoped ? 'host-scoped' : 'host unknown'}</span>
              <span className="tag">{evidence.completeness.has_process_guid ? 'process GUID present' : 'no process GUID'}</span>
              <span className="tag">{evidence.completeness.edge_host_scope_complete ? 'artifact host scope complete' : 'legacy artifact scope'}</span>
            </div>
            {evidence.completeness.notes.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 10 }}>
                {evidence.completeness.notes.map(note => (
                  <span key={note} style={{ fontSize: 11, color: 'var(--text-3)', lineHeight: 1.4 }}>{note}</span>
                ))}
              </div>
            )}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0,1fr))', gap: 6 }}>
              {[
                ['Proc', evidence.counts.processes],
                ['Net', evidence.counts.network],
                ['File', evidence.counts.files],
                ['Reg', evidence.counts.registry],
                ['AMSI', evidence.counts.amsi],
              ].map(([label, value]) => (
                <div key={label} style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 7, textAlign: 'center' }}>
                  <div style={{ fontSize: 14, color: 'var(--text)', fontWeight: 800 }}>{value}</div>
                  <div style={{ fontSize: 9, color: 'var(--text-3)', textTransform: 'uppercase' }}>{label}</div>
                </div>
              ))}
            </div>
          </EvidenceSection>

          <EvidenceSection 
            title="Process Commands" 
            icon={<Terminal size={14} color="var(--high)" />} 
            count={evidence.artifacts.process.length}
            onCopy={() => navigator.clipboard.writeText(JSON.stringify(evidence.artifacts.process, null, 2))}
          >
            {evidence.artifacts.process.length === 0 ? (
              <EmptyLine text="No process GUID was available for this alert, so command-chain evidence cannot be trusted." />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {evidence.artifacts.process.map(proc => (
                  <div key={proc.process_guid} style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 9 }}>
                    <div style={{ fontSize: 12, color: 'var(--text)', fontWeight: 700 }}>{basename(proc.image)}</div>
                    <div style={{ marginTop: 3, fontSize: 10, color: 'var(--text-3)' }}>PID {proc.pid ?? 'unknown'} | {proc.user_name || 'unknown'} | {proc.timestamp || 'no timestamp'}</div>
                    {proc.command_line && (
                      <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-2)', fontFamily: "'Courier New', monospace", wordBreak: 'break-all' }}>
                        {proc.command_line}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </EvidenceSection>

          <EvidenceSection 
            title="Network" 
            icon={<Network size={14} color="var(--info)" />} 
            count={evidence.artifacts.network.length}
            onCopy={() => navigator.clipboard.writeText(JSON.stringify(evidence.artifacts.network, null, 2))}
          >
            <ArtifactList items={evidence.artifacts.network} kind="network" missing={evidence.completeness.missing_network} />
          </EvidenceSection>

          <EvidenceSection 
            title="Files" 
            icon={<FileText size={14} color="var(--high)" />} 
            count={evidence.artifacts.file.length}
            onCopy={() => navigator.clipboard.writeText(JSON.stringify(evidence.artifacts.file, null, 2))}
          >
            <ArtifactList items={evidence.artifacts.file} kind="file" missing={evidence.completeness.missing_file} />
          </EvidenceSection>

          <EvidenceSection 
            title="Registry" 
            icon={<HardDrive size={14} color="var(--med)" />} 
            count={evidence.artifacts.registry.length}
            onCopy={() => navigator.clipboard.writeText(JSON.stringify(evidence.artifacts.registry, null, 2))}
          >
            <ArtifactList items={evidence.artifacts.registry} kind="registry" missing={evidence.completeness.missing_registry} />
          </EvidenceSection>

          <EvidenceSection title="AMSI" icon={<Activity size={14} color="var(--crit)" />} count={evidence.amsi.length}>
            {evidence.amsi.length === 0 ? (
              evidence.completeness.missing_amsi 
                ? <MissingLine text="⚠ Linking issue detected — AMSI events exist for this GUID but failed to map." />
                : <EmptyLine text="No AMSI activity for this process." />
            ) : (
              <JsonBlock value={evidence.amsi} />
            )}
          </EvidenceSection>

          <EvidenceSection title="Source Event" icon={<GitBranch size={14} color="var(--text-2)" />}>
            <JsonBlock value={evidence.source_event} />
          </EvidenceSection>
        </div>
      )}
    </aside>
  )
}
