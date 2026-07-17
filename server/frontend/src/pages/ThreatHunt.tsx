import { useState, useCallback, useEffect } from 'react'
import AlertQueue from '../components/AlertQueue'
import ProcessTree from '../components/ProcessTree'
import BlastRadius from '../components/BlastRadius'
import EvidenceDrawer from '../components/EvidenceDrawer'
import IncidentChains from '../components/IncidentChains'
import Button from '../components/Button'
import { api, type Alert } from '../api/client'
import { GitBranch, Radiation, Database, Loader, Activity } from 'lucide-react'

export default function ThreatHunt({ initialHost }: { initialHost?: string | null }) {
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [centerView, setCenterView] = useState<'tree' | 'blast' | 'evidence' | 'chains'>(initialHost ? 'chains' : 'tree')
  const [fetching, setFetching] = useState(false)

  useEffect(() => {
    if (initialHost) {
      setCenterView('chains')
      setSelectedAlert(null)
    }
  }, [initialHost])

  const handleSelectAlert = useCallback(async (alert: Alert) => {
    setFetching(true)
    try {
      const fresh = await api.getAlert(alert.alert_id)
      setSelectedAlert(fresh)
    } catch {
      setSelectedAlert(alert)
    } finally {
      setFetching(false)
    }
  }, [])

  const metadata = selectedAlert
    ? [selectedAlert.host_id, selectedAlert.source_layer, selectedAlert.event_id ? `EID ${selectedAlert.event_id}` : null]
        .filter(Boolean)
        .join(' | ')
    : ''

  return (
    <div style={{
      flex: 1, display: 'flex', overflow: 'hidden',
      padding: '16px', gap: '16px',
    }}>
      <div style={{
        width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column',
        background: 'var(--bg-2)', borderRadius: '12px', border: '1px solid var(--border)',
        overflow: 'hidden', boxShadow: 'var(--shadow)',
      }}>
        <AlertQueue selectedId={selectedAlert?.alert_id ?? null} onSelect={handleSelectAlert} />
      </div>

      <div style={{
        flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column',
        background: 'var(--bg-2)', borderRadius: '12px', border: '1px solid var(--border)',
        position: 'relative', boxShadow: 'var(--shadow)',
      }}>
        {fetching && (
          <div style={{
            position: 'absolute', inset: 0, zIndex: 20,
            background: 'rgba(var(--bg-rgb, 15,15,20),0.7)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            gap: 10, color: 'var(--text-3)', fontSize: 13,
          }}>
            <Loader size={16} style={{ animation: 'spin 1s linear infinite' }} />
            Loading alert details...
          </div>
        )}

        {selectedAlert || centerView === 'chains' ? (
          <>
            <div style={{
              display: 'flex', gap: 2, padding: '8px 12px',
              borderBottom: '1px solid var(--border)',
              background: 'var(--bg)', flexShrink: 0,
            }}>
              <Button
                id="tab-process-tree"
                variant="custom"
                customColor="var(--low)"
                onClick={() => setCenterView('tree')}
                disabled={!selectedAlert}
                active={centerView === 'tree'}
                icon={<GitBranch size={12} />}
              >
                Process Tree
              </Button>
              <Button
                id="tab-blast-radius"
                variant="custom"
                customColor="var(--crit)"
                onClick={() => setCenterView('blast')}
                disabled={!selectedAlert}
                active={centerView === 'blast'}
                icon={<Radiation size={12} />}
              >
                Blast Radius
              </Button>
              <Button
                id="tab-evidence"
                variant="custom"
                customColor="var(--info)"
                onClick={() => setCenterView('evidence')}
                disabled={!selectedAlert}
                active={centerView === 'evidence'}
                icon={<Database size={12} />}
              >
                Evidence Drawer
              </Button>
              <Button
                id="tab-chains"
                variant="custom"
                customColor="var(--med)"
                onClick={() => setCenterView('chains')}
                active={centerView === 'chains'}
                icon={<Activity size={12} />}
              >
                Incident Chains
              </Button>

              <div style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'flex-end',
                gap: 10, paddingRight: 4,
              }}>
                {selectedAlert?.suppressed && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '2px 8px',
                    borderRadius: 99, background: 'var(--bg-3)',
                    color: 'var(--text-3)', border: '1px solid var(--border)',
                    textTransform: 'uppercase', letterSpacing: '0.5px',
                  }}>
                    Suppressed
                  </span>
                )}
                {metadata && <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{metadata}</span>}
              </div>
            </div>

            <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
              {centerView === 'tree' && (
                selectedAlert?.raw_event_ref ? (
                  <ProcessTree
                    key={`tree-${selectedAlert.alert_id}`}
                    rootGuid={selectedAlert.raw_event_ref}
                    alertGuids={[selectedAlert.raw_event_ref]}
                  />
                ) : (
                  <div className="empty-state">
                    <GitBranch size={48} color="var(--border-2)" />
                    <h3>Process Tree Not Applicable</h3>
                    <p>This alert source does not include a process GUID, so no process tree can be trusted for it.</p>
                  </div>
                )
              )}
              {centerView === 'blast' && (
                selectedAlert?.raw_event_ref ? (
                  <BlastRadius
                    key={`blast-${selectedAlert.alert_id}`}
                    rootGuid={selectedAlert.raw_event_ref}
                    rootLabel={selectedAlert.rule_name}
                  />
                ) : (
                  <div className="empty-state">
                    <GitBranch size={48} color="var(--border-2)" />
                    <h3>Blast Radius Not Applicable</h3>
                    <p>Blast radius requires a source process GUID linked to Sysmon file, registry, or network events.</p>
                  </div>
                )
              )}
              {centerView === 'evidence' && selectedAlert && (
                <EvidenceDrawer alert={selectedAlert} />
              )}
              {centerView === 'chains' && (
                <IncidentChains hostId={initialHost || selectedAlert?.host_id} />
              )}
            </div>
          </>
        ) : (
          <div className="empty-state">
            <GitBranch size={48} color="var(--border-2)" />
            <h3>No Alert Selected</h3>
            <p>
              Select an alert from the left panel to inspect the exact telemetry behind it.
              Process views appear only when the source event contains a process GUID.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
