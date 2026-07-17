import { useEffect, useState } from 'react'
import { Activity, HardDrive, Network, Cpu } from 'lucide-react'
import { api, type Alert, type ProcessNode } from '../api/client'

interface Props {
  alert: Alert
}

export default function ThreatIntelPanel({ alert }: Props) {
  const [processes, setProcesses] = useState<ProcessNode[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedProcess, setSelectedProcess] = useState<ProcessNode | null>(null)
  
  // Details for selected process
  const [networkEvents, setNetworkEvents] = useState<any[]>([])
  const [fileEvents, setFileEvents] = useState<any[]>([])
  const [detailsLoading, setDetailsLoading] = useState(false)

  // Load process tree based on alert's raw_event_ref
  useEffect(() => {
    if (!alert.raw_event_ref) {
      setLoading(false)
      return
    }
    
    setLoading(true)
    api.getProcessTree({ root_guid: alert.raw_event_ref, depth: 3 })
      .then(data => {
        setProcesses(data.nodes)
        if (data.nodes.length > 0) {
          setSelectedProcess(data.nodes.find(n => n.process_guid === alert.raw_event_ref) || data.nodes[0])
        }
      })
      .catch(() => null)
      .finally(() => setLoading(false))
  }, [alert.raw_event_ref])

  // Load details when a process is selected
  useEffect(() => {
    if (!selectedProcess) return
    setDetailsLoading(true)
    
    Promise.all([
      api.getPivotEvents(selectedProcess.process_guid, 'network').catch(() => ({ events: [] })),
      api.getPivotEvents(selectedProcess.process_guid, 'file').catch(() => ({ events: [] }))
    ]).then(([netData, fileData]) => {
      setNetworkEvents(netData.events)
      setFileEvents(fileData.events)
    }).finally(() => setDetailsLoading(false))
  }, [selectedProcess])

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--bg)'
    }}>
      
        {loading ? (
          <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center' }}>
            <div className="spinner" />
          </div>
        ) : processes.length === 0 ? (
          <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)' }}>
            <p>No process chain data available for this alert.</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
            {/* Left Pane: Processes */}
            <div style={{
              width: 350, borderRight: '1px solid var(--border)', background: 'var(--bg-2)',
              overflowY: 'auto', display: 'flex', flexDirection: 'column'
            }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600, color: 'var(--text-2)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Activity size={14} /> Involved Processes
              </div>
              <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {processes.map(p => {
                  const isSelected = selectedProcess?.process_guid === p.process_guid
                  return (
                    <div
                      key={p.process_guid}
                      onClick={() => setSelectedProcess(p)}
                      style={{
                        padding: 12, borderRadius: 6, cursor: 'pointer',
                        background: isSelected ? 'var(--accent-bg)' : 'var(--bg)',
                        border: `1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                        transition: 'all 0.15s'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <Cpu size={14} color={isSelected ? 'var(--accent)' : 'var(--text-3)'} />
                        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>
                          {p.image.split('\\').pop() || p.image}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)', wordBreak: 'break-all' }}>
                        PID: {p.pid} • {p.user_name || 'SYSTEM'}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Right Pane: Intel Details */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h4 style={{ margin: 0, fontSize: 14 }}>Process Artifacts</h4>
              </div>
              
              <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
                {detailsLoading ? (
                   <div style={{ display: 'flex', padding: 40, justifyContent: 'center' }}><div className="spinner" /></div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                    {/* Network IPs */}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
                        <Network size={16} color="var(--info)" />
                        <h5 style={{ margin: 0, fontSize: 13 }}>Network Connections ({networkEvents.length})</h5>
                      </div>
                      {networkEvents.length === 0 ? (
                        <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No network events recorded for this process.</div>
                      ) : (
                        <div style={{ background: 'var(--bg-2)', borderRadius: 6, border: '1px solid var(--border)', padding: 12 }}>
                          {networkEvents.map((net, i) => (
                            <div key={i} style={{ padding: '4px 0', borderBottom: i < networkEvents.length -1 ? '1px solid var(--border)' : 'none', fontSize: 12 }}>
                              <span style={{ fontWeight: 600, color: 'var(--text-2)' }}>{net.destination_ip || 'Unknown IP'}</span>
                              <span style={{ color: 'var(--text-3)', marginLeft: 8 }}>Port: {net.destination_port}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* File Hashes */}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
                        <HardDrive size={16} color="var(--med)" />
                        <h5 style={{ margin: 0, fontSize: 13 }}>File Modifications ({fileEvents.length})</h5>
                      </div>
                      {fileEvents.length === 0 ? (
                        <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No file events recorded for this process.</div>
                      ) : (
                        <div style={{ background: 'var(--bg-2)', borderRadius: 6, border: '1px solid var(--border)', padding: 12 }}>
                          {fileEvents.map((file, i) => (
                            <div key={i} style={{ padding: '4px 0', borderBottom: i < fileEvents.length -1 ? '1px solid var(--border)' : 'none', fontSize: 12 }}>
                              <div style={{ color: 'var(--text-2)', marginBottom: 2, wordBreak: 'break-all' }}>{file.target_filename}</div>
                              <div style={{ color: 'var(--text-3)', fontSize: 11, fontFamily: 'monospace' }}>Hash: {file.hashes || 'N/A'}</div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                  </div>
                )}
              </div>
            </div>
          </div>
        )}
    </div>
  )
}
