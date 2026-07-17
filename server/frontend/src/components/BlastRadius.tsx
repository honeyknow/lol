import React, { useEffect, useState, useMemo } from 'react'
import {
  ReactFlow, Background, Controls, type Node, type Edge, MarkerType,
  Handle, Position
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { api } from '../api/client'
import { FileText, HardDrive, Globe, Cpu } from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────
type Category = 'file' | 'registry' | 'network' | 'process'

interface BlastNode {
  id: string
  type: Category | 'root'
  label: string
}

// ── Node type components ─────────────────────────────────────────────────────
const baseNodeStyle: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
  borderRadius: 8, fontSize: 11, fontWeight: 600, maxWidth: 220,
  background: 'var(--bg)', border: '1px solid var(--border)',
  boxShadow: 'var(--shadow-sm)',
}

const RootNode = ({ data }: { data: { label: string } }) => (
  <div style={{
    ...baseNodeStyle,
    border: '2px solid var(--crit)',
    background: 'var(--crit-bg)',
    color: 'var(--crit)',
    fontWeight: 700, fontSize: 12,
  }}>
    <Handle type="source" position={Position.Top} id="top" style={{ opacity: 0 }} />
    <Handle type="source" position={Position.Right} id="right" style={{ opacity: 0 }} />
    <Handle type="source" position={Position.Bottom} id="bottom" style={{ opacity: 0 }} />
    <Handle type="source" position={Position.Left} id="left" style={{ opacity: 0 }} />
    <Cpu size={14} />
    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
  </div>
)

const FileNode = ({ data }: { data: { label: string } }) => (
  <div style={{ ...baseNodeStyle, borderColor: 'var(--high)', color: 'var(--high)' }}>
    <Handle type="target" position={Position.Top} id="top" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Right} id="right" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Bottom} id="bottom" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Left} id="left" style={{ opacity: 0 }} />
    <FileText size={13} />
    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
  </div>
)

const RegNode = ({ data }: { data: { label: string } }) => (
  <div style={{ ...baseNodeStyle, borderColor: 'var(--med)', color: 'var(--med)' }}>
    <Handle type="target" position={Position.Top} id="top" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Right} id="right" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Bottom} id="bottom" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Left} id="left" style={{ opacity: 0 }} />
    <HardDrive size={13} />
    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
  </div>
)

const NetNode = ({ data }: { data: { label: string } }) => (
  <div style={{ ...baseNodeStyle, borderColor: 'var(--info)', color: 'var(--info)' }}>
    <Handle type="target" position={Position.Top} id="top" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Right} id="right" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Bottom} id="bottom" style={{ opacity: 0 }} />
    <Handle type="target" position={Position.Left} id="left" style={{ opacity: 0 }} />
    <Globe size={13} />
    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
  </div>
)

const nodeTypes = { root: RootNode, file: FileNode, registry: RegNode, network: NetNode }

// ── Legend ───────────────────────────────────────────────────────────────────
const LEGEND = [
  { color: 'var(--crit)', label: 'Root Process' },
  { color: 'var(--high)', label: 'File Events' },
  { color: 'var(--med)',  label: 'Registry Keys' },
  { color: 'var(--info)', label: 'Network IPs' },
]

// ── Radial layout helper ─────────────────────────────────────────────────────
function radialLayout(items: BlastNode[]): Node[] {
  const root = items.find(n => n.type === 'root')
  const rest = items.filter(n => n.type !== 'root')
  if (!root) return []

  const cx = 400, cy = 300
  // Increase base radius to 320 to avoid overlap with wide root nodes
  const radius = Math.max(320, rest.length * 40)

  const nodes: Node[] = [
    { id: root.id, type: 'root', position: { x: cx - 110, y: cy - 20 }, data: { label: root.label } },
  ]

  rest.forEach((n, i) => {
    const angle = (i / rest.length) * 2 * Math.PI
    
    let sourceHandle = 'right'
    let targetHandle = 'left'

    if (angle >= Math.PI / 4 && angle < 3 * Math.PI / 4) {
      sourceHandle = 'bottom'
      targetHandle = 'top'
    } else if (angle >= 3 * Math.PI / 4 && angle < 5 * Math.PI / 4) {
      sourceHandle = 'left'
      targetHandle = 'right'
    } else if (angle >= 5 * Math.PI / 4 && angle < 7 * Math.PI / 4) {
      sourceHandle = 'top'
      targetHandle = 'bottom'
    }

    nodes.push({
      id: n.id,
      type: n.type as string,
      position: { x: cx + radius * Math.cos(angle) - 110, y: cy + radius * Math.sin(angle) - 20 },
      data: { label: n.label, sourceHandle, targetHandle },
    })
  })

  return nodes
}

// ── Main Component ────────────────────────────────────────────────────────────
interface Props {
  rootGuid: string
  rootLabel?: string
}

export default function BlastRadius({ rootGuid, rootLabel = 'Suspicious Process' }: Props) {
  const [fileEvents,     setFileEvents]     = useState<any[]>([])
  const [regEvents,      setRegEvents]      = useState<any[]>([])
  const [netEvents,      setNetEvents]      = useState<any[]>([])
  const [loading,        setLoading]        = useState(true)

  useEffect(() => {
    if (!rootGuid) return
    setLoading(true)
    Promise.all([
      api.getPivotEvents(rootGuid, 'file'),
      api.getPivotEvents(rootGuid, 'registry'),
      api.getPivotEvents(rootGuid, 'network'),
    ]).then(([f, r, n]) => {
      setFileEvents((f.events as any[]).slice(0, 15))
      setRegEvents((r.events as any[]).slice(0, 15))
      setNetEvents((n.events as any[]).slice(0, 15))
    }).catch(console.error).finally(() => setLoading(false))
  }, [rootGuid])

  const { nodes, edges } = useMemo(() => {
    const items: BlastNode[] = [
      { id: 'root', type: 'root', label: rootLabel },
    ]

    // Deduplicate
    const seenFiles = new Set<string>()
    fileEvents.forEach((e: any, i) => {
      const label = e.target_label || `File ${i}`
      if (seenFiles.has(label)) return
      seenFiles.add(label)
      items.push({ id: `file-${i}`, type: 'file', label: label.split('\\').pop() || label })
    })

    const seenReg = new Set<string>()
    regEvents.forEach((e: any, i) => {
      const label = e.target_label || `RegKey ${i}`
      if (seenReg.has(label)) return
      seenReg.add(label)
      items.push({ id: `reg-${i}`, type: 'registry', label: label.split('\\').pop() || label })
    })

    const seenNet = new Set<string>()
    netEvents.forEach((e: any, i) => {
      const label = e.target_label || `IP ${i}`
      if (seenNet.has(label)) return
      seenNet.add(label)
      items.push({ id: `net-${i}`, type: 'network', label: label })
    })

    const rfNodes = radialLayout(items)

    const rfEdges: Edge[] = items.filter(n => n.type !== 'root').map(n => {
      const nodeLayout = rfNodes.find(x => x.id === n.id)
      return {
        id: `e-root-${n.id}`,
        source: 'root',
        target: n.id,
        sourceHandle: nodeLayout?.data?.sourceHandle as string | undefined,
        targetHandle: nodeLayout?.data?.targetHandle as string | undefined,
        animated: false,
        style: {
          stroke: n.type === 'file'     ? 'var(--high)' :
                  n.type === 'registry' ? 'var(--med)'  :
                  n.type === 'network'  ? 'var(--info)' : 'var(--border-2)',
          strokeWidth: 1.5,
          strokeDasharray: '5,3',
        },
        markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16,
          color: n.type === 'file' ? 'var(--high)' : n.type === 'registry' ? 'var(--med)' : 'var(--info)',
        },
      }
    })

    return { nodes: rfNodes, edges: rfEdges }
  }, [fileEvents, regEvents, netEvents, rootLabel])

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', gap: 10 }}>
        <div className="spinner" />
        Building blast radius map…
      </div>
    )
  }

  if (nodes.length <= 1) {
    return (
      <div className="empty-state">
        <HardDrive size={40} />
        <h3>No Impact Data Found</h3>
        <p>No file, registry, or network events linked to this process in the database.</p>
      </div>
    )
  }

  return (
    <div style={{ flex: 1, position: 'relative', height: '100%' }}>
      {/* Legend */}
      <div style={{
        position: 'absolute', top: 12, left: 12, zIndex: 10,
        background: 'var(--bg)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '8px 12px',
        display: 'flex', flexDirection: 'column', gap: 6,
        boxShadow: 'var(--shadow)',
      }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '1px' }}>Blast Radius</div>
        {LEGEND.map(l => (
          <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: l.color }} />
            <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{l.label}</span>
          </div>
        ))}
        <div style={{ marginTop: 4, borderTop: '1px solid var(--border)', paddingTop: 6, display: 'flex', flexDirection: 'column', gap: 3 }}>
          <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{fileEvents.length} file • {regEvents.length} registry • {netEvents.length} network</span>
        </div>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        attributionPosition="bottom-right"
      >
        <Background color="var(--border)" gap={24} size={1} />
        <Controls style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6 }} />
      </ReactFlow>
    </div>
  )
}
