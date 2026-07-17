import { useCallback, useEffect, useState } from 'react'
import {
  ReactFlow, Background, Controls,
  useNodesState, useEdgesState, type Node, type Edge,
  Handle, Position, type NodeProps, useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { api, type ProcessTree as ProcessTreeType } from '../api/client'
import { GitBranch, Loader } from 'lucide-react'
import dagre from 'dagre'

/* ── Helpers ─────────────────────────────────────────────────── */
function basename(path: string) {
  return path.split(/[/\\]/).pop() ?? path
}

/* ── Custom process node (light theme) ──────────────────────── */
function ProcessNodeCard({ data }: NodeProps) {
  const { label, image, pid, user, isAlert, isSelected } = data as {
    label: string; image: string; pid: number; user: string; isAlert: boolean; isSelected: boolean
  }
  return (
    <>
      <Handle
        type="target"
        position={Position.Top}
        isConnectable={false}
        style={{ opacity: 0 }}
      />
      <div style={{
        background: 'var(--bg)',
        border: `1px solid ${isAlert ? 'var(--crit)' : isSelected ? 'var(--accent)' : 'var(--border)'}`,
        borderLeft: `3px solid ${isAlert ? 'var(--crit)' : isSelected ? 'var(--accent)' : 'var(--border-2)'}`,
        borderRadius: 6,
        padding: '8px 12px',
        minWidth: 180,
        maxWidth: 260,
        boxShadow: isAlert
          ? '0 0 0 3px rgba(204,0,0,0.10), 0 2px 8px rgba(0,0,0,0.10)'
          : isSelected
          ? '0 0 0 3px rgba(139,0,0,0.08), 0 2px 8px rgba(0,0,0,0.10)'
          : '0 1px 4px rgba(0,0,0,0.08)',
      }}>
        <div style={{
          fontSize: 12, fontWeight: 700,
          color: isAlert ? 'var(--crit)' : 'var(--text)',
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        }}>
          {label}
        </div>
        <div style={{
          fontSize: 10, color: 'var(--text-3)', marginTop: 2,
          fontFamily: "'Courier New', monospace",
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        }}>
          {image}
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
          {pid && <span style={{ fontSize: 10, color: 'var(--text-2)', background: 'var(--bg-3)', padding: '1px 5px', borderRadius: 3 }}>PID {pid}</span>}
          {user && <span style={{ fontSize: 10, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user}</span>}
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        isConnectable={false}
        style={{ opacity: 0 }}
      />
    </>
  )
}

const NODE_TYPES = { process: ProcessNodeCard }

/* ── Layout ──────────────────────────────────────────────────── */
function buildLayout(tree: ProcessTreeType, alertGuids: Set<string>, selectedGuid: string | null) {
  const dagreGraph = new dagre.graphlib.Graph()
  dagreGraph.setDefaultEdgeLabel(() => ({}))

  const NODE_W = 220
  const NODE_H = 70

  // Configure DAG layout: Top-to-Bottom, with standard spacing
  dagreGraph.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 90 })

  tree.nodes.forEach((node) => {
    dagreGraph.setNode(node.process_guid, { width: NODE_W, height: NODE_H })
  })

  tree.edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target)
  })

  // Magic happens here - calculates all x,y positions avoiding overlaps
  dagre.layout(dagreGraph)

  const nodes: Node[] = tree.nodes.map(n => {
    const nodeWithPosition = dagreGraph.node(n.process_guid)
    return {
      id: n.process_guid,
      type: 'process',
      targetPosition: Position.Top,
      sourcePosition: Position.Bottom,
      position: {
        // Dagre centers nodes, React Flow anchors at top-left
        x: nodeWithPosition.x - NODE_W / 2,
        y: nodeWithPosition.y - NODE_H / 2,
      },
      data: {
        label:      basename(n.image ?? 'unknown'),
        image:      n.image ?? '',
        pid:        n.pid,
        user:       n.user_name ?? '',
        isAlert:    alertGuids.has(n.process_guid),
        isSelected: n.process_guid === selectedGuid,
      },
      style: { cursor: 'pointer' },
    }
  })

  const edges: Edge[] = tree.edges.map(e => ({
    id: `${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    style: { stroke: 'var(--border-2)', strokeWidth: 1.5 },
    type: 'smoothstep',
    animated: false,
  }))

  return { nodes, edges }
}

function FitViewOnLoad({ nodes }: { nodes: Node[] }) {
  const { fitView } = useReactFlow()
  useEffect(() => {
    if (nodes.length > 0) {
      window.requestAnimationFrame(() => fitView({ padding: 0.2, duration: 500 }))
    }
  }, [nodes, fitView])
  return null
}

/* ── Main component ──────────────────────────────────────────── */
interface Props {
  hostId?: string | null
  rootGuid?: string | null | undefined
  alertGuids?: string[]
  onNodeClick?: (guid: string) => void
}

export default function ProcessTree({ hostId, rootGuid, alertGuids = [], onNodeClick }: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [loading, setLoading]            = useState(false)

  const loadTree = useCallback(() => {
    if (!hostId && !rootGuid) return
    setLoading(true)
    const params = rootGuid
      ? { root_guid: rootGuid, depth: 4 }
      : { host_id: hostId!, depth: 3, hours: 6 }

    api.getProcessTree(params)
      .then(tree => {
        const ag = new Set([...tree.alert_guids, ...alertGuids])
        const { nodes: n, edges: e } = buildLayout(tree, ag, rootGuid ?? null)
        setNodes(n)
        setEdges(e)
      })
      .catch(() => { setNodes([]); setEdges([]) })
      .finally(() => setLoading(false))
  }, [hostId, rootGuid, alertGuids, setNodes, setEdges])

  useEffect(() => { loadTree() }, [loadTree])

  const handleNodeClick = useCallback((_: unknown, node: Node) => {
    onNodeClick?.(node.id)
  }, [onNodeClick])

  return (
    <div style={{ flex: 1, position: 'relative', background: 'var(--bg-2)', height: '100%' }}>
      {loading && (
        <div style={{
          position: 'absolute', top: 16, left: '50%', transform: 'translateX(-50%)',
          zIndex: 10, background: 'var(--bg)', padding: '6px 14px',
          borderRadius: 99, border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 6,
          fontSize: 12, color: 'var(--text-2)', boxShadow: 'var(--shadow)',
        }}>
          <Loader size={12} style={{ animation: 'spin 1s linear infinite' }} />
          Loading process tree…
        </div>
      )}
      {!loading && nodes.length === 0 && (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', height: '100%', color: 'var(--text-3)', gap: 12,
        }}>
          <GitBranch size={32} strokeWidth={1} color="var(--border-2)" />
          <span style={{ fontSize: 13 }}>
            {(hostId || rootGuid) ? 'No process data found for this alert' : 'Select a host to view the process tree'}
          </span>
        </div>
      )}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        nodeTypes={NODE_TYPES}
        nodesConnectable={false}
        elementsSelectable={false}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <FitViewOnLoad nodes={nodes} />
        <Background color="var(--border)" gap={24} size={1} />
        <Controls
          style={{
            border: '1px solid var(--border)',
            background: 'var(--bg)',
            boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
            borderRadius: 6,
          }}
        />
      </ReactFlow>
    </div>
  )
}
