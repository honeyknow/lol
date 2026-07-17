import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { Shield, Users, Database, Cpu, HardDrive, MemoryStick, Trash2, Eye, RefreshCw, Activity, UserPlus, UserMinus, Lock } from 'lucide-react'

interface AllowedUser {
  email: string
  added_by: string
  added_at: number
  note: string
}

interface Tenant {
  id: string
  email: string
  db_filename: string
  created_at: number
  last_login: number | null
  is_active: number
  agent_count: number
  db_size_bytes: number
}

interface SystemStats {
  cpu: number
  ram: number
  disk: number
}

interface Props {
  /** Called when admin clicks "View Dashboard" for a tenant */
  onImpersonate: (tenantId: string, email: string) => void
}

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function fmtDate(epoch: number | null): string {
  if (!epoch) return '—'
  return new Date(epoch * 1000).toLocaleString()
}

function UsageBar({ value, color }: { value: number; color: string }) {
  const pct = Math.min(100, Math.max(0, value))
  const danger = pct > 85
  const warn = pct > 65
  const barColor = danger ? '#ef4444' : warn ? '#f59e0b' : color
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: 'var(--bg-4)', borderRadius: 99, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: barColor, borderRadius: 99, transition: 'width 0.5s' }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 700, color: barColor, minWidth: 36, textAlign: 'right' }}>{pct.toFixed(0)}%</span>
    </div>
  )
}

export default function AdminPanel({ onImpersonate }: Props) {
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [sysStats, setSysStats] = useState<SystemStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [purging, setPurging] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [confirmPurge, setConfirmPurge] = useState<string | null>(null)

  // Whitelist state
  const [allowedUsers, setAllowedUsers] = useState<AllowedUser[]>([])
  const [newEmail, setNewEmail] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newNote, setNewNote] = useState('')
  const [addingUser, setAddingUser] = useState(false)
  const [addError, setAddError] = useState('')

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const [tenantsRes, healthRes, allowedRes] = await Promise.all([
        api.adminGetTenants(),
        api.getHealth(),
        api.adminGetAllowedUsers(),
      ])
      setTenants(tenantsRes)
      if (healthRes.system_stats) setSysStats(healthRes.system_stats)
      setAllowedUsers(allowedRes)
    } catch (e: unknown) {
      setError('Failed to load admin data. Are you authenticated as admin?')
    } finally {
      setLoading(false)
    }
  }

  const handleAddUser = async () => {
    const email = newEmail.trim().toLowerCase()
    if (!email || !email.includes('@')) { setAddError('Enter a valid email'); return }
    setAddingUser(true)
    setAddError('')
    try {
      await api.adminAddAllowedUser(email, newPassword, newNote.trim())
      setNewEmail('')
      setNewPassword('')
      setNewNote('')
      const updated = await api.adminGetAllowedUsers()
      setAllowedUsers(updated)
    } catch (e: unknown) {
      setAddError(e instanceof Error ? e.message : 'Failed to add user.')
    } finally {
      setAddingUser(false)
    }
  }

  const handleRemoveUser = async (email: string) => {
    try {
      await api.adminRemoveAllowedUser(email)
      setAllowedUsers(prev => prev.filter(u => u.email !== email))
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to remove user.')
    }
  }

  useEffect(() => { load() }, [])

  const handlePurge = async (tenantId: string) => {
    if (confirmPurge !== tenantId) { setConfirmPurge(tenantId); return }
    setPurging(tenantId)
    try {
      await api.adminPurgeTenant(tenantId)
      setTenants(prev => prev.filter(t => t.id !== tenantId))
    } catch {
      alert('Failed to purge tenant.')
    } finally {
      setPurging(null)
      setConfirmPurge(null)
    }
  }

  const totalAgents = tenants.reduce((s, t) => s + t.agent_count, 0)
  const totalDbSize = tenants.reduce((s, t) => s + t.db_size_bytes, 0)
  const activeTenants = tenants.filter(t => t.is_active).length
  const maxDbSize = Math.max(...tenants.map(t => t.db_size_bytes), 1)

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 24px' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {error && (
        <div style={{ padding: '10px 14px', background: 'var(--crit-bg)', border: '1px solid rgba(204,0,0,0.2)', borderRadius: 8, color: 'var(--crit)', fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        <StatCard icon={<Users size={16} color="var(--accent)" />} label="Active Tenants" value={String(activeTenants)} />
        <StatCard icon={<Activity size={16} color="#22c55e" />} label="Total Agents" value={String(totalAgents)} />
        <StatCard icon={<Database size={16} color="var(--high)" />} label="Total DB Size" value={fmtBytes(totalDbSize)} />
      </div>

      {/* Server Hardware Stats */}
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 12, padding: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-2)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Cpu size={14} color="var(--text-3)" />
          Server Hardware Specs
        </div>
        {sysStats ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
            <HardwareStat icon={<Cpu size={13} />} label="CPU Usage" value={sysStats.cpu} />
            <HardwareStat icon={<MemoryStick size={13} />} label="RAM Usage" value={sysStats.ram} color="#a78bfa" />
            <HardwareStat icon={<HardDrive size={13} />} label="Disk Usage" value={sysStats.disk} color="#f59e0b" />
          </div>
        ) : (
          <div style={{ fontSize: 13, color: 'var(--text-3)', padding: '8px 0' }}>
            Hardware stats not available.
          </div>
        )}
      </div>

      {/* Tenants Table */}
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontSize: 13, fontWeight: 700, color: 'var(--text-2)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Users size={14} color="var(--text-3)" />
          Registered Tenants — Data Usage
        </div>
        {loading ? (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>Loading...</div>
        ) : tenants.length === 0 ? (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>No tenants registered yet.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'var(--bg-3)' }}>
                {['Email', 'Status', 'Agents', 'DB Size', 'Usage', 'Last Login', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '8px 14px', textAlign: 'left', color: 'var(--text-3)', fontWeight: 600, fontSize: 11, letterSpacing: '0.5px', textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tenants.map((t, i) => (
                <tr
                  key={t.id}
                  style={{ borderTop: i === 0 ? 'none' : '1px solid var(--border)', background: 'transparent' }}
                >
                  <td style={{ padding: '10px 14px', color: 'var(--text-1)', fontWeight: 600, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.email}</td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
                      background: t.is_active ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                      color: t.is_active ? '#22c55e' : '#ef4444',
                    }}>
                      {t.is_active ? 'ACTIVE' : 'BANNED'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', color: 'var(--text-2)', fontWeight: 700 }}>{t.agent_count}</td>
                  <td style={{ padding: '10px 14px', color: 'var(--text-2)' }}>{fmtBytes(t.db_size_bytes)}</td>
                  <td style={{ padding: '10px 14px', color: 'var(--text-3)', fontSize: 12 }}>{fmtDate(t.last_login)}</td>
                  <td style={{ padding: '10px 14px' }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => onImpersonate(t.id, t.email)} title="View their dashboard" style={actionBtn('#ef4444')}>
                        <Eye size={13} /> View
                      </button>
                      <button onClick={() => api.adminExportTenantDb(t.id)} title="Download their raw SQLite DB" style={actionBtn('#22c55e')}>
                        <Database size={13} /> Export
                      </button>
                      <button
                        onClick={() => handlePurge(t.id)}
                        disabled={purging === t.id}
                        title={confirmPurge === t.id ? 'Click again to confirm — IRREVERSIBLE' : 'Permanently delete tenant'}
                        style={actionBtn(confirmPurge === t.id ? '#ef4444' : '#e57373')}
                      >
                        <Trash2 size={13} />
                        {confirmPurge === t.id ? 'Confirm?' : 'Purge'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Whitelist Management */}
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 700, color: 'var(--text-2)' }}>
            <UserPlus size={14} color="var(--text-3)" />
            Access Management — Create Users
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{allowedUsers.length} user{allowedUsers.length !== 1 ? 's' : ''} total</span>
        </div>

        {/* Add user form */}
        <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 8, alignItems: 'flex-start', flexWrap: 'wrap' }}>
          <input
            id="whitelist-email-input"
            type="email"
            placeholder="user@gmail.com"
            value={newEmail}
            onChange={e => setNewEmail(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAddUser()}
            style={{
              flex: '1 1 200px', padding: '7px 12px', borderRadius: 7, fontSize: 13,
              background: 'var(--bg-3)', border: '1px solid var(--border)', color: 'var(--text)',
              outline: 'none',
            }}
          />
          <input
            type="password"
            placeholder="Password (for login)"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAddUser()}
            style={{
              flex: '1 1 140px', padding: '7px 12px', borderRadius: 7, fontSize: 13,
              background: 'var(--bg-3)', border: '1px solid var(--border)', color: 'var(--text)',
              outline: 'none',
            }}
          />
          <input
            type="text"
            placeholder="Note (e.g. Rahul's Account)"
            value={newNote}
            onChange={e => setNewNote(e.target.value)}
            style={{
              flex: '1 1 160px', padding: '7px 12px', borderRadius: 7, fontSize: 13,
              background: 'var(--bg-3)', border: '1px solid var(--border)', color: 'var(--text)',
              outline: 'none',
            }}
          />
          <button
            id="whitelist-add-btn"
            onClick={handleAddUser}
            disabled={addingUser}
            style={{
              padding: '7px 16px', borderRadius: 7, fontSize: 13, fontWeight: 700,
              background: 'linear-gradient(135deg,#6366f1,#8b5cf6)', border: 'none',
              color: '#fff', cursor: addingUser ? 'not-allowed' : 'pointer', opacity: addingUser ? 0.7 : 1,
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            <UserPlus size={13} />
            {addingUser ? 'Adding...' : 'Add User'}
          </button>
          {addError && <div style={{ width: '100%', fontSize: 12, color: 'var(--crit)', fontWeight: 600 }}>⚠ {addError}</div>}
        </div>

        {/* Whitelist table */}
        {allowedUsers.length === 0 ? (
          <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>No users whitelisted yet.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'var(--bg-3)' }}>
                {['Email', 'Note', 'Added By', 'Added At', 'Action'].map(h => (
                  <th key={h} style={{ padding: '7px 14px', textAlign: 'left', color: 'var(--text-3)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {allowedUsers.map((u, i) => {
                const isAdmin = u.email === 'info.honeyknows@gmail.com'
                return (
                  <tr key={u.email} style={{ borderTop: i === 0 ? 'none' : '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 14px', color: 'var(--text-1)', fontWeight: 600 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {isAdmin && <Lock size={11} color="var(--accent)" title="Admin" />}
                        {u.email}
                      </div>
                    </td>
                    <td style={{ padding: '8px 14px', color: 'var(--text-3)', fontSize: 12 }}>{u.note || '—'}</td>
                    <td style={{ padding: '8px 14px', color: 'var(--text-3)', fontSize: 12 }}>{u.added_by}</td>
                    <td style={{ padding: '8px 14px', color: 'var(--text-3)', fontSize: 12 }}>{fmtDate(u.added_at)}</td>
                    <td style={{ padding: '8px 14px' }}>
                      {isAdmin ? (
                        <span style={{ fontSize: 11, color: 'var(--accent)', fontWeight: 600 }}>Admin</span>
                      ) : (
                        <button
                          onClick={() => handleRemoveUser(u.email)}
                          title="Remove from whitelist"
                          style={actionBtn('#ef4444')}
                        >
                          <UserMinus size={12} /> Remove
                        </button>
                      )}
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function StatCard({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: string; sub?: string }) {
  return (
    <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 10, padding: '14px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        {icon}
        <span style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</span>
      </div>
      <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--text-1)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

function HardwareStat({ icon, label, value, color = '#22c55e' }: { icon: React.ReactNode; label: string; value: number; color?: string }) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 6, color: 'var(--text-3)', fontSize: 12 }}>
        {icon}
        {label}
      </div>
      <UsageBar value={value} color={color} />
    </div>
  )
}

function SpecBadge({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
      <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{label}</span>
      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-2)' }}>{value}</span>
    </div>
  )
}

function actionBtn(color: string): React.CSSProperties {
  return {
    display: 'inline-flex', alignItems: 'center', gap: 4,
    padding: '4px 9px', borderRadius: 6, fontSize: 12, fontWeight: 600,
    background: `${color}18`, border: `1px solid ${color}40`,
    color, cursor: 'pointer',
  }
}
