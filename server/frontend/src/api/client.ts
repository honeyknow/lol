import axios from 'axios'

export const http = axios.create({
  baseURL: '/', // Points to the same origin (FastAPI backend will serve SPA and API)
  headers: {
    'Content-Type': 'application/json',
  }
})

// 401 interceptor: redirect to login page if unauthorized
http.interceptors.response.use(
  r => r,
  err => {
    // Only redirect if it's a 401 and we aren't currently on the login page
    if (err.response?.status === 401 && window.location.pathname !== '/login') {
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)


// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface Alert {
  alert_id: string
  rule_id?: string
  source_layer: string
  technique_id: string | null
  rule_name: string
  severity_score: number
  raw_event_ref: string | null
  source_table: string | null
  host_id: string | null
  created_at: string
  suppressed: boolean
  summary?: string
  event_id?: number
  channel?: string | null
  process_chain?: {
    self: Record<string, unknown>
    parents: Record<string, unknown>[]
    children: Record<string, unknown>[]
  } | null
}

export interface ProcessNode {
  process_guid: string
  parent_process_guid: string | null
  image: string
  command_line: string | null
  pid: number | null
  user_name: string | null
  host_id: string
  event_timestamp: string
  depth?: number
}

export interface RuleResponse {
  rules: SigmaRule[];
}

export interface AIQueryRequest {
  question: string;
  alert_id?: number;
  host_id?: string;
  hours?: number;
}

export interface AIQueryResponse {
  mode: string;
  answer: string;
  citations: Array<{ label: string; route: string }>;
  suggested_checks: string[];
  context: Record<string, any>;
}

export interface ProcessTree {
  nodes: ProcessNode[]
  edges: { source: string; target: string }[]
  alert_guids: string[]
}

export interface TimelineEvent {
  event_type: string
  id: string
  label: string
  event_timestamp: string
  raw_json?: string
  severity_score?: number
}

export interface Stats {
  row_counts: Record<string, number>
  severity_counts: { crit: number, high: number, med: number, low: number }
  last_alert?: string
  utc: string
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'empty'
  db_exists: boolean
  utc: string
  pipeline: Record<string, number>
  last_event?: Record<string, unknown> | null
  last_alert?: Record<string, unknown> | null
  lag_seconds: number | null
  missing_fields?: Record<string, number>
  warnings: string[]
  system_stats?: {
    cpu: number
    ram: number
    disk: number
  }
}

export interface AmsiEvent {
  pid: number
  process_guid: string
  content_name: string
  content_hex: string
  scan_result: number
  host_id: string
  event_timestamp: string
}

export interface SigmaRule {
  rule_id:       string
  title:         string
  description:   string
  date:          string
  severity:      string          // low | medium | high | critical
  technique_ids: string[]
  tags:          string[]
  enabled:       boolean
  is_custom:     boolean
  is_global:     boolean
  tenant_id:     string | null
  uploaded_by:   string | null
  hit_count:     number
  last_fired_at: number | null
  noise_score:   number
  created_at:    number | null
  updated_at:    number | null
}

export interface RuleStat {
  rule_id:       string
  title:         string
  severity:      string
  hit_count:     number
  last_fired_at: number | null
  noise_score:   number
  enabled:       number
  is_custom:     number
  uploaded_by:   string | null
  tenant_id:     string | null
  days_active:   number
  is_dead:       boolean
  is_high_noise: boolean
}

export interface RegisteredEndpoint {
  host_id: string
  pc_name: string
  registered_at: string | null
  last_seen: string | null
}

export interface EvidenceArtifact {
  process_guid?: string
  parent_process_guid?: string | null
  process_image?: string | null
  image?: string
  command_line?: string | null
  pid?: number | null
  user_name?: string | null
  host_id?: string | null
  target_label?: string
  target_filename?: string
  target_object?: string
  destination_ip?: string | null
  destination_port?: string | null
  timestamp?: string
}

export interface AlertEvidence {
  alert: Alert
  source_event: Record<string, unknown> | null
  root_process_guid: string | null
  host_id: string | null
  process_tree: ProcessTree
  artifacts: {
    process: EvidenceArtifact[]
    network: EvidenceArtifact[]
    file: EvidenceArtifact[]
    registry: EvidenceArtifact[]
  }
  amsi: Array<Record<string, unknown>>
  completeness: {
    level: string
    has_source_event: boolean
    has_process_guid: boolean
    has_process_node: boolean
    host_scoped: boolean
    edge_host_scope_complete: boolean
    missing_network: boolean
    missing_file: boolean
    missing_registry: boolean
    missing_amsi: boolean
    notes: string[]
  }
  counts: Record<string, number>
}

export interface AlertChain {
  host_id: string
  start: string
  end: string
  alerts: Alert[]
}

export interface CorrelationResponse {
  chains: AlertChain[]
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

export const api = {
  // Alerts
  getAlerts: (params?: {
    limit?: number; offset?: number; severity_min?: number; layer?: string; technique?: string
  }) => http.get<{ total: number; limit: number; offset: number; alerts: Alert[] }>('/alerts', { params }).then(r => r.data),

  getAlertCorrelations: (params?: { window_seconds?: number }) =>
    http.get<CorrelationResponse>('/alerts/correlations', { params }).then(r => r.data),

  getAlert: (id: string) => http.get<Alert>(`/alerts/${id}`).then(r => r.data),

  getAlertEvidence: (id: string) =>
    http.get<AlertEvidence>(`/alerts/${id}/evidence`).then(r => r.data),

  getStats: () => http.get<Stats>('/stats').then(r => r.data),

  getHealth: () => http.get<HealthStatus>('/health').then(r => r.data),

  // Rules
  getRules: () => http.get<{ count: number; rules: SigmaRule[] }>('/rules').then(r => r.data),

  getRuleStats: () => http.get<{ stats: RuleStat[] }>('/rules/stats').then(r => r.data),

  toggleRule: (ruleId: string, enabled: boolean) =>
    http.post<{ status: string; rule_id: string; enabled: boolean }>(`/rules/${ruleId}/toggle`, { enabled }).then(r => r.data),

  getRuleYaml: (ruleId: string) =>
    http.get<{ rule_id: string; yaml: string }>(`/rules/${ruleId}/yaml`).then(r => r.data),

  updateRuleYaml: (ruleId: string, yaml: string) =>
    http.put<{ status: string; rule_id: string }>(`/rules/${ruleId}/yaml`, { yaml }).then(r => r.data),

  updateRuleMeta: (ruleId: string, updates: Partial<Pick<SigmaRule,
    'title' | 'description' | 'date' | 'severity' | 'tags' | 'technique_ids'
  >>) =>
    http.put<{ status: string; rule_id: string }>(`/rules/${ruleId}/meta`, updates).then(r => r.data),

  uploadRule: (yamlText: string) => {
    const form = new FormData()
    form.append('yaml_text', yamlText)
    return http.post<{ status: string; rule_id: string; title: string; rules_loaded: number }>(
      '/rules/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } }
    ).then(r => r.data)
  },

  uploadRuleFile: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return http.post<{ status: string; rule_id: string; title: string; rules_loaded: number }>(
      '/rules/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } }
    ).then(r => r.data)
  },

  deleteRule: (ruleId: string) =>
    http.delete<{ status: string; rule_id: string }>(`/rules/${ruleId}`).then(r => r.data),

  // AI
  queryAI: (payload: AIQueryRequest) => http.post<AIQueryResponse>('/ai/query', payload).then(r => r.data),

  // Hosts
  getHosts: () =>
    http.get<{ hosts: RegisteredEndpoint[] }>('/hosts').then(r => r.data),

  // Process tree / events
  getProcessTree: (params: { root_guid?: string; host_id?: string; depth?: number; hours?: number }) =>
    http.get<ProcessTree>('/process-tree', { params }).then(r => r.data),

  getPivotEvents: (processGuid: string, type: 'network' | 'file' | 'registry' | 'process') =>
    http.get<{ events: unknown[] }>(`/events/${processGuid}`, { params: { type } }).then(r => r.data),

  getTimeline: (params: { host_id: string; hours?: number }) =>
    http.get<{ events: TimelineEvent[] }>('/timeline', { params }).then(r => r.data),

  // AMSI
  getAmsiEvents: (params: { host_id?: string; detected_only?: boolean; limit?: number; offset?: number }) =>
    http.get<{ total: number; limit: number; offset: number; events: AmsiEvent[] }>('/amsi', { params }).then(r => r.data),

  getAmsiByProcess: (processGuid: string, detectedOnly = false) =>
    http.get<{ total: number; limit: number; offset: number; events: AmsiEvent[] }>('/amsi', {
      params: { process_guid: processGuid, detected_only: detectedOnly, limit: 100 }
    }).then(r => r.data),

  /** Returns logged-in user's identity and role. */
  getMe: () => http.get('/auth/me').then(r => r.data),
  login: (email: string, password: string) => http.post('/auth/login', { email, password }).then(r => r.data),
  logout: () => http.post('/auth/logout').then(r => r.data),

  /** Returns all agents registered to the current tenant. */
  getAgents: (impersonateTenantId?: string) =>
    http.get<{ agents: { agent_id: string; agent_name: string; last_seen_at: number | null; registered_at: number; is_revoked: number }[]; count: number }>(
      '/agents',
      { headers: impersonateTenantId ? { 'X-Impersonate-Tenant': impersonateTenantId } : {} }
    ).then(r => r.data),

  /** Revoke the user's own agent. */
  revokeMyAgent: (agentId: string) =>
    http.get<{ status: string; agent_id: string }>(`/admin/agents/${agentId}/revoke`).then(r => r.data),

  /**
   * Triggers download of a personalised ISHAX_Setup.exe.
   * Shows a loading state while the server compiles the installer (~3-5s).
   */
  downloadAgent: async (): Promise<void> => {
    const res = await fetch('/deploy/download-agent', { credentials: 'include' })
    if (res.status === 429) {
      const text = await res.text()
      throw new Error(text || 'Rate limited. Please wait 60 seconds.')
    }
    if (!res.ok) {
      const text = await res.text()
      throw new Error(text || 'Download failed. Server may be busy.')
    }
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    const cd = res.headers.get('content-disposition') || ''
    const match = cd.match(/filename="?([^"]+)"?/)
    a.download = match ? match[1] : 'ISHAX_Setup.exe'
    a.href = url
    document.body.appendChild(a)
    a.click()
    setTimeout(() => { URL.revokeObjectURL(url); document.body.removeChild(a) }, 100)
  },

  /** Triggers a browser file download of the tenant's raw SQLite DB. */
  downloadDb: () => {
    const link = document.createElement('a')
    link.href = '/download-db'
    link.download = 'ishax_edr.db'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  },

  /** Permanently deletes the user's account and all their data. */
  deleteMyData: () =>
    http.delete<{ status: string; message: string }>('/delete-my-data').then(r => r.data),

  // Admin-only -----------------------------------------------------------------

  /** Admin: list all tenants with agent counts and DB sizes. */
  adminGetTenants: () =>
    http.get<Array<{ id: string; email: string; db_filename: string; created_at: number; last_login: number | null; is_active: number; agent_count: number; db_size_bytes: number }>>('/admin/tenants').then(r => r.data),

  /** Admin: revoke a specific agent (any tenant). */
  adminRevokeAgent: (agentId: string) =>
    http.delete<{ status: string; agent_id: string }>(`/admin/agents/${agentId}`).then(r => r.data),

  /** Admin: permanently delete a tenant and wipe their .db file. */
  adminPurgeTenant: (tenantId: string) =>
    http.delete<{ status: string; tenant_id: string }>(`/admin/tenants/${tenantId}`).then(r => r.data),

  /** Admin: export a tenant's raw .db file. */
  adminExportTenantDb: (tenantId: string) => {
    const link = document.createElement('a')
    link.href = `/admin/tenants/${tenantId}/export`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  },

  // Whitelist management -------------------------------------------------------

  /** Admin: get all whitelisted emails. */
  adminGetAllowedUsers: () =>
    http.get<Array<{ email: string; added_by: string; added_at: number; note: string }>>('/admin/allowed-users').then(r => r.data),

  /** Admin: add an email to the whitelist. No restart needed. */
  adminAddAllowedUser: (email: string, password?: string, note?: string) =>
    http.post<{ status: string; email: string }>('/admin/allowed-users', { email, password, note }).then(r => r.data),

  /** Admin: remove an email from the whitelist. Cannot remove super-admin. */
  adminRemoveAllowedUser: (email: string) =>
    http.delete<{ status: string; email: string }>(`/admin/allowed-users/${encodeURIComponent(email)}`).then(r => r.data),
}
