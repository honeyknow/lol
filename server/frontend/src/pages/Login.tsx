import React, { useState } from 'react'
import { Shield, Lock, Mail, ArrowRight, Activity } from 'lucide-react'
import { api } from '../api/client'

interface LoginProps {
  onLoginSuccess: (user: { email: string; role: 'admin' | 'user'; tenant: Record<string, unknown> | null }) => void
}

export function Login({ onLoginSuccess }: LoginProps) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email || !password) {
      setError('Please enter both email and password.')
      return
    }

    setLoading(true)
    setError('')
    
    try {
      await api.login(email, password)
      // If login is successful, get me
      const me = await api.getMe()
      if (me.authenticated) {
        onLoginSuccess({ email: me.email, role: me.role, tenant: me.tenant ?? null })
      } else {
        setError('Login succeeded but session could not be verified.')
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Invalid email or password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: '#0d0d0f',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Background decorations */}
      <div style={{
        position: 'absolute', top: '10%', left: '15%', width: 400, height: 400,
        background: 'radial-gradient(circle, rgba(99,102,241,0.15) 0%, rgba(0,0,0,0) 70%)',
        filter: 'blur(40px)'
      }} />
      <div style={{
        position: 'absolute', bottom: '10%', right: '15%', width: 500, height: 500,
        background: 'radial-gradient(circle, rgba(139,92,246,0.1) 0%, rgba(0,0,0,0) 70%)',
        filter: 'blur(60px)'
      }} />

      <div style={{
        width: '100%',
        maxWidth: 420,
        padding: '40px',
        background: 'rgba(20, 20, 22, 0.6)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 24,
        boxShadow: '0 24px 48px rgba(0,0,0,0.4)',
        zIndex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center'
      }}>
        {/* Logo */}
        <div style={{
          width: 56, height: 56, borderRadius: 16,
          background: 'linear-gradient(135deg, rgba(99,102,241,0.2) 0%, rgba(139,92,246,0.2) 100%)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '1px solid rgba(99,102,241,0.3)',
          marginBottom: 24
        }}>
          <Shield size={28} color="#8b5cf6" />
        </div>

        <h1 style={{ fontSize: 24, fontWeight: 900, color: '#fff', marginBottom: 8, letterSpacing: '-0.5px' }}>
          ISHA-X EDR
        </h1>
        <p style={{ fontSize: 14, color: 'var(--text-3)', marginBottom: 32 }}>
          Secure Endpoint Detection & Response
        </p>

        <form onSubmit={handleSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>
          
          {error && (
            <div style={{
              padding: '12px 16px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: 12, color: '#fca5a5', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8
            }}>
              <Activity size={16} />
              {error}
            </div>
          )}

          <div style={{ position: 'relative' }}>
            <div style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }}>
              <Mail size={18} />
            </div>
            <input
              type="email"
              placeholder="Email address"
              value={email}
              onChange={e => setEmail(e.target.value)}
              style={{
                width: '100%', padding: '14px 16px 14px 44px',
                background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 12, color: '#fff', fontSize: 14, outline: 'none',
                transition: 'border-color 0.2s'
              }}
              autoFocus
            />
          </div>

          <div style={{ position: 'relative' }}>
            <div style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }}>
              <Lock size={18} />
            </div>
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              style={{
                width: '100%', padding: '14px 16px 14px 44px',
                background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 12, color: '#fff', fontSize: 14, outline: 'none',
                transition: 'border-color 0.2s'
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%', padding: '14px', marginTop: 8,
              background: loading ? 'var(--bg-3)' : 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
              color: loading ? 'var(--text-3)' : '#fff',
              border: 'none', borderRadius: 12, fontSize: 14, fontWeight: 700,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              transition: 'opacity 0.2s'
            }}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        <div style={{ marginTop: 32, fontSize: 12, color: 'var(--text-4)' }}>
          Enterprise Endpoint Security
        </div>
      </div>
    </div>
  )
}
