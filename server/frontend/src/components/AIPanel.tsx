import { useState, useRef, useEffect } from 'react'
import { Sparkles, X, Send, Bot, User, ArrowRight } from 'lucide-react'
import { api, type AIQueryResponse } from '../api/client'

interface AIPanelProps {
  isOpen: boolean
  onClose: () => void
  context?: { alert_id?: number; host_id?: string; hours?: number }
}

interface Message {
  role: 'user' | 'assistant'
  content: string
  response?: AIQueryResponse
}

export default function AIPanel({ isOpen, onClose, context }: AIPanelProps) {
  const [messages, setMessages] = useState<Message[]>([
    { role: 'assistant', content: 'Hello! I am your Analyst AI. Ask me about system health, current alerts, or provide an alert ID for deep dive analysis.' }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages, isOpen])

  // Automatically trigger a context-aware analysis if opened with a specific alert context and no existing messages
  useEffect(() => {
    if (isOpen && context?.alert_id && messages.length === 1) {
      handleSend(`Analyze alert ${context.alert_id}`)
    }
  }, [isOpen, context])

  const handleSend = async (text: string = input) => {
    if (!text.trim() || loading) return

    const userMsg: Message = { role: 'user', content: text }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const resp = await api.queryAI({
        question: text,
        alert_id: context?.alert_id,
        host_id: context?.host_id,
        hours: context?.hours || 24,
      })

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: resp.answer,
        response: resp
      }])
    } catch (error: any) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error: ${error.response?.data?.detail || error.message || 'Failed to query AI'}`
      }])
    } finally {
      setLoading(false)
    }
  }

  if (!isOpen) return null

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      right: 0,
      width: 400,
      height: '100vh',
      background: 'var(--bg)',
      borderLeft: '1px solid var(--border)',
      boxShadow: 'var(--shadow-lg)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 9999,
      animation: 'slideInRight 0.2s ease-out'
    }}>
      {/* Header */}
      <div style={{
        padding: '16px 20px',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'var(--bg-2)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent)' }}>
          <Sparkles size={18} />
          <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0, color: 'var(--text)' }}>AI Analyst</h2>
          {context?.alert_id && (
            <span className="badge badge-med" style={{ marginLeft: 8 }}>Alert {context.alert_id} context</span>
          )}
        </div>
        <button className="btn-ghost" onClick={onClose} style={{ padding: 4 }}>
          <X size={16} />
        </button>
      </div>

      {/* Messages */}
      <div className="scroll-y" style={{ flex: 1, padding: 20, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {messages.map((msg, idx) => (
          <div key={idx} style={{
            display: 'flex',
            gap: 12,
            flexDirection: msg.role === 'user' ? 'row-reverse' : 'row'
          }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              background: msg.role === 'user' ? 'var(--bg-3)' : 'var(--accent-bg)',
              color: msg.role === 'user' ? 'var(--text-2)' : 'var(--accent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0
            }}>
              {msg.role === 'user' ? <User size={14} /> : <Bot size={14} />}
            </div>

            <div style={{
              background: msg.role === 'user' ? 'var(--bg-3)' : 'transparent',
              padding: msg.role === 'user' ? '10px 14px' : '4px 0',
              borderRadius: 8,
              fontSize: 13,
              color: 'var(--text)',
              maxWidth: '85%',
              lineHeight: 1.5,
              whiteSpace: 'pre-wrap'
            }}>
              {msg.content}

              {/* Render AI specifics if present */}
              {msg.response && (
                <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {msg.response.citations && msg.response.citations.length > 0 && (
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {msg.response.citations.map((c, i) => (
                        <span key={i} className="tag" style={{ background: 'var(--bg-3)', color: 'var(--text-2)', fontSize: 10, cursor: 'pointer' }} title={c.route}>
                          {c.label}
                        </span>
                      ))}
                    </div>
                  )}

                  {msg.response.suggested_checks && msg.response.suggested_checks.length > 0 && (
                    <div style={{
                      background: 'var(--bg-2)',
                      border: '1px solid var(--border)',
                      borderRadius: 6,
                      padding: 12
                    }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-2)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        Suggested Actions
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {msg.response.suggested_checks.map((chk, i) => (
                          <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12, color: 'var(--text-2)' }}>
                            <ArrowRight size={12} style={{ marginTop: 2, color: 'var(--accent)' }} flexShrink={0} />
                            <span>{chk}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
        {loading && (
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--accent-bg)', color: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Bot size={14} />
            </div>
            <div style={{ padding: '4px 0' }}>
              <div className="spinner-sm" style={{ borderColor: 'var(--border-2)', borderTopColor: 'var(--accent)' }} />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div style={{ padding: 16, borderTop: '1px solid var(--border)', background: 'var(--bg)' }}>
        <form onSubmit={(e) => { e.preventDefault(); handleSend(); }} style={{ position: 'relative' }}>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={context?.alert_id ? `Ask about alert ${context.alert_id}...` : "Ask about system or threats..."}
            style={{
              width: '100%',
              padding: '12px 40px 12px 16px',
              borderRadius: 24,
              border: '1px solid var(--border-2)',
              background: 'var(--bg-2)',
              fontSize: 13
            }}
            disabled={loading}
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            style={{
              position: 'absolute',
              right: 8,
              top: 8,
              width: 28,
              height: 28,
              borderRadius: '50%',
              background: input.trim() && !loading ? 'var(--accent)' : 'transparent',
              color: input.trim() && !loading ? '#fff' : 'var(--text-3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}
          >
            <Send size={14} style={{ marginLeft: input.trim() && !loading ? -1 : 0 }} />
          </button>
        </form>
      </div>
    </div>
  )
}
