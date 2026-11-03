import { useState, useEffect } from 'react'
import { Plus, Trash2, AlertTriangle, Database, Cpu } from 'lucide-react'
import { chatRAG, getChatHistory, listSessions, deleteSession, getCVEStats, getLLMStatus, getRagConfig } from '../api/client'
import ChatPanel from '../components/ChatPanel'
import { Button, Callout, Card, IconButton, PageHeader, cx } from '../components/ui'

function sessionLabel(s) {
  const when = s.last_activity ? new Date(s.last_activity.replace(' ', 'T') + 'Z') : null
  return when && !Number.isNaN(when.getTime())
    ? when.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : s.session_id
}

export default function RAGAssistant() {
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState(`session_${Date.now()}`)
  const [sessions, setSessions] = useState([])
  const [cveCount, setCveCount] = useState(null)
  const [llmStatus, setLlmStatus] = useState(null)
  const [rag, setRag] = useState(null)

  useEffect(() => {
    loadSessions()
    getCVEStats()
      .then(({ data }) => setCveCount(Object.values(data).reduce((sum, n) => sum + n, 0)))
      .catch(() => setCveCount(null))
    getLLMStatus().then(({ data }) => setLlmStatus(data)).catch(() => setLlmStatus({ unreachable: true }))
    getRagConfig().then(({ data }) => setRag(data)).catch(() => setRag(null))
  }, [])

  const loadSessions = async () => {
    try { const { data } = await listSessions(); setSessions(data) } catch (err) { console.error(err) }
  }

  const loadSession = async (sid) => {
    setSessionId(sid)
    try {
      const { data } = await getChatHistory(sid)
      setMessages(data.map((m) => ({ role: m.role, content: m.content, sources: m.sources || [] })))
    } catch (err) { console.error(err) }
  }

  const handleSend = async (message) => {
    setMessages((prev) => [...prev, { role: 'user', content: message }])
    setLoading(true)
    try {
      const { data } = await chatRAG(message, sessionId)
      setMessages((prev) => [...prev, { role: 'assistant', content: data.answer, sources: data.sources }])
      loadSessions()
    } catch (err) {
      setMessages((prev) => [...prev, {
        role: 'assistant',
        error: true,
        content: err.message || 'The request failed. Check that the backend is running.',
        sources: [],
      }])
    } finally { setLoading(false) }
  }

  const clearChat = () => { setMessages([]); setSessionId(`session_${Date.now()}`) }

  const handleDeleteSession = async (sid) => {
    try {
      await deleteSession(sid)
      if (sid === sessionId) clearChat()
      loadSessions()
    } catch (err) { console.error(err) }
  }

  // Reports the model actually answering (usually a cloud provider), not
  // whether Ollama happens to be installed. Ollama is only the fallback.
  const activeModel = llmStatus?.active_provider
    ? `${llmStatus.active_provider} / ${llmStatus.active_model || 'default'}`
    : null
  const noModel = llmStatus && !llmStatus.unreachable && !llmStatus.active_provider

  return (
    <div className="flex-1 flex flex-col min-h-0 lg:h-[calc(100vh-4rem)]">
      <PageHeader
        title="Assistant"
        description="Answers come from the CVE knowledge base, with every citation checked against the retrieved text."
        actions={<Button size="sm" icon={Plus} onClick={clearChat}>New chat</Button>}
      />

      {noModel && (
        <Callout tone="warn" icon={AlertTriangle} title="No language model available" className="mb-4">
          Add an API key for Groq, Gemini, OpenRouter or NVIDIA in <code className="font-mono">backend/.env</code>, or start Ollama for offline use.
        </Callout>
      )}
      {llmStatus?.unreachable && (
        <Callout tone="crit" icon={AlertTriangle} title="Backend unreachable" className="mb-4">
          The assistant cannot answer until the API on port 8000 is running.
        </Callout>
      )}

      {/* The sidebar below is desktop-only, so narrower windows get a picker;
          without it past conversations were unreachable under 1024px. */}
      {sessions.length > 0 && (
        <div className="lg:hidden mb-3 flex items-center gap-2">
          <label htmlFor="session-picker" className="text-xs text-ink-subtle flex-shrink-0">Conversation</label>
          <select
            id="session-picker"
            value={sessions.some((s) => s.session_id === sessionId) ? sessionId : ''}
            onChange={(e) => (e.target.value ? loadSession(e.target.value) : clearChat())}
            className="flex-1 min-w-0 h-9 rounded-ctl border border-line bg-surface px-2 text-[13px]"
          >
            <option value="">New conversation</option>
            {sessions.map((s) => (
              <option key={s.session_id} value={s.session_id}>
                {sessionLabel(s)} · {s.message_count} messages
              </option>
            ))}
          </select>
        </div>
      )}

      <div className="flex gap-4 flex-1 min-h-[480px]">
        {sessions.length > 0 && (
          <Card as="aside" className="hidden lg:flex w-60 flex-shrink-0 flex-col overflow-hidden" aria-label="Past conversations">
            <p className="px-4 pt-4 pb-2 text-xs text-ink-subtle">Conversations</p>
            <ul className="flex-1 overflow-auto px-2 pb-2 space-y-0.5">
              {sessions.map((s) => {
                const active = s.session_id === sessionId
                return (
                  <li key={s.session_id} className="group relative">
                    <button
                      type="button"
                      onClick={() => loadSession(s.session_id)}
                      aria-current={active ? 'true' : undefined}
                      className={cx(
                        'w-full text-left pl-3 pr-9 py-2 rounded-ctl transition-colors duration-150',
                        active ? 'bg-accent-soft/60' : 'hover:bg-hover'
                      )}
                    >
                      <span className="block text-[13px] truncate">{sessionLabel(s)}</span>
                      <span className="block text-xs text-ink-subtle tabular">{s.message_count} messages</span>
                    </button>
                    <IconButton
                      size="sm"
                      icon={Trash2}
                      label="Delete conversation"
                      onClick={() => handleDeleteSession(s.session_id)}
                      className="absolute right-1 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:text-crit"
                    />
                  </li>
                )
              })}
            </ul>
          </Card>
        )}

        <Card className="flex-1 min-w-0 overflow-hidden flex flex-col">
          <ChatPanel messages={messages} onSend={handleSend} loading={loading} />
        </Card>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-subtle">
        <span className="flex items-center gap-1.5">
          <Database className="w-3.5 h-3.5" aria-hidden="true" />
          {cveCount !== null ? `${cveCount} CVEs indexed` : 'Index unavailable'}
          {rag && ` · retrieval ${rag.rag_enabled ? 'on' : 'off'}`}
        </span>
        {activeModel && (
          <span className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="font-mono">{activeModel}</span>
          </span>
        )}
      </div>
    </div>
  )
}
