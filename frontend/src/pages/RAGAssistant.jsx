import { useState, useEffect } from 'react'
import { Bot, RefreshCw, Database, MessageSquare, Trash2, Cpu, AlertTriangle } from 'lucide-react'
import { chatRAG, getChatHistory, listSessions, deleteSession, getCVEStats, getLLMStatus } from '../api/client'
import ChatPanel from '../components/ChatPanel'

export default function RAGAssistant() {
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState(`session_${Date.now()}`)
  const [sessions, setSessions] = useState([])
  const [cveCount, setCveCount] = useState(0)
  const [llmStatus, setLlmStatus] = useState(null)

  useEffect(() => {
    loadSessions()
    loadCVECount()
    loadLLMStatus()
  }, [])

  const loadLLMStatus = async () => {
    try {
      const { data } = await getLLMStatus()
      setLlmStatus(data)
    } catch (err) {
      console.error(err)
      setLlmStatus({ available: false, model: '', provider: 'ollama', models: [] })
    }
  }

  const loadCVECount = async () => {
    try {
      const { data } = await getCVEStats()
      const total = Object.values(data).reduce((sum, count) => sum + count, 0)
      setCveCount(total)
    } catch (err) {
      console.error(err)
    }
  }

  const loadSessions = async () => {
    try {
      const { data } = await listSessions()
      setSessions(data)
    } catch (err) {
      console.error(err)
    }
  }

  const loadSession = async (sid) => {
    setSessionId(sid)
    try {
      const { data } = await getChatHistory(sid)
      setMessages(data.map(m => ({
        role: m.role,
        content: m.content,
        sources: m.sources || [],
      })))
    } catch (err) {
      console.error(err)
    }
  }

  const handleSend = async (message) => {
    setMessages((prev) => [...prev, { role: 'user', content: message }])
    setLoading(true)

    try {
      const { data } = await chatRAG(message, sessionId)
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: data.answer,
          sources: data.sources,
        },
      ])
      loadSessions()
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: 'Sorry, I encountered an error processing your request. Please make sure the backend is running.',
          sources: [],
        },
      ])
    } finally {
      setLoading(false)
    }
  }

  const clearChat = () => {
    setMessages([])
    setSessionId(`session_${Date.now()}`)
  }

  const handleDeleteSession = async (sid) => {
    try {
      await deleteSession(sid)
      if (sid === sessionId) clearChat()
      loadSessions()
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <div className="h-full flex flex-col min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-white">RAG Assistant</h1>
          <p className="text-dark-400 text-sm mt-1">
            AI-powered vulnerability intelligence
          </p>
        </div>
        <button
          onClick={clearChat}
          className="px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-sm text-dark-300 hover:text-white flex items-center gap-2 flex-shrink-0"
        >
          <RefreshCw className="w-4 h-4" />
          New Chat
        </button>
      </div>

      {/* LLM Status Banner */}
      {llmStatus && (
        <div className={`mb-4 px-4 py-3 rounded-lg border flex items-center gap-3 ${
          llmStatus.available
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
            : 'bg-red-500/10 border-red-500/30 text-red-400'
        }`}>
          {llmStatus.available ? (
            <>
              <Cpu className="w-5 h-5 flex-shrink-0" />
              <div className="min-w-0">
                <span className="font-medium">Local LLM Active: </span>
                <span className="font-mono text-sm">{llmStatus.model}</span>
                <span className="text-xs ml-2 opacity-70">via Ollama</span>
              </div>
            </>
          ) : (
            <>
              <AlertTriangle className="w-5 h-5 flex-shrink-0" />
              <div className="min-w-0">
                <span className="font-medium">No local LLM detected — </span>
                <span className="text-sm opacity-80">
                  Install Ollama and run <code className="bg-dark-800 px-1.5 py-0.5 rounded text-xs font-mono">ollama pull qwen2.5-coder:7b</code> for AI-powered answers
                </span>
              </div>
            </>
          )}
        </div>
      )}

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Session History Sidebar */}
        {sessions.length > 0 && (
          <div className="hidden lg:flex w-56 flex-shrink-0 bg-dark-900 border border-dark-700 rounded-lg flex-col">
            <div className="p-3 border-b border-dark-700">
              <h3 className="text-xs font-semibold text-dark-400 uppercase">Sessions</h3>
            </div>
            <div className="flex-1 overflow-auto divide-y divide-dark-700">
              {sessions.map((s) => (
                <div
                  key={s.session_id}
                  className={`px-3 py-2 flex items-center justify-between cursor-pointer hover:bg-dark-800 transition-colors ${
                    s.session_id === sessionId ? 'bg-dark-800' : ''
                  }`}
                  onClick={() => loadSession(s.session_id)}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <MessageSquare className="w-3 h-3 text-dark-500 flex-shrink-0" />
                    <span className="text-xs text-dark-300 truncate">
                      {s.message_count} messages
                    </span>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleDeleteSession(s.session_id) }}
                    className="text-dark-600 hover:text-red-400 flex-shrink-0"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Chat Panel */}
        <div className="flex-1 bg-dark-900 border border-dark-700 rounded-lg overflow-hidden">
          <ChatPanel messages={messages} onSend={handleSend} loading={loading} />
        </div>
      </div>

      {/* Info footer */}
      <div className="mt-3 flex items-center gap-4 text-xs text-dark-500">
        <div className="flex items-center gap-1">
          <Database className="w-3 h-3" />
          <span>Knowledge base: {cveCount} CVEs indexed</span>
        </div>
        <div className="flex items-center gap-1">
          <Cpu className="w-3 h-3" />
          <span>
            {llmStatus?.available
              ? `RAG with ChromaDB + ${llmStatus.model} (Ollama)`
              : 'RAG with ChromaDB (no LLM — fallback mode)'}
          </span>
        </div>
      </div>
    </div>
  )
}
