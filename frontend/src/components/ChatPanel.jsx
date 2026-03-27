import { useState, useRef, useEffect } from 'react'
import { Send, Bot, User, Loader2, ExternalLink } from 'lucide-react'

export default function ChatPanel({ messages, onSend, loading }) {
  const [input, setInput] = useState('')
  const messagesEndRef = useRef(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!input.trim() || loading) return
    onSend(input.trim())
    setInput('')
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-dark-500">
            <Bot className="w-12 h-12 mb-3" />
            <h3 className="text-lg font-semibold">Vulnerability Assistant</h3>
            <p className="text-sm mt-1">Ask about CVEs, remediation steps, or exploit techniques</p>
            <div className="mt-4 space-y-2 text-sm">
              <p className="text-dark-400">Try asking:</p>
              <div className="flex flex-wrap gap-2 mt-2">
                {[
                  'What is CVE-2021-44228?',
                  'How to remediate Log4Shell?',
                  'List critical CVEs for Exchange Server',
                  'What are the attack vectors for Spring4Shell?',
                ].map((q) => (
                  <button
                    key={q}
                    onClick={() => onSend(q)}
                    className="px-3 py-1.5 bg-dark-800 border border-dark-600 rounded-lg text-dark-300 hover:bg-dark-700 hover:text-white transition-colors text-xs"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
            {msg.role === 'assistant' && (
              <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-blue-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <Bot className="w-4 h-4 text-white" />
              </div>
            )}
            <div
              className={`max-w-[80%] rounded-lg px-4 py-3 ${
                msg.role === 'user'
                  ? 'bg-blue-600 text-white'
                  : 'bg-dark-800 border border-dark-700 text-dark-100'
              }`}
            >
              <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
              {msg.sources?.length > 0 && (
                <div className="mt-3 pt-3 border-t border-dark-600 space-y-1">
                  <p className="text-[10px] uppercase font-semibold text-dark-400">Sources</p>
                  {msg.sources.map((s, j) => (
                    <div key={j} className="flex items-center gap-2 text-xs text-dark-400">
                      <ExternalLink className="w-3 h-3" />
                      <span className="font-mono">{s.cve_id || 'CVE'}</span>
                      <span className="text-dark-500">({(s.score * 100).toFixed(0)}% match)</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {msg.role === 'user' && (
              <div className="w-8 h-8 bg-dark-700 rounded-lg flex items-center justify-center flex-shrink-0">
                <User className="w-4 h-4 text-dark-300" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-blue-500 rounded-lg flex items-center justify-center">
              <Bot className="w-4 h-4 text-white" />
            </div>
            <div className="bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 flex items-center gap-3">
              <Loader2 className="w-4 h-4 animate-spin text-dark-400" />
              <span className="text-sm text-dark-400">Generating response... (Local LLMs may take 30-60s)</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSubmit} className="p-4 border-t border-dark-700">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about vulnerabilities, CVEs, remediation..."
            className="flex-1 bg-dark-800 border border-dark-600 rounded-lg px-4 py-2.5 text-sm text-white placeholder-dark-500 focus:outline-none focus:border-blue-500"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-4 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-dark-700 disabled:text-dark-500 rounded-lg transition-colors"
          >
            <Send className="w-4 h-4 text-white" />
          </button>
        </div>
      </form>
    </div>
  )
}
