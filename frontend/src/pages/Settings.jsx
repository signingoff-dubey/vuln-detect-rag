import { useState, useEffect } from 'react'
import { getBackendLogs, getLLMStatus, getHealth } from '../api/client'
import { RefreshCw, Download, FileText, Settings as SettingsIcon, Cpu, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

export default function Settings() {
  const [logs, setLogs] = useState('')
  const [loading, setLoading] = useState(false)
  const [llmStatus, setLlmStatus] = useState(null)
  const [healthData, setHealthData] = useState(null)
  
  const fetchLogs = async () => {
    setLoading(true)
    try {
      const { data } = await getBackendLogs()
      setLogs(data.logs || 'No logs available yet.')
    } catch (err) {
      setLogs(`Error fetching logs: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const fetchStatus = async () => {
    try {
      const [llmRes, healthRes] = await Promise.all([
        getLLMStatus(),
        getHealth(),
      ])
      setLlmStatus(llmRes.data)
      setHealthData(healthRes.data)
    } catch (err) {
      console.error('Failed to fetch status:', err)
    }
  }

  useEffect(() => {
    fetchLogs()
    fetchStatus()
    
    // Auto refresh logs every 5 seconds
    const interval = setInterval(fetchLogs, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-6 flex flex-col h-full min-h-0 min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 border-b border-dark-700/50 pb-4">
        <div className="p-2 bg-purple-500/20 rounded-lg flex-shrink-0 self-start">
          <SettingsIcon className="w-6 h-6 text-purple-400" />
        </div>
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-sm text-dark-400">Platform configuration and logs</p>
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* LLM Status Card */}
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <Cpu className="w-5 h-5 text-purple-400" />
            <h3 className="font-medium text-white">Local LLM Status</h3>
          </div>
          {llmStatus ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                {llmStatus.available ? (
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                )}
                <span className={llmStatus.available ? 'text-emerald-400' : 'text-red-400'}>
                  {llmStatus.available ? 'Connected' : 'No local LLM detected'}
                </span>
              </div>
              {llmStatus.available && (
                <>
                  <div className="text-sm text-dark-300">
                    <span className="text-dark-500">Model:</span>{' '}
                    <code className="bg-dark-800 px-1.5 py-0.5 rounded text-xs font-mono text-blue-400">
                      {llmStatus.model}
                    </code>
                  </div>
                  <div className="text-sm text-dark-300">
                    <span className="text-dark-500">Provider:</span> Ollama
                  </div>
                </>
              )}
              {llmStatus.models && llmStatus.models.length > 0 && (
                <div className="text-sm text-dark-300">
                  <span className="text-dark-500">Installed models:</span>{' '}
                  {llmStatus.models.join(', ')}
                </div>
              )}
              {!llmStatus.available && (
                <p className="text-xs text-dark-500 mt-2">
                  Run <code className="bg-dark-800 px-1 py-0.5 rounded font-mono">ollama pull qwen2.5-coder:7b</code> to install
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-dark-500">Loading...</p>
          )}
        </div>

        {/* Scanner Status Card */}
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <SettingsIcon className="w-5 h-5 text-blue-400" />
            <h3 className="font-medium text-white">Scanner Status</h3>
          </div>
          {healthData ? (
            <div className="space-y-2">
              {Object.entries(healthData.scanners || {}).map(([name, available]) => (
                <div key={name} className="flex items-center gap-2">
                  {available ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <XCircle className="w-4 h-4 text-dark-600" />
                  )}
                  <span className={`text-sm ${available ? 'text-dark-200' : 'text-dark-500'}`}>
                    {name}
                  </span>
                </div>
              ))}
              <div className="text-xs text-dark-500 mt-2">
                Version: {healthData.version}
              </div>
            </div>
          ) : (
            <p className="text-sm text-dark-500">Loading...</p>
          )}
        </div>
      </div>

      {/* Log Viewer */}
      <div className="flex-1 flex flex-col bg-dark-900 border border-dark-700 rounded-lg overflow-hidden min-h-0">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 border-b border-dark-700 glass gap-3">
          <div className="flex items-center gap-2 text-white font-medium">
            <FileText className="w-5 h-5 text-dark-300 flex-shrink-0" />
            <span>Backend Live Logs</span>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            <button
              onClick={fetchLogs}
              disabled={loading}
              className="px-3 py-1.5 bg-dark-800 hover:bg-dark-700 text-dark-200 text-sm font-medium rounded-lg transition-colors flex items-center gap-2 border border-dark-600"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button
              onClick={() => {
                const blob = new Blob([logs], { type: 'text/plain' })
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = 'vulndetect-backend.log'
                a.click()
              }}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              Download
            </button>
          </div>
        </div>
        
        <div className="flex-1 overflow-auto bg-[#0d1117] p-4 text-xs font-mono text-gray-300 leading-relaxed min-h-0">
          <pre className="whitespace-pre-wrap break-all overflow-hidden">
            {logs}
          </pre>
        </div>
      </div>
    </div>
  )
}
