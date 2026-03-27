import { useState, useEffect } from 'react'
import { getBackendLogs } from '../api/client'
import { RefreshCw, Download, FileText, Settings as SettingsIcon } from 'lucide-react'

export default function Settings() {
  const [logs, setLogs] = useState('')
  const [loading, setLoading] = useState(false)
  
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

  useEffect(() => {
    fetchLogs()
    
    // Auto refresh logs every 5 seconds
    const interval = setInterval(fetchLogs, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-6 flex flex-col h-full max-h-[calc(100vh-3rem)]">
      <div className="flex items-center gap-3 border-b border-dark-700/50 pb-4">
        <div className="p-2 bg-purple-500/20 rounded-lg">
          <SettingsIcon className="w-6 h-6 text-purple-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-sm text-dark-400">Platform configuration and logs</p>
        </div>
      </div>

      <div className="flex-1 flex flex-col bg-dark-900 border border-dark-700 rounded-lg overflow-hidden min-h-0">
        <div className="flex items-center justify-between p-4 border-b border-dark-700 glass">
          <div className="flex items-center gap-2 text-white font-medium">
            <FileText className="w-5 h-5 text-dark-300" />
            Backend Live Logs
          </div>
          <div className="flex items-center gap-3">
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
        
        <div className="flex-1 overflow-auto bg-[#0d1117] p-4 text-xs font-mono text-gray-300 leading-relaxed">
          <pre className="whitespace-pre-wrap breakdown-all">
            {logs}
          </pre>
        </div>
      </div>
    </div>
  )
}
