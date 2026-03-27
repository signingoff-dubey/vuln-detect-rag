import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts'
import {
  Shield, AlertTriangle, TrendingUp, Activity, ChevronRight
} from 'lucide-react'
import { getStats } from '../api/client'

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

const statusColors = {
  completed: 'bg-green-500/20 text-green-400',
  running: 'bg-blue-500/20 text-blue-400',
  pending: 'bg-yellow-500/20 text-yellow-400',
  failed: 'bg-red-500/20 text-red-400',
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  
  // New scan state
  const [targetUrl, setTargetUrl] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanError, setScanError] = useState('')

  const navigate = useNavigate()

  useEffect(() => {
    loadStats()
    const interval = setInterval(loadStats, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadStats = async () => {
    try {
      const { data } = await getStats()
      setStats(data)
      setError(null)
    } catch (err) {
      console.error('Failed to load stats:', err)
      setError(err.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const handleStartScan = async (e) => {
    e.preventDefault()
    if (!targetUrl.trim()) return

    setIsScanning(true)
    setScanError('')
    
    try {
      const { startScan } = await import('../api/client')
      const { data } = await startScan(targetUrl, ['nmap', 'nuclei'])
      setTargetUrl('')
      navigate(`/scans?scan=${data.id}`)
    } catch (err) {
      setScanError(err.message || 'Failed to start scan')
    } finally {
      setIsScanning(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (error && !stats) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-dark-400">
        <AlertTriangle className="w-10 h-10 text-red-400 mb-3" />
        <p className="text-white font-semibold mb-1">Failed to load dashboard</p>
        <p className="text-sm mb-4">{error}</p>
        <button
          onClick={loadStats}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-white text-sm font-medium"
        >
          Retry
        </button>
      </div>
    )
  }

  const severityData = [
    { name: 'Critical', value: stats?.critical_vulns || 0, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: stats?.high_vulns || 0, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: stats?.medium_vulns || 0, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: stats?.low_vulns || 0, color: SEVERITY_COLORS.LOW },
  ].filter(d => d.value > 0)

  return (
    <div className="space-y-6">
      <div className="flex flex-col space-y-4 md:flex-row md:items-center md:justify-between md:space-y-0 relative">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-dark-400 text-sm mt-1">Vulnerability scanning overview</p>
        </div>
        
        <form onSubmit={handleStartScan} className="flex items-center relative gap-2 bg-dark-900 border border-dark-700 p-2 rounded-xl focus-within:border-blue-500 transition-colors shadow-lg">
          <Shield className="w-5 h-5 text-dark-400 ml-2" />
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="Enter target URL or IP (e.g., example.com)"
            className="bg-transparent border-none outline-none text-white text-sm px-2 w-64 placeholder-dark-500"
            disabled={isScanning}
            required
          />
          <button
            type="submit"
            disabled={isScanning || !targetUrl.trim()}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-dark-700 disabled:text-dark-400 rounded-lg text-sm font-medium text-white transition-colors flex items-center gap-2"
          >
            {isScanning ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              'Start Scan'
            )}
          </button>
        </form>
        {scanError && (
          <div className="absolute -bottom-6 right-0 text-red-400 text-xs">
            {scanError}
          </div>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
              <Activity className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_scans || 0}</div>
              <div className="text-xs text-dark-400">Total Scans</div>
            </div>
          </div>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-red-500/20 rounded-lg flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.total_vulnerabilities || 0}</div>
              <div className="text-xs text-dark-400">Vulnerabilities Found</div>
            </div>
          </div>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.critical_vulns || 0}</div>
              <div className="text-xs text-dark-400">Critical Vulnerabilities</div>
            </div>
          </div>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
              <TrendingUp className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <div className="text-2xl font-bold text-white">{stats?.avg_cvss || 0}</div>
              <div className="text-xs text-dark-400">Avg CVSS Score</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#f1f5f9',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-dark-500 text-sm">
              No data yet
            </div>
          )}
        </div>

        {/* Severity Bar Chart */}
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Vulnerability Count</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={severityData}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#f1f5f9',
                  }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-dark-500 text-sm">
              No data yet
            </div>
          )}
        </div>

        {/* Evaluation Metrics */}
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">System Health</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">Backend API</span>
              <span className="px-2 py-0.5 text-xs bg-green-500/20 text-green-400 rounded">Online</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">ChromaDB</span>
              <span className="px-2 py-0.5 text-xs bg-green-500/20 text-green-400 rounded">Ready</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">RAG Engine</span>
              <span className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded">Partial</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">Scanners</span>
              <span className="px-2 py-0.5 text-xs bg-green-500/20 text-green-400 rounded">Mock Mode</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-dark-900 border border-dark-700 rounded-lg">
        <div className="p-5 border-b border-dark-700">
          <h3 className="text-sm font-semibold text-white">Recent Scans</h3>
        </div>
        <div className="divide-y divide-dark-700">
          {stats?.recent_scans?.length > 0 ? (
            stats.recent_scans.map((scan) => (
              <div
                key={scan.id}
                className="px-5 py-3 flex items-center justify-between hover:bg-dark-800 cursor-pointer transition-colors"
                onClick={() => navigate(`/scans?scan=${scan.id}`)}
              >
                <div className="flex items-center gap-4">
                  <div className="text-sm font-medium text-white">{scan.target}</div>
                  <span className={`px-2 py-0.5 text-xs rounded ${statusColors[scan.status]}`}>
                    {scan.status}
                  </span>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-xs text-dark-400">
                    {scan.total_vulnerabilities} vulns
                  </span>
                  <span className="text-xs text-dark-500">
                    {new Date(scan.started_at).toLocaleString()}
                  </span>
                  <ChevronRight className="w-4 h-4 text-dark-500" />
                </div>
              </div>
            ))
          ) : (
            <div className="p-8 text-center text-dark-500 text-sm">
              No scans yet. Start a scan from the Scan Console.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
