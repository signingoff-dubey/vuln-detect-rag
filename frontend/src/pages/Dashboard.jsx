import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts'
import {
  Shield, AlertTriangle, TrendingUp, Activity, ChevronRight
} from 'lucide-react'
import { getStats, getHealth, startScan } from '../api/client'

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
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // New scan state
  const [targetUrl, setTargetUrl] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanError, setScanError] = useState('')

  const navigate = useNavigate()

  useEffect(() => {
    loadStats()
    loadHealth()
    const interval = setInterval(() => { loadStats(); loadHealth() }, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadHealth = async () => {
    try {
      const { data } = await getHealth()
      setHealth(data)
    } catch (err) {
      console.error('Failed to load health:', err)
    }
  }

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
    <div className="space-y-6 min-w-0">
      <div className="flex flex-col gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-dark-400 text-sm mt-1">Vulnerability scanning overview</p>
        </div>
        
        <form onSubmit={handleStartScan} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 bg-dark-900 border border-dark-700 p-3 rounded-xl focus-within:border-blue-500 transition-colors shadow-lg">
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <Shield className="w-5 h-5 text-dark-400 flex-shrink-0" />
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Enter target URL or IP (e.g., example.com)"
              className="bg-transparent border-none outline-none text-white text-sm w-full placeholder-dark-500"
              disabled={isScanning}
              required
            />
          </div>
          <button
            type="submit"
            disabled={isScanning || !targetUrl.trim()}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-dark-700 disabled:text-dark-400 rounded-lg text-sm font-medium text-white transition-colors flex items-center justify-center gap-2 flex-shrink-0"
          >
            {isScanning ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              'Start Scan'
            )}
          </button>
        </form>
        {scanError && (
          <div className="text-red-400 text-xs">{scanError}</div>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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
                  innerRadius={55}
                  outerRadius={80}
                  dataKey="value"
                  stroke="none"
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
                <Legend verticalAlign="bottom" height={36} wrapperStyle={{ color: '#94a3b8', fontSize: '12px' }}/>
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

        {/* System Health */}
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">System Health</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">Backend API</span>
              <span className={`px-2 py-0.5 text-xs rounded ${health ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                {health ? 'Online' : 'Offline'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">Nmap Scanner</span>
              <span className={`px-2 py-0.5 text-xs rounded ${health?.scanners?.nmap ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                {health?.scanners?.nmap ? 'Ready' : 'Mock Mode'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">Nuclei Scanner</span>
              <span className={`px-2 py-0.5 text-xs rounded ${health?.scanners?.nuclei ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                {health?.scanners?.nuclei ? 'Ready' : 'Mock Mode'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-dark-400">RAG Engine</span>
              <span className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded">Local Mode</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-dark-900 border border-dark-700 rounded-lg overflow-hidden">
        <div className="p-5 border-b border-dark-700">
          <h3 className="text-sm font-semibold text-white">Recent Scans</h3>
        </div>
        <div className="divide-y divide-dark-700">
          {stats?.recent_scans?.length > 0 ? (
            stats.recent_scans.map((scan) => (
              <div
                key={scan.id}
                className="px-5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-dark-800 cursor-pointer transition-colors"
                onClick={() => navigate(`/scans?scan=${scan.id}`)}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="text-sm font-medium text-white truncate">{scan.target}</div>
                  <span className={`px-2 py-0.5 text-xs rounded flex-shrink-0 ${statusColors[scan.status]}`}>
                    {scan.status}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs flex-shrink-0">
                  <span className="text-dark-400">
                    {scan.total_vulnerabilities} vulns
                  </span>
                  <span className="text-dark-500 hidden sm:inline">
                    {new Date(scan.started_at).toLocaleString()}
                  </span>
                  <ChevronRight className="w-4 h-4 text-dark-500" />
                </div>
              </div>
            ))
          ) : (
            <div className="p-8 text-center text-dark-500 text-sm">
              No scans yet. Start a scan from the dashboard or Scan Console.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
