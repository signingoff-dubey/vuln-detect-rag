import { useState } from 'react'
import { AlertTriangle, Shield, Download, Filter } from 'lucide-react'
import { exportScan } from '../api/client'
import VulnerabilityCard from './VulnerabilityCard'

const SEVERITY_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const severityColors = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-blue-400',
  INFO: 'text-gray-400',
}

export default function ScanResults({ scan, vulnerabilities }) {
  const [severityFilter, setSeverityFilter] = useState('ALL')

  if (!scan) return null

  if (scan.status === 'pending' || scan.status === 'running') {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-dark-400">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-4" />
        <p className="text-lg font-medium">Scanning {scan.target}...</p>
        <p className="text-sm mt-1">
          {scan.current_scanner ? `Running ${scan.current_scanner}...` : 'This may take a few minutes'}
        </p>
        <div className="w-64 mt-4">
          <div className="flex justify-between text-xs text-dark-500 mb-1">
            <span>Progress</span>
            <span>{scan.progress || 0}%</span>
          </div>
          <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${scan.progress || 0}%` }}
            />
          </div>
        </div>
      </div>
    )
  }

  if (scan.status === 'failed') {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-red-400 px-4">
        <AlertTriangle className="w-8 h-8 mb-4" />
        <p className="text-lg font-medium">Scan Failed</p>
        <p className="text-sm mt-1 text-dark-400 text-center max-w-lg break-words overflow-hidden">{scan.error_message}</p>
      </div>
    )
  }

  const filteredVulns = severityFilter === 'ALL'
    ? vulnerabilities
    : vulnerabilities.filter(v => v.severity === severityFilter)

  const handleExport = async (format) => {
    try {
      const response = await exportScan(scan.id, format)
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = `scan_${scan.id}.${format}`
      link.click()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Export failed:', err)
    }
  }

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-3 sm:p-4">
          <div className="text-[10px] sm:text-xs text-dark-400 uppercase font-semibold">Total</div>
          <div className="text-xl sm:text-2xl font-bold text-white mt-1">{scan.total_vulnerabilities}</div>
        </div>
        <div className="bg-dark-900 border border-red-500/20 rounded-lg p-3 sm:p-4">
          <div className="text-[10px] sm:text-xs text-red-400 uppercase font-semibold">Critical</div>
          <div className="text-xl sm:text-2xl font-bold text-red-400 mt-1">{scan.critical_count}</div>
        </div>
        <div className="bg-dark-900 border border-orange-500/20 rounded-lg p-3 sm:p-4">
          <div className="text-[10px] sm:text-xs text-orange-400 uppercase font-semibold">High</div>
          <div className="text-xl sm:text-2xl font-bold text-orange-400 mt-1">{scan.high_count}</div>
        </div>
        <div className="bg-dark-900 border border-yellow-500/20 rounded-lg p-3 sm:p-4">
          <div className="text-[10px] sm:text-xs text-yellow-400 uppercase font-semibold">Medium</div>
          <div className="text-xl sm:text-2xl font-bold text-yellow-400 mt-1">{scan.medium_count}</div>
        </div>
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-3 sm:p-4 col-span-2 sm:col-span-1">
          <div className="text-[10px] sm:text-xs text-dark-400 uppercase font-semibold">Avg CVSS</div>
          <div className="text-xl sm:text-2xl font-bold text-white mt-1">{scan.avg_cvss}</div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="w-4 h-4 text-dark-400 flex-shrink-0" />
          {SEVERITY_OPTIONS.map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`px-2.5 py-1.5 rounded text-[11px] sm:text-xs font-medium transition-colors ${
                severityFilter === s
                  ? 'bg-blue-600 text-white'
                  : 'bg-dark-800 text-dark-400 hover:text-white'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="flex gap-2 flex-shrink-0">
          <button
            onClick={() => handleExport('json')}
            className="px-3 py-1.5 bg-dark-800 border border-dark-600 rounded text-xs text-dark-300 hover:text-white flex items-center gap-1.5"
          >
            <Download className="w-3 h-3" /> JSON
          </button>
          <button
            onClick={() => handleExport('csv')}
            className="px-3 py-1.5 bg-dark-800 border border-dark-600 rounded text-xs text-dark-300 hover:text-white flex items-center gap-1.5"
          >
            <Download className="w-3 h-3" /> CSV
          </button>
        </div>
      </div>

      {/* Vulnerability List */}
      <div className="space-y-3">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Vulnerabilities ({filteredVulns.length})
        </h3>
        {filteredVulns.map((vuln) => (
          <VulnerabilityCard key={vuln.id} vuln={vuln} />
        ))}
        {filteredVulns.length === 0 && (
          <div className="text-center py-8 text-dark-500 text-sm">
            No {severityFilter !== 'ALL' ? severityFilter.toLowerCase() : ''} vulnerabilities found
          </div>
        )}
      </div>
    </div>
  )
}
