import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Bug, ExternalLink } from 'lucide-react'
import { searchCVEs } from '../api/client'

const severityColors = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-blue-400',
}

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function CVEBrowse() {
  const navigate = useNavigate()
  const [cves, setCves] = useState([])
  const [loading, setLoading] = useState(false)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('')
  const [exploitOnly, setExploitOnly] = useState(false)

  useEffect(() => {
    searchCVE()
  }, [severity, exploitOnly])

  const searchCVE = async () => {
    setLoading(true)
    try {
      const { data } = await searchCVEs(query, severity, exploitOnly)
      setCves(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleSearch = (e) => {
    e.preventDefault()
    searchCVE()
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">CVE Database</h1>
        <p className="text-dark-400 text-sm mt-1">Browse and search known vulnerabilities</p>
      </div>

      <div className="flex flex-col gap-3">
        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search CVE descriptions..."
            className="flex-1 min-w-0 bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-dark-500 focus:outline-none focus:border-blue-500"
          />
          <button type="submit" className="px-4 py-2.5 bg-blue-600 hover:bg-blue-500 rounded-lg text-white flex-shrink-0">
            <Search className="w-4 h-4" />
          </button>
        </form>

        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((s) => (
            <button
              key={s || 'all'}
              onClick={() => setSeverity(s)}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                severity === s ? 'bg-blue-600 text-white' : 'bg-dark-900 border border-dark-700 text-dark-400 hover:text-white'
              }`}
            >
              {s || 'ALL'}
            </button>
          ))}

          <button
            onClick={() => setExploitOnly(!exploitOnly)}
            className={`px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors ${
              exploitOnly ? 'bg-red-600 text-white' : 'bg-dark-900 border border-dark-700 text-dark-400 hover:text-white'
            }`}
          >
            <Bug className="w-3 h-3" /> Exploits
          </button>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-lg divide-y divide-dark-700">
        {loading ? (
          <div className="p-8 text-center">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" />
          </div>
        ) : cves.length > 0 ? (
          cves.map((cve) => (
            <div
              key={cve.id}
              onClick={() => navigate(`/cve/${cve.cve_id}`)}
              className="px-5 py-4 flex items-center justify-between hover:bg-dark-800 cursor-pointer transition-colors"
            >
              <div className="flex items-center gap-4 flex-1 min-w-0">
                <span className={`text-sm font-semibold font-mono ${severityColors[cve.severity] || 'text-dark-400'}`}>
                  {cve.cve_id}
                </span>
                <span className="text-sm text-dark-300 truncate">{cve.description}</span>
                {cve.exploit_available && (
                  <span className="px-1.5 py-0.5 text-[10px] bg-red-600 text-white rounded flex-shrink-0">EXPLOIT</span>
                )}
              </div>
              <div className="flex items-center gap-4 ml-4">
                <span className="text-lg font-bold text-white">{cve.cvss_score}</span>
                <ExternalLink className="w-4 h-4 text-dark-500" />
              </div>
            </div>
          ))
        ) : (
          <div className="p-8 text-center text-dark-500 text-sm">No CVEs found</div>
        )}
      </div>

      <div className="text-xs text-dark-500 text-center">{cves.length} results</div>
    </div>
  )
}
