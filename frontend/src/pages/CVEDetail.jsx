import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Shield, ExternalLink, Bug } from 'lucide-react'
import { getCVE } from '../api/client'
import { sanitizeUrl } from '../utils/sanitize'

const severityColors = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
}

export default function CVEDetail() {
  const { cveId } = useParams()
  const navigate = useNavigate()
  const [cve, setCve] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadCVE()
  }, [cveId])

  const loadCVE = async () => {
    setLoading(true)
    setError(null)
    try {
      const { data } = await getCVE(cveId)
      setCve(data)
    } catch (err) {
      setError(err.response?.data?.detail || 'CVE not found')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-dark-400 hover:text-white text-sm">
          <ArrowLeft className="w-4 h-4" /> Back
        </button>
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-12 text-center">
          <Shield className="w-12 h-12 text-dark-600 mx-auto mb-4" />
          <p className="text-lg text-red-400">{error}</p>
          <p className="text-sm text-dark-500 mt-2">{cveId} was not found in the database</p>
        </div>
      </div>
    )
  }

  const severityClass = severityColors[cve.severity] || severityColors.LOW

  return (
    <div className="space-y-6">
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-dark-400 hover:text-white text-sm">
        <ArrowLeft className="w-4 h-4" /> Back
      </button>

      <div className="bg-dark-900 border border-dark-700 rounded-lg p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-2xl font-bold text-white font-mono">{cve.cve_id}</h1>
              <span className={`px-2 py-1 text-xs font-semibold rounded border ${severityClass}`}>
                {cve.severity}
              </span>
              {cve.exploit_available && (
                <span className="px-2 py-1 text-xs bg-red-600 text-white rounded flex items-center gap-1">
                  <Bug className="w-3 h-3" /> EXPLOIT
                </span>
              )}
            </div>
            <p className="text-dark-400 text-sm">Source: {cve.source}</p>
          </div>
          <div className="text-right">
            <div className="text-4xl font-bold text-white">{cve.cvss_score}</div>
            <div className="text-xs text-dark-500 uppercase">CVSS Score</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-3">Description</h3>
          <p className="text-sm text-dark-300 leading-relaxed">{cve.description}</p>
        </div>
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-3">Remediation</h3>
          <p className="text-sm text-green-400 leading-relaxed">{cve.solution || 'No remediation info available'}</p>
        </div>
      </div>

      {cve.references?.length > 0 && (
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-3">References</h3>
          <div className="space-y-2">
            {cve.references.map((ref, i) => {
              const safeHref = sanitizeUrl(ref)
              return safeHref ? (
                <a key={i} href={safeHref} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300">
                  <ExternalLink className="w-4 h-4" /> {ref}
                </a>
              ) : (
                <span key={i} className="flex items-center gap-2 text-sm text-dark-500">
                  {ref}
                </span>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
