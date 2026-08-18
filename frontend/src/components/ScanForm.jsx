import { useState } from 'react'
import { Play, Loader2, Star } from 'lucide-react'

const scanners = [
  { id: 'nmap', label: 'Nmap', desc: 'Port scanning & service detection' },
  { id: 'nuclei', label: 'Nuclei', desc: 'Template-based vulnerability scanning' },
  { id: 'openvas', label: 'OpenVAS', desc: 'Comprehensive vulnerability assessment' },
  { id: 'nessus', label: 'Nessus', desc: 'Enterprise vulnerability scanner' },
]

export default function ScanForm({ onStartScan, loading, onAddFavorite }) {
  const [target, setTarget] = useState('')
  const [selected, setSelected] = useState(['nmap', 'nuclei'])

  const toggleScanner = (id) => {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
    )
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!target.trim() || selected.length === 0) return
    onStartScan(target.trim(), selected)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-dark-300 mb-2">
          Target Domain or IP
        </label>
        <div className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g., example.com or 192.168.1.1"
            className="flex-1 min-w-0 bg-dark-800 border border-dark-600 rounded-lg px-4 py-3 text-white placeholder-dark-500 focus:outline-none focus:border-blue-500"
            disabled={loading}
          />
          {target.trim() && onAddFavorite && (
            <button
              type="button"
              onClick={() => onAddFavorite(target.trim())}
              className="px-3 bg-dark-800 border border-dark-600 rounded-lg text-dark-400 hover:text-yellow-400 transition-colors flex-shrink-0"
              title="Save to favorites"
            >
              <Star className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-dark-300 mb-2">
          Select Scanners
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 sm:gap-3">
          {scanners.map((s) => (
            <label
              key={s.id}
              className={`flex items-center gap-3 p-2.5 sm:p-3 rounded-lg border cursor-pointer transition-colors ${
                selected.includes(s.id)
                  ? 'bg-blue-500/10 border-blue-500/50 text-white'
                  : 'bg-dark-800 border-dark-600 text-dark-400 hover:border-dark-500'
              }`}
            >
              <input
                type="checkbox"
                checked={selected.includes(s.id)}
                onChange={() => toggleScanner(s.id)}
                className="sr-only"
              />
              <div
                className={`w-4 h-4 rounded border-2 flex items-center justify-center flex-shrink-0 ${
                  selected.includes(s.id)
                    ? 'bg-blue-500 border-blue-500'
                    : 'border-dark-500'
                }`}
              >
                {selected.includes(s.id) && (
                  <svg className="w-3 h-3 text-white" viewBox="0 0 12 12">
                    <path
                      d="M10 3L4.5 8.5 2 6"
                      stroke="currentColor"
                      strokeWidth="2"
                      fill="none"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </div>
              <div className="min-w-0">
                <div className="text-sm font-medium">{s.label}</div>
                <div className="text-[11px] text-dark-500 truncate">{s.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <button
        type="submit"
        disabled={loading || !target.trim() || selected.length === 0}
        className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-dark-700 disabled:text-dark-500 rounded-lg font-medium transition-colors"
      >
        {loading ? (
          <>
            <Loader2 className="w-5 h-5 animate-spin" />
            Scanning...
          </>
        ) : (
          <>
            <Play className="w-5 h-5" />
            Start Scan
          </>
        )}
      </button>
    </form>
  )
}
