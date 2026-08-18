import { GitBranch, AlertTriangle } from 'lucide-react'

const nodeColors = {
  host: '#3b82f6',
  vulnerability: '#ef4444',
  service: '#f59e0b',
}

export default function AttackPathGraph({ paths }) {
  if (!paths || paths.length === 0) {
    return (
      <div className="text-center py-8 text-dark-500">
        <GitBranch className="w-8 h-8 mx-auto mb-2" />
        <p>No attack paths identified</p>
      </div>
    )
  }

  return (
    <div className="space-y-4 min-w-0">
      <h3 className="text-lg font-semibold text-white flex items-center gap-2">
        <GitBranch className="w-5 h-5" />
        Attack Paths ({paths.length})
      </h3>

      {paths.map((path, i) => (
        <div key={i} className="bg-dark-900 border border-dark-700 rounded-lg p-4 overflow-hidden">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
            <span className="text-sm font-medium text-white truncate">{path.path_id}</span>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span
                className={`px-2 py-0.5 text-xs rounded ${
                  path.risk_level === 'CRITICAL'
                    ? 'bg-red-500/20 text-red-400'
                    : path.risk_level === 'HIGH'
                    ? 'bg-orange-500/20 text-orange-400'
                    : 'bg-yellow-500/20 text-yellow-400'
                }`}
              >
                {path.risk_level}
              </span>
              <span className="text-sm text-dark-400">CVSS: {path.total_cvss}</span>
            </div>
          </div>

          {/* Visual path */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 -mx-1 px-1">
            {path.nodes.map((node, j) => (
              <div key={j} className="flex items-center gap-2 flex-shrink-0">
                <div
                  className="px-2 sm:px-3 py-1.5 sm:py-2 rounded-lg text-[10px] sm:text-xs font-medium text-white max-w-[140px] sm:max-w-[200px] truncate"
                  style={{ backgroundColor: nodeColors[node.type] || '#6b7280' }}
                  title={node.label}
                >
                  {node.type === 'vulnerability' && <AlertTriangle className="w-3 h-3 inline mr-1" />}
                  {node.label}
                </div>
                {j < path.nodes.length - 1 && (
                  <span className="text-dark-500 text-sm sm:text-lg">→</span>
                )}
              </div>
            ))}
          </div>

          {/* Edges as list */}
          <div className="mt-2 space-y-1">
            {path.edges.map((edge, j) => (
              <div key={j} className="text-xs text-dark-500 font-mono truncate">
                {edge.source.split(':')[1]} → {edge.target.split(':')[1]}
                {edge.label && <span className="text-dark-600"> ({edge.label})</span>}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
