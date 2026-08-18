import { BarChart3 } from 'lucide-react'

const colorMap = {
  green: 'bg-green-500',
  blue: 'bg-blue-500',
  purple: 'bg-purple-500',
}

export default function MetricsPanel({ metrics }) {
  if (!metrics) {
    return (
      <div className="text-center py-8 text-dark-500">
        <BarChart3 className="w-8 h-8 mx-auto mb-2" />
        <p>No evaluation metrics available</p>
      </div>
    )
  }

  const metricItems = [
    { label: 'CVE Detection F1', value: metrics.detection_f1, color: 'green' },
    { label: 'BLEU Score', value: metrics.bleu, color: 'blue' },
    { label: 'ROUGE Score', value: metrics.rouge, color: 'purple' },
  ]

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold text-white flex items-center gap-2">
        <BarChart3 className="w-5 h-5" />
        Evaluation Metrics
      </h3>

      <div className="grid grid-cols-3 gap-4">
        {metricItems.map(({ label, value, color }) => (
          <div key={label} className="bg-dark-900 border border-dark-700 rounded-lg p-4">
            <div className="text-xs text-dark-400 uppercase font-semibold mb-2">{label}</div>
            <div className="text-3xl font-bold text-white">{((value || 0) * 100).toFixed(1)}%</div>
            <div className="mt-2 h-2 bg-dark-700 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${colorMap[color]}`}
                style={{ width: `${(value || 0) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
