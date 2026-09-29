import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Card } from './ui'

const parseStart = (value) => {
  if (!value) return null
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value}Z`
  const ms = Date.parse(iso)
  return Number.isNaN(ms) ? null : ms
}

const formatElapsed = (seconds) => {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return m > 0 ? `${m}m ${String(s).padStart(2, '0')}s` : `${s}s`
}

export default function ScanProgress({ scan }) {
  const [now, setNow] = useState(() => Date.now())
  const active = scan && (scan.status === 'pending' || scan.status === 'running')

  useEffect(() => {
    if (!active) return undefined
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [active])

  if (!active) return null

  const start = parseStart(scan.started_at)
  const elapsed = start ? Math.max(0, Math.round((now - start) / 1000)) : 0
  const progress = Math.min(100, Math.max(scan.progress || 0, 3))
  const label = scan.status === 'pending'
    ? 'Queued'
    : scan.current_scanner
      ? `Running ${scan.current_scanner}`
      : 'Starting'

  return (
    <Card className="p-4" role="status" aria-live="polite">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Loader2 className="w-4 h-4 animate-spin text-accent shrink-0" aria-hidden="true" />
          <span className="text-sm font-medium truncate">{label}</span>
        </div>
        <span className="text-xs text-ink-subtle tabular shrink-0">
          {formatElapsed(elapsed)} · {scan.progress || 0}%
        </span>
      </div>
      <div className="mt-3 h-1.5 rounded-full bg-hover overflow-hidden">
        <div
          className="h-full rounded-full bg-accent transition-[width] duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-ink-muted">
        Scanning is in progress. This page refreshes automatically and results appear as each scanner finishes.
      </p>
    </Card>
  )
}
