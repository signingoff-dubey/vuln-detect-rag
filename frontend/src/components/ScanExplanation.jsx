import { useEffect, useState } from 'react'
import { FileText, AlertTriangle, RefreshCw, Cpu, Clock } from 'lucide-react'
import { explainScan, getBriefing, regenerateBriefing } from '../api/client'
import { Button, Callout, Card, CardHeader, EmptyState, Input } from './ui'
import { SkeletonText } from './Skeleton'

/**
 * Final step of the scan flow: a plain-language briefing on what the findings
 * mean, for a competent engineer who is not a security specialist.
 */
export default function ScanExplanation({ scan }) {
  const [explanation, setExplanation] = useState(null)
  const [generating, setGenerating] = useState(false)
  const [asking, setAsking] = useState(false)
  const [error, setError] = useState('')
  const [question, setQuestion] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)
  const scanId = scan.id
  const completed = scan.status === 'completed'

  useEffect(() => {
    setExplanation(null)
    setError('')
    setGenerating(false)
    setQuestion('')
  }, [scanId])

  useEffect(() => {
    if (!completed) return undefined
    let alive = true
    let timer = null

    const load = async () => {
      try {
        const { data } = await getBriefing(scanId)
        if (!alive) return
        if (data.status === 'ready') {
          setExplanation(data)
          setError('')
          setGenerating(false)
        } else if (data.status === 'failed') {
          setError(data.error || 'Failed to generate a briefing.')
          setGenerating(false)
        } else {
          setGenerating(true)
          timer = setTimeout(load, 3000)
        }
      } catch (err) {
        if (!alive) return
        setError(err.message || 'Failed to load the briefing.')
        setGenerating(false)
      }
    }
    load()
    return () => { alive = false; if (timer) clearTimeout(timer) }
  }, [scanId, completed, refreshKey])

  const regenerate = async () => {
    setError('')
    setExplanation(null)
    setGenerating(true)
    try {
      await regenerateBriefing(scanId)
      setRefreshKey((k) => k + 1)
    } catch (err) {
      setError(err.message || 'Failed to start a new briefing.')
      setGenerating(false)
    }
  }

  const ask = async (e) => {
    e.preventDefault()
    const q = question.trim()
    if (!q) return
    setAsking(true)
    setError('')
    try {
      const { data } = await explainScan(scanId, q)
      setExplanation(data)
      if (data.error) setError(data.error)
    } catch (err) {
      setError(err.message || 'Failed to answer the question.')
    } finally {
      setAsking(false)
    }
  }

  const loading = generating || asking

  if (scan.status !== 'completed') {
    return (
      <Card>
        <EmptyState icon={FileText} title="Available once the scan completes" />
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="Briefing"
          description={`What the ${scan.total_vulnerabilities} findings on ${scan.target} mean, and what to fix first.`}
        />
        <form onSubmit={ask} className="px-5 pb-5 flex flex-col sm:flex-row gap-2">
          <Input
            aria-label="Optional question about this scan"
            className="flex-1 min-w-0"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask something specific about this scan"
            disabled={loading}
          />
          <Button type="submit" variant="primary" loading={asking} icon={FileText} disabled={!question.trim() || generating}>
            {asking ? 'Answering…' : 'Ask'}
          </Button>
          <Button type="button" onClick={regenerate} loading={generating} icon={RefreshCw} disabled={asking}>
            {generating ? 'Writing…' : 'Regenerate'}
          </Button>
        </form>
      </Card>

      {error && (
        <Callout tone="crit" icon={AlertTriangle} title="Could not write a briefing" role="alert">{error}</Callout>
      )}

      {loading && !explanation && (
        <Card className="p-6" aria-busy="true">
          <SkeletonText lines={6} />
        </Card>
      )}

      {explanation && !error && (
        <Card>
          <div className="px-6 py-5 text-sm leading-relaxed whitespace-pre-wrap max-w-prose">
            {explanation.explanation}
          </div>
          <div className="px-6 py-3 border-t border-line flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-subtle">
            {explanation.llm_model && (
              <span className="flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="font-mono">{explanation.llm_provider} / {explanation.llm_model}</span>
              </span>
            )}
            {explanation.generation_ms > 0 && (
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" aria-hidden="true" />
                {(explanation.generation_ms / 1000).toFixed(1)}s
              </span>
            )}
            <span>{explanation.finding_count} findings analysed</span>
            {explanation.sources?.length > 0 && <span>{explanation.sources.length} sources retrieved</span>}
          </div>
        </Card>
      )}
    </div>
  )
}
