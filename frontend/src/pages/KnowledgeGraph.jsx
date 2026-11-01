import { useState, useEffect, useCallback } from 'react'
import { Search, AlertTriangle, ExternalLink, Info, Crosshair } from 'lucide-react'
import { getGraphStats, getGraphChain, searchGraph } from '../api/client'
import { Badge, Button, Callout, Card, CardHeader, Input, PageHeader } from '../components/ui'
import { SkeletonRegion, SkeletonCard } from '../components/Skeleton'
import { sanitizeUrl } from '../utils/sanitize'

// Lanes rather than a force-directed graph: the relationship is a fixed
// four-stage walk, and a hairball hides exactly the structure worth showing.
const LAYERS = [
  { key: 'cve', label: 'Vulnerability', sub: 'CVE' },
  { key: 'weaknesses', label: 'Weakness class', sub: 'CWE' },
  { key: 'patterns', label: 'Attack patterns', sub: 'CAPEC' },
  { key: 'techniques', label: 'Adversary techniques', sub: 'ATT&CK' },
]

const KIND_LABEL = { cve: 'CVE', cwe: 'CWE', capec: 'CAPEC', attack: 'ATT&CK' }
const fmt = (n) => (typeof n === 'number' ? n.toLocaleString() : n)

export default function KnowledgeGraph() {
  const [stats, setStats] = useState(null)
  const [query, setQuery] = useState('CVE-2021-44228')
  const [chain, setChain] = useState(null)
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getGraphStats()
      .then(({ data }) => setStats(data))
      .catch((err) => setError(err.message || 'Failed to read graph status'))
  }, [])

  const runLookup = useCallback(async (term) => {
    const value = (term || '').trim()
    if (!value) return
    setLoading(true)
    setError('')
    setChain(null)
    setResults([])
    try {
      if (/^CVE-\d{4}-\d{4,}$/i.test(value)) {
        const { data } = await getGraphChain(value.toUpperCase())
        setChain(data)
        if (!data.found) setError(`${value.toUpperCase()} is not in the graph.`)
      } else {
        const { data } = await searchGraph(value)
        setResults(data.results || [])
        if (!data.results?.length) setError(`Nothing matched "${value}".`)
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Lookup failed')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { runLookup('CVE-2021-44228') }, [runLookup])

  const graphMissing = stats && !stats.loaded

  return (
    <div className="space-y-6">
      <PageHeader
        title="Knowledge graph"
        description="Trace a CVE to its weakness, attack patterns and ATT&CK techniques. Every edge is a published MITRE or NVD cross-reference."
      />

      {graphMissing && (
        <Callout tone="warn" icon={AlertTriangle} title="Graph not built">
          <p className="mb-2">{stats.error}</p>
          <pre className="text-xs bg-surface border border-line rounded-ctl p-2.5 overflow-x-auto">
python scripts/fetch_datasets.py{'\n'}python scripts/build_knowledge_graph.py
          </pre>
        </Callout>
      )}

      <Card>
        <form
          onSubmit={(e) => { e.preventDefault(); runLookup(query) }}
          className="p-4 flex flex-col sm:flex-row gap-2"
          role="search"
        >
          <Input
            icon={Search}
            aria-label="CVE, CWE or keyword"
            className="flex-1 min-w-0"
            inputClassName="font-mono"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="CVE-2021-44228, CWE-502, or a keyword like deserialization"
          />
          <Button type="submit" variant="primary" icon={Crosshair} loading={loading} disabled={!query.trim()}>
            Trace
          </Button>
        </form>
        {stats?.loaded && (
          <p className="px-4 pb-3 -mt-1 text-xs text-ink-subtle tabular">
            {fmt(stats.nodes)} nodes · {fmt(stats.edges)} edges · {fmt(stats.meta?.kinds?.cwe ?? 0)} weaknesses ·{' '}
            {fmt(stats.meta?.kinds?.capec ?? 0)} patterns · {fmt(stats.meta?.kinds?.attack ?? 0)} techniques
          </p>
        )}
      </Card>

      {error && !loading && <Callout icon={Info}>{error}</Callout>}

      {loading && (
        <SkeletonRegion label="Tracing" className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {LAYERS.map((l) => <SkeletonCard key={l.key} lines={3} />)}
        </SkeletonRegion>
      )}

      {results.length > 0 && (
        <Card>
          <CardHeader title={`${results.length} matches`} />
          <ul className="border-t border-line divide-y divide-line max-h-[480px] overflow-y-auto">
            {results.map((node) => (
              <li key={node.id}>
                <button
                  type="button"
                  onClick={() => { if (node.kind === 'cve') { setQuery(node.id); runLookup(node.id) } }}
                  disabled={node.kind !== 'cve'}
                  className="w-full text-left px-5 py-3 enabled:hover:bg-hover disabled:cursor-default"
                >
                  <div className="flex items-center gap-2 mb-0.5 min-w-0">
                    <Badge>{KIND_LABEL[node.kind] || node.kind}</Badge>
                    <span className="font-mono text-[13px] font-medium">{node.id}</span>
                    <span className="text-[13px] truncate">{node.name}</span>
                  </div>
                  {node.description && <p className="text-xs text-ink-muted line-clamp-2 max-w-prose">{node.description}</p>}
                </button>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {chain?.found && (
        <>
          {chain.weaknesses.length === 0 && (
            <Callout icon={Info} title={`${chain.cve} carries no CWE assignment`}>
              NVD has not assigned a weakness to this CVE, so there is no path onward to attack patterns or
              techniques. This is a gap in the published data, not a lookup failure.
            </Callout>
          )}

          <ol className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {LAYERS.map((layer, idx) => {
              const items = layer.key === 'cve'
                ? [{ id: chain.cve, name: 'Reported vulnerability' }]
                : chain[layer.key] || []
              return (
                <li key={layer.key} className="min-w-0">
                  <Card className="h-full">
                    <div className="px-4 pt-4 pb-2 flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="w-5 h-5 rounded-full bg-accent-soft text-accent-text text-2xs font-semibold flex items-center justify-center flex-shrink-0">
                          {idx + 1}
                        </span>
                        <h3 className="text-[13px] font-semibold truncate">{layer.label}</h3>
                      </div>
                      <span className="text-xs text-ink-subtle tabular">{layer.sub} · {items.length}</span>
                    </div>
                    {items.length === 0 ? (
                      <p className="px-4 pb-4 text-[13px] text-ink-subtle">None mapped</p>
                    ) : (
                      <ul className="divide-y divide-line border-t border-line">
                        {items.map((item) => (
                          <li key={item.id} className="px-4 py-2.5">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-xs font-medium">{item.id}</span>
                              {item.severity && <span className="text-2xs text-ink-subtle">{item.severity}</span>}
                              {item.url && sanitizeUrl(item.url) && (
                                <a
                                  href={sanitizeUrl(item.url)}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  aria-label={`${item.id} on MITRE`}
                                  className="ml-auto text-ink-subtle hover:text-accent-text"
                                >
                                  <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                                </a>
                              )}
                            </div>
                            <p className="text-[13px] leading-snug mt-0.5">{item.name}</p>
                            {item.tactics?.length > 0 && (
                              <p className="text-xs text-ink-subtle mt-0.5">{item.tactics.join(', ')}</p>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </Card>
                </li>
              )
            })}
          </ol>

          {(chain.truncated?.patterns > 0 || chain.truncated?.techniques > 0) && (
            <p className="text-xs text-ink-subtle">
              {chain.truncated.patterns} further patterns and {chain.truncated.techniques} further techniques were
              reached but not shown.
            </p>
          )}

          {chain.tactics?.length > 0 && (
            <Card>
              <CardHeader title="ATT&CK tactics reachable from this vulnerability" />
              <div className="px-5 pb-5 flex flex-wrap gap-2">
                {chain.tactics.map((tactic) => (
                  <Badge key={tactic} tone="accent" className="capitalize">{tactic.replace(/-/g, ' ')}</Badge>
                ))}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
