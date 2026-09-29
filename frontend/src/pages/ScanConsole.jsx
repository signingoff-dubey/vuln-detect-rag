import { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { History, RefreshCw, Star, X, Radar, AlertTriangle } from 'lucide-react'
import {
  startScan, getScanResults, getAttackPaths, listScans, getFavorites, addFavorite, deleteFavorite, getHealth,
} from '../api/client'
import ScanForm from '../components/ScanForm'
import ScanResults from '../components/ScanResults'
import AttackPathGraph from '../components/AttackPathGraph'
import ScanExplanation from '../components/ScanExplanation'
import ScanProgress from '../components/ScanProgress'
import {
  Button, Callout, Card, CardHeader, IconButton, PageHeader, Segmented, StatusBadge, EmptyState, cx,
} from '../components/ui'

export default function ScanConsole() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [scanning, setScanning] = useState(false)
  const [currentScan, setCurrentScan] = useState(null)
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [attackPaths, setAttackPaths] = useState([])
  const [scanHistory, setScanHistory] = useState([])
  const [favorites, setFavorites] = useState([])
  const [activeTab, setActiveTab] = useState('results')
  const [scanError, setScanError] = useState('')
  const [health, setHealth] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [historyError, setHistoryError] = useState('')
  const pollRef = useRef(null)

  useEffect(() => {
    loadHistory()
    loadFavorites()
    getHealth().then(({ data }) => setHealth(data)).catch(() => setHealth(null))
    const scanId = searchParams.get('scan')
    if (scanId) loadScan(parseInt(scanId))
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  const loadHistory = async () => {
    try {
      const { data } = await listScans()
      setScanHistory(data)
      setHistoryError('')
    } catch (err) {
      setHistoryError(err.message || 'Could not load history')
    }
  }

  const loadFavorites = async () => {
    try { const { data } = await getFavorites(); setFavorites(data) } catch (err) { console.error(err) }
  }

  const loadScan = async (scanId) => {
    try {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
      setLoadError(null)
      const { data } = await getScanResults(scanId)
      setCurrentScan(data.scan)
      setVulnerabilities(data.vulnerabilities)
      setAttackPaths([])
      if (data.scan.status === 'pending' || data.scan.status === 'running') {
        setScanning(true)
        pollScan(scanId)
      } else {
        setScanning(false)
        if (data.scan.status === 'completed') loadAttackPaths(scanId)
      }
    } catch (err) {
      setLoadError({ id: scanId, message: err.message || 'Could not load this scan' })
    }
  }

  const selectScan = (scanId) => {
    setActiveTab('results')
    setSearchParams({ scan: String(scanId) }, { replace: true })
    loadScan(scanId)
  }

  const loadAttackPaths = async (scanId) => {
    try { const { data } = await getAttackPaths(scanId); setAttackPaths(data.paths || []) } catch (err) { console.error(err) }
  }

  const handleStartScan = async (target, scanners) => {
    setScanning(true)
    setScanError('')
    setVulnerabilities([])
    setAttackPaths([])
    try {
      const { data } = await startScan(target, scanners)
      setCurrentScan(data)
      setActiveTab('results')
      setSearchParams({ scan: String(data.id) }, { replace: true })
      loadHistory()
      pollScan(data.id)
    } catch (err) {
      // Rejections (invalid or private target) used to be swallowed here,
      // which made the Start scan button look dead. See issues.md ISSUE-001.
      setScanError(err.message || 'Failed to start scan')
      setScanning(false)
    }
  }

  const handleAddFavorite = async (target) => {
    try { await addFavorite(target, ''); loadFavorites() } catch (err) { console.error(err) }
  }

  const handleDeleteFavorite = async (id) => {
    try { await deleteFavorite(id); loadFavorites() } catch (err) { console.error(err) }
  }

  const pollScan = (scanId) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await getScanResults(scanId)
        setCurrentScan(data.scan)
        setVulnerabilities(data.vulnerabilities)
        loadHistory()
        if (data.scan.status === 'completed' || data.scan.status === 'failed') {
          clearInterval(pollRef.current)
          pollRef.current = null
          setScanning(false)
          if (data.scan.status === 'completed') loadAttackPaths(scanId)
        }
      } catch {
        clearInterval(pollRef.current)
        pollRef.current = null
        setScanning(false)
      }
    }, 2000)
  }

  return (
    <div>
      <PageHeader
        title="Scan console"
        description="Launch scans and review what each one found."
        actions={<Button size="sm" icon={RefreshCw} onClick={loadHistory}>Refresh</Button>}
      />

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(320px,380px)_1fr] gap-6 items-start">
        <div className="space-y-6 min-w-0">
          <Card>
            <CardHeader title="New scan" />
            <div className="px-5 pb-5">
              <ScanForm
                onStartScan={handleStartScan}
                loading={scanning}
                onAddFavorite={handleAddFavorite}
                error={scanError}
                availability={health?.scanners}
              />
            </div>
          </Card>

          {favorites.length > 0 && (
            <Card>
              <CardHeader title="Saved targets" icon={Star} />
              <ul className="border-t border-line divide-y divide-line">
                {favorites.map((fav) => (
                  <li key={fav.id} className="flex items-center justify-between pl-5 pr-2 py-1.5">
                    <span className="font-mono text-[13px] truncate">{fav.target}</span>
                    <IconButton size="sm" icon={X} label={`Remove ${fav.target} from saved targets`} onClick={() => handleDeleteFavorite(fav.id)} />
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <Card>
            <CardHeader title="History" icon={History} description={historyError ? undefined : `${scanHistory.length} scans`} />
            {historyError && scanHistory.length === 0 ? (
              <p className="px-5 pb-5 text-[13px] text-crit">
                {historyError}{' '}
                <button type="button" className="underline text-ink" onClick={loadHistory}>Try again</button>
              </p>
            ) : scanHistory.length > 0 ? (
              <ul className="border-t border-line divide-y divide-line max-h-[420px] overflow-auto">
                {scanHistory.map((scan) => {
                  const active = currentScan?.id === scan.id
                  return (
                    <li key={scan.id}>
                      <button
                        onClick={() => selectScan(scan.id)}
                        aria-current={active ? 'true' : undefined}
                        className={cx(
                          'w-full px-5 py-3 text-left transition-colors duration-150',
                          active ? 'bg-accent-soft/60' : 'hover:bg-hover'
                        )}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono text-[13px] truncate">{scan.target}</span>
                          <StatusBadge status={scan.status} />
                        </div>
                        <div className="text-xs text-ink-subtle mt-1 tabular">
                          {scan.total_vulnerabilities} findings
                          {scan.progress > 0 && scan.progress < 100 && ` · ${scan.progress}%`}
                          {' · '}#{scan.id}
                        </div>
                      </button>
                    </li>
                  )
                })}
              </ul>
            ) : (
              <p className="px-5 pb-5 text-[13px] text-ink-muted">No scans yet.</p>
            )}
          </Card>
        </div>

        <div className="min-w-0 space-y-5">
          {loadError && (
            <Callout tone="crit" icon={AlertTriangle} title={`Scan #${loadError.id} did not load`} role="alert">
              {loadError.message}{' '}
              <button type="button" className="underline text-ink" onClick={() => loadScan(loadError.id)}>Try again</button>
            </Callout>
          )}
          {currentScan ? (
            <div className="space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h2 className="font-mono text-base font-medium truncate">{currentScan.target}</h2>
                    <StatusBadge status={currentScan.status} />
                  </div>
                  <p className="text-xs text-ink-subtle mt-0.5">
                    Scan #{currentScan.id} · {(currentScan.scanners_used || []).join(', ')}
                  </p>
                </div>
                <Segmented
                  label="Scan views"
                  value={activeTab}
                  onChange={setActiveTab}
                  options={[
                    { value: 'results', label: 'Findings', count: vulnerabilities.length },
                    { value: 'explain', label: 'Briefing' },
                    { value: 'attack-paths', label: 'Attack paths', count: attackPaths.length || undefined },
                  ]}
                />
              </div>
              <ScanProgress scan={currentScan} />
              {activeTab === 'results' && <ScanResults scan={currentScan} vulnerabilities={vulnerabilities} />}
              <div hidden={activeTab !== 'explain'}>
                <ScanExplanation scan={currentScan} />
              </div>
              {activeTab === 'attack-paths' && <AttackPathGraph paths={attackPaths} />}
            </div>
          ) : (
            <Card>
              <EmptyState icon={Radar} title="No scan selected" className="py-20">
                Start a new scan, or pick one from history to review its findings.
              </EmptyState>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
