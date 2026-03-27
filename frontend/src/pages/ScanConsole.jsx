import { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { History, RefreshCw, Star, StarOff } from 'lucide-react'
import { startScan, getScanResults, getAttackPaths, listScans, getFavorites, addFavorite, deleteFavorite } from '../api/client'
import ScanForm from '../components/ScanForm'
import ScanResults from '../components/ScanResults'
import AttackPathGraph from '../components/AttackPathGraph'

export default function ScanConsole() {
  const [searchParams] = useSearchParams()
  const [scanning, setScanning] = useState(false)
  const [currentScan, setCurrentScan] = useState(null)
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [attackPaths, setAttackPaths] = useState([])
  const [scanHistory, setScanHistory] = useState([])
  const [favorites, setFavorites] = useState([])
  const [activeTab, setActiveTab] = useState('results')

  const pollRef = useRef(null)

  useEffect(() => {
    loadHistory()
    loadFavorites()
    const scanId = searchParams.get('scan')
    if (scanId) loadScan(parseInt(scanId))
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const loadHistory = async () => {
    try {
      const { data } = await listScans()
      setScanHistory(data)
    } catch (err) {
      console.error(err)
    }
  }

  const loadFavorites = async () => {
    try {
      const { data } = await getFavorites()
      setFavorites(data)
    } catch (err) {
      console.error(err)
    }
  }

  const loadScan = async (scanId) => {
    try {
      const { data } = await getScanResults(scanId)
      setCurrentScan(data.scan)
      setVulnerabilities(data.vulnerabilities)
      loadAttackPaths(scanId)
    } catch (err) {
      console.error(err)
    }
  }

  const loadAttackPaths = async (scanId) => {
    try {
      const { data } = await getAttackPaths(scanId)
      setAttackPaths(data.paths || [])
    } catch (err) {
      console.error(err)
    }
  }

  const handleStartScan = async (target, scanners) => {
    setScanning(true)
    setVulnerabilities([])
    setAttackPaths([])
    try {
      const { data } = await startScan(target, scanners)
      setCurrentScan(data)
      pollScan(data.id)
    } catch (err) {
      console.error(err)
      setScanning(false)
    }
  }

  const handleAddFavorite = async (target) => {
    try {
      await addFavorite(target, '')
      loadFavorites()
    } catch (err) {
      console.error(err)
    }
  }

  const handleDeleteFavorite = async (id) => {
    try {
      await deleteFavorite(id)
      loadFavorites()
    } catch (err) {
      console.error(err)
    }
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
          if (data.scan.status === 'completed') {
            loadAttackPaths(scanId)
          }
        }
      } catch (err) {
        clearInterval(pollRef.current)
        pollRef.current = null
        setScanning(false)
      }
    }, 2000)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Scan Console</h1>
          <p className="text-dark-400 text-sm mt-1">Launch and monitor vulnerability scans</p>
        </div>
        <button
          onClick={loadHistory}
          className="px-3 py-2 glass hover:bg-dark-800/80 rounded-lg text-sm text-dark-300 hover:text-white flex items-center gap-2 transition-colors"
        >
          <RefreshCw className="w-4 h-4 text-blue-400" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Scan Form */}
        <div className="col-span-1">
          <div className="glass rounded-lg p-5">
            <h3 className="text-sm font-semibold text-white mb-4">New Scan</h3>
            <ScanForm onStartScan={handleStartScan} loading={scanning} onAddFavorite={handleAddFavorite} />
          </div>

          {/* Favorites */}
          {favorites.length > 0 && (
            <div className="glass rounded-lg mt-4">
              <div className="p-4 border-b border-dark-700 flex items-center gap-2">
                <Star className="w-4 h-4 text-yellow-400" />
                <h3 className="text-sm font-semibold text-white">Favorites</h3>
              </div>
              <div className="divide-y divide-dark-700">
                {favorites.map((fav) => (
                  <div key={fav.id} className="px-4 py-2 flex items-center justify-between hover:bg-dark-800">
                    <span className="text-sm text-dark-300">{fav.target}</span>
                    <button
                      onClick={() => handleDeleteFavorite(fav.id)}
                      className="text-dark-500 hover:text-red-400"
                    >
                      <StarOff className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan History */}
          <div className="glass rounded-lg mt-4">
            <div className="p-4 border-b border-dark-700/50 flex items-center gap-2">
              <History className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-semibold text-white">Scan History</h3>
            </div>
            <div className="divide-y divide-dark-700 max-h-[400px] overflow-auto">
              {scanHistory.map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => { loadScan(scan.id); setActiveTab('results') }}
                  className={`px-4 py-3 cursor-pointer hover:bg-dark-800/50 transition-colors ${
                    currentScan?.id === scan.id ? 'bg-dark-800/80 border-l-2 border-blue-500' : ''
                  }`}
                >
                  <div className="text-sm font-medium text-white">{scan.target}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded ${
                        scan.status === 'completed'
                          ? 'bg-green-500/20 text-green-400'
                          : scan.status === 'failed'
                          ? 'bg-red-500/20 text-red-400'
                          : 'bg-yellow-500/20 text-yellow-400'
                      }`}
                    >
                      {scan.status}
                    </span>
                    <span className="text-[10px] text-dark-500">{scan.total_vulnerabilities} vulns</span>
                    {scan.progress > 0 && scan.progress < 100 && (
                      <span className="text-[10px] text-blue-400">{scan.progress}%</span>
                    )}
                  </div>
                </div>
              ))}
              {scanHistory.length === 0 && (
                <div className="p-4 text-center text-dark-500 text-sm">No scans yet</div>
              )}
            </div>
          </div>
        </div>

        {/* Results */}
        <div className="col-span-2">
          {currentScan ? (
            <div className="space-y-4">
              {/* Tabs */}
              <div className="flex gap-1 glass p-1 rounded-lg">
                {['results', 'attack-paths'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                      activeTab === tab
                        ? 'bg-dark-700 text-white'
                        : 'text-dark-400 hover:text-white'
                    }`}
                  >
                    {tab === 'results' ? 'Vulnerabilities' : 'Attack Paths'}
                  </button>
                ))}
              </div>

              {activeTab === 'results' && (
                <ScanResults scan={currentScan} vulnerabilities={vulnerabilities} />
              )}
              {activeTab === 'attack-paths' && (
                <AttackPathGraph paths={attackPaths} />
              )}
            </div>
          ) : (
            <div className="glass rounded-lg p-12 text-center">
              <div className="text-dark-500">
                <p className="text-lg font-medium">No scan selected</p>
                <p className="text-sm mt-1">Start a new scan or select one from history</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
