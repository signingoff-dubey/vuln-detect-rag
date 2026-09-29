import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 300000,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  let key = import.meta.env.VITE_API_KEY || ''
  try {
    key = window.localStorage.getItem('vulndetect.apiKey') || key
  } catch {
    // storage unavailable; fall back to the build-time key
  }
  if (key) config.headers['X-API-Key'] = key
  return config
})

// Centralized error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      error.message = 'The API key is missing or wrong. Set VITE_API_KEY or localStorage vulndetect.apiKey.'
    } else if (error.response?.status === 429) {
      error.message = 'Too many requests. Wait a moment and try again.'
    } else if (error.response?.data?.detail) {
      error.message = error.response.data.detail
    } else if (!error.response) {
      error.message = 'Cannot connect to the server. Is the backend running?'
    }
    return Promise.reject(error)
  }
)

// Health
export const getHealth = () => api.get('/health')

// Scans
export const startScan = (target, scanners) => api.post('/scans', { target, scanners })
export const getScan = (id) => api.get(`/scans/${id}`)
export const getScanResults = (id) => api.get(`/scans/${id}/results`)
export const getAttackPaths = (id) => api.get(`/scans/${id}/attack-paths`)
export const listScans = () => api.get('/scans')
export const deleteScan = (id) => api.delete(`/scans/${id}`)
export const exportScan = (id, format) => api.get(`/scans/${id}/export?format=${format}`, { responseType: 'blob' })
// Final step of the scan flow: the AI explains the report in plain language.
export const getBriefing = (id) => api.get(`/scans/${id}/briefing`)
export const regenerateBriefing = (id) => api.post(`/scans/${id}/briefing/regenerate`)
export const explainScan = (id, question) => api.post(`/scans/${id}/explain`, null, { params: question ? { question } : {} })
export const getStats = () => api.get('/stats')
export const getBackendLogs = () => api.get('/logs')

// RAG
export const chatRAG = (message, sessionId) => api.post('/rag/chat', { message, session_id: sessionId })
export const getChatHistory = (sessionId) => api.get(`/rag/history/${sessionId}`)
export const listSessions = () => api.get('/rag/sessions')
export const deleteSession = (sessionId) => api.delete(`/rag/sessions/${sessionId}`)

// CVE
export const getCVE = (cveId) => api.get(`/cve/${cveId}`)
export const searchCVEs = (query, severity, exploitOnly) => api.get('/cve', { params: { q: query, severity, exploit_only: exploitOnly } })
export const getCVEStats = () => api.get('/cve/stats/severity')

// Favorites
export const getFavorites = () => api.get('/favorites')
export const addFavorite = (target, label) => api.post('/favorites', null, { params: { target, label } })
export const deleteFavorite = (id) => api.delete(`/favorites/${id}`)

// LLM Status
export const getLLMStatus = () => api.get('/llm-status')

// Provider + RAG controls (used for research: isolate a backend, or turn
// retrieval off entirely to measure the no-RAG baseline)
export const getProviders = () => api.get('/providers')
export const toggleProvider = (provider, enabled) => api.post(`/providers/${provider}`, null, { params: { enabled } })
export const getProviderModels = (provider) => api.get(`/providers/${provider}/models`)
export const setProviderModel = (provider, model) => api.post(`/providers/${provider}/model`, null, { params: { model } })
export const getEvalMetrics = () => api.get('/eval-metrics')
export const getRagConfig = () => api.get('/rag-config')
export const setRagConfig = (enabled) => api.post('/rag-config', null, { params: { enabled } })

export default api


// Knowledge graph (CVE -> CWE -> CAPEC -> ATT&CK)
export const getGraphStats = () => api.get('/graph/stats')
export const getGraphChain = (cveId) => api.get(`/graph/chain/${cveId}`)
export const getGraphNode = (nodeId) => api.get(`/graph/node/${nodeId}`)
export const searchGraph = (q, limit = 25) => api.get('/graph/search', { params: { q, limit } })
export const getGraphNeighborhood = (nodeId, depth = 2, limit = 120) =>
  api.get(`/graph/neighborhood/${nodeId}`, { params: { depth, limit } })
