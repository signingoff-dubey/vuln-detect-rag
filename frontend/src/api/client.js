import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// Centralized error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 429) {
      error.message = 'Too many requests — please slow down and try again.'
    } else if (error.response?.data?.detail) {
      error.message = error.response.data.detail
    } else if (!error.response) {
      error.message = 'Cannot connect to the server. Is the backend running?'
    }
    return Promise.reject(error)
  }
)

// Scans
export const startScan = (target, scanners) => api.post('/scans', { target, scanners })
export const getScan = (id) => api.get(`/scans/${id}`)
export const getScanResults = (id) => api.get(`/scans/${id}/results`)
export const getAttackPaths = (id) => api.get(`/scans/${id}/attack-paths`)
export const listScans = () => api.get('/scans')
export const deleteScan = (id) => api.delete(`/scans/${id}`)
export const exportScan = (id, format) => api.get(`/scans/${id}/export?format=${format}`, { responseType: 'blob' })
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

// Favorites
export const getFavorites = () => api.get('/favorites')
export const addFavorite = (target, label) => api.post('/favorites', null, { params: { target, label } })
export const deleteFavorite = (id) => api.delete(`/favorites/${id}`)

export default api

