import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanConsole from './pages/ScanConsole'
import RAGAssistant from './pages/RAGAssistant'
import CVEDetail from './pages/CVEDetail'
import ScanConsole from './pages/ScanConsole'
import RAGAssistant from './pages/RAGAssistant'
import CVEDetail from './pages/CVEDetail'
import CVEBrowse from './pages/CVEBrowse'
import Settings from './pages/Settings'

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-dark-400">
      <h1 className="text-6xl font-bold text-white mb-4">404</h1>
      <p className="text-lg">Page not found</p>
      <a href="/" className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-white text-sm">Go to Dashboard</a>
    </div>
  )
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')

  useEffect(() => {
    localStorage.setItem('theme', theme)
    document.documentElement.classList.toggle('light', theme === 'light')
  }, [theme])

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout theme={theme} onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} />}>
          <Route index element={<Dashboard />} />
          <Route path="scans" element={<ScanConsole />} />
          <Route path="rag" element={<RAGAssistant />} />
          <Route path="cve" element={<CVEBrowse />} />
          <Route path="cve/:cveId" element={<CVEDetail />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
