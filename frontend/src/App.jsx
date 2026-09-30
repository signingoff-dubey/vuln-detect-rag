import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import { Compass } from 'lucide-react'
import Layout from './components/Layout'
import Skeleton, { SkeletonRegion, SkeletonStatCards, SkeletonPanel } from './components/Skeleton'
import { EmptyState } from './components/ui'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const ScanConsole = lazy(() => import('./pages/ScanConsole'))
const RAGAssistant = lazy(() => import('./pages/RAGAssistant'))
const CVEDetail = lazy(() => import('./pages/CVEDetail'))
const CVEBrowse = lazy(() => import('./pages/CVEBrowse'))
const KnowledgeGraph = lazy(() => import('./pages/KnowledgeGraph'))
const Sanitize = lazy(() => import('./pages/Sanitize'))
const Settings = lazy(() => import('./pages/Settings'))

// Route-level fallback while a page chunk downloads: a header and two blocks
// is the most honest outline available before the page module arrives.
function Loading() {
  return (
    <SkeletonRegion label="Loading page" className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-7 w-56" />
        <Skeleton className="h-3 w-72" />
      </div>
      <SkeletonStatCards count={4} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SkeletonPanel />
        <SkeletonPanel />
      </div>
    </SkeletonRegion>
  )
}

function NotFound() {
  return (
    <EmptyState
      icon={Compass}
      title="Page not found"
      className="flex-1"
      action={
        <Link
          to="/"
          className="inline-flex items-center h-9 px-3.5 rounded-ctl bg-accent text-accent-fg text-sm font-medium hover:bg-accent-hover"
        >
          Go to dashboard
        </Link>
      }
    >
      That address does not match any page.
    </EmptyState>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Suspense fallback={<Loading />}><Dashboard /></Suspense>} />
          <Route path="scans" element={<Suspense fallback={<Loading />}><ScanConsole /></Suspense>} />
          <Route path="rag" element={<Suspense fallback={<Loading />}><RAGAssistant /></Suspense>} />
          <Route path="cve" element={<Suspense fallback={<Loading />}><CVEBrowse /></Suspense>} />
          <Route path="cve/:cveId" element={<Suspense fallback={<Loading />}><CVEDetail /></Suspense>} />
          <Route path="graph" element={<Suspense fallback={<Loading />}><KnowledgeGraph /></Suspense>} />
          <Route path="sanitize" element={<Suspense fallback={<Loading />}><Sanitize /></Suspense>} />
          <Route path="settings" element={<Suspense fallback={<Loading />}><Settings /></Suspense>} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
