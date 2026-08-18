import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'

export default function Layout({ theme, onToggleTheme }) {
  return (
    <div className="flex h-screen bg-dark-950 overflow-hidden">
      <Sidebar theme={theme} onToggleTheme={onToggleTheme} />
      <main className="flex-1 overflow-auto overflow-x-hidden p-4 sm:p-6 min-w-0">
        <Outlet />
      </main>
    </div>
  )
}
