import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  ShieldCheck, LayoutDashboard, Radar, MessagesSquare, Database, Network, ScanSearch, Settings,
  Sun, Moon, Monitor,
} from 'lucide-react'
import { useTheme } from '../context/ThemeContext'
import { getHealth } from '../api/client'
import { cx } from './ui'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans', icon: Radar, label: 'Scan console' },
  { to: '/rag', icon: MessagesSquare, label: 'Assistant' },
  { to: '/cve', icon: Database, label: 'CVE database' },
  { to: '/graph', icon: Network, label: 'Knowledge graph' },
  { to: '/sanitize', icon: ScanSearch, label: 'File & link check' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

const THEME_ICONS = { light: Sun, dark: Moon, system: Monitor }

export default function Sidebar({ onNavigate }) {
  const { theme, setTheme, themes } = useTheme()
  const [health, setHealth] = useState(undefined)

  useEffect(() => {
    let alive = true
    const load = () =>
      getHealth()
        .then(({ data }) => alive && setHealth(data))
        .catch(() => alive && setHealth(null))
    load()
    const id = setInterval(load, 30000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  return (
    <aside className="w-60 h-full bg-sunken border-r border-line flex flex-col">
      <div className="h-14 lg:h-16 px-4 flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-ctl bg-accent text-accent-fg flex items-center justify-center">
          <ShieldCheck className="w-[18px] h-[18px]" aria-hidden="true" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold text-ink">VulnDetect</div>
          <div className="text-2xs text-ink-subtle">Vulnerability intelligence</div>
        </div>
      </div>

      <nav aria-label="Main" className="flex-1 px-3 py-2 space-y-0.5 overflow-y-auto">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            onClick={onNavigate}
            className={({ isActive }) =>
              cx(
                'flex items-center gap-2.5 h-9 px-3 rounded-ctl text-sm transition-colors duration-150',
                isActive
                  ? 'bg-surface text-ink font-medium shadow-card border border-line'
                  : 'text-ink-muted hover:text-ink hover:bg-hover border border-transparent'
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon className={cx('w-4 h-4', isActive ? 'text-accent' : 'text-ink-subtle')} aria-hidden="true" />
                {label}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="p-3 space-y-3 border-t border-line">
        <div role="radiogroup" aria-label="Color theme" className="grid grid-cols-3 gap-0.5 p-0.5 rounded-ctl bg-hover">
          {themes.map((t) => {
            const Icon = THEME_ICONS[t.id]
            const active = theme === t.id
            return (
              <button
                key={t.id}
                type="button"
                role="radio"
                aria-checked={active}
                title={t.label}
                onClick={() => setTheme(t.id)}
                className={cx(
                  'h-7 rounded-[8px] flex items-center justify-center gap-1 text-2xs transition-colors duration-150',
                  active ? 'bg-surface text-ink shadow-card' : 'text-ink-subtle hover:text-ink'
                )}
              >
                <Icon className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="sr-only sm:not-sr-only">{t.label}</span>
              </button>
            )
          })}
        </div>

        <div className="flex items-center justify-between px-1 text-xs text-ink-subtle">
          <span className="flex items-center gap-1.5" role="status">
            <span
              className={cx(
                'w-1.5 h-1.5 rounded-full',
                health === undefined ? 'bg-line-strong' : health ? 'bg-ok-solid' : 'bg-crit-solid'
              )}
              aria-hidden="true"
            />
            {health === undefined ? 'Connecting' : health ? 'Backend online' : 'Backend offline'}
          </span>
          {health?.version && <span className="font-mono">v{health.version}</span>}
        </div>
      </div>
    </aside>
  )
}
