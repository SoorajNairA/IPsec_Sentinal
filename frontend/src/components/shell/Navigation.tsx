import { NavLink } from 'react-router-dom'

const views = [
  ['overview', 'Overview'],
  ['tunnel', 'Tunnel'],
  ['traffic', 'Traffic'],
  ['security', 'Security'],
  ['evidence', 'Evidence'],
  ['report', 'Report'],
] as const

export function Navigation() {
  return (
    <nav className="analysis-nav" aria-label="Analysis views">
      {views.map(([path, label]) => (
        <NavLink key={path} to={`/analysis/${path}`} className={({ isActive }) => isActive ? 'is-active' : undefined}>
          {label}
        </NavLink>
      ))}
    </nav>
  )
}
