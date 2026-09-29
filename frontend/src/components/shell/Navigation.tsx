import { NavLink, useLocation } from 'react-router-dom'

const analysisViews = [
  ['overview', 'Overview'],
  ['tunnel', 'Tunnel'],
  ['traffic', 'Traffic'],
  ['security', 'Security'],
  ['evidence', 'Evidence'],
  ['report', 'Report'],
] as const

export function Navigation() {
  const location = useLocation()
  const live = location.pathname.startsWith('/live')
  const views = live
    ? [['', 'Live Lab'], ['tunnel', 'Tunnel'], ['traffic', 'Traffic'], ['security', 'Security'], ['evidence', 'Evidence'], ['report', 'Report']] as const
    : analysisViews
  const prefix = live ? '/live' : '/analysis'
  return (
    <nav className="analysis-nav" aria-label={live ? 'Live Lab views' : 'Analysis views'}>
      {views.map(([path, label]) => (
        <NavLink key={path} to={`${prefix}${path ? `/${path}` : ''}`} end={!path} className={({ isActive }) => isActive ? 'is-active' : undefined}>
          {label}
        </NavLink>
      ))}
    </nav>
  )
}
