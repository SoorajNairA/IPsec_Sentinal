import { BrowserRouter } from 'react-router-dom'

import { AnalysisProvider } from './AnalysisContext'
import { LiveLabProvider } from './LiveLabContext'
import { AppRoutes } from './routes'

export function App() {
  return (
    <BrowserRouter>
      <AnalysisProvider>
        <LiveLabProvider>
          <AppRoutes />
        </LiveLabProvider>
      </AnalysisProvider>
    </BrowserRouter>
  )
}
