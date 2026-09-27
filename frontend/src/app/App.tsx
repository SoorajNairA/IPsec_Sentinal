import { BrowserRouter } from 'react-router-dom'

import { AnalysisProvider } from './AnalysisContext'
import { AppRoutes } from './routes'

export function App() {
  return (
    <BrowserRouter>
      <AnalysisProvider>
        <AppRoutes />
      </AnalysisProvider>
    </BrowserRouter>
  )
}
