import { useEffect } from 'react'
import { BrowserRouter } from 'react-router-dom'

import { AnalysisProvider, useAnalysis } from './AnalysisContext'
import { LiveLabProvider, useLiveLab } from './LiveLabContext'
import { AppRoutes } from './routes'

function LiveAnalysisBridge() {
  const { analysis } = useLiveLab()
  const { acceptLiveEnvelope } = useAnalysis()
  useEffect(() => {
    if (analysis) acceptLiveEnvelope(analysis)
  }, [acceptLiveEnvelope, analysis])
  return null
}

export function App() {
  return (
    <BrowserRouter>
      <AnalysisProvider>
        <LiveLabProvider>
          <LiveAnalysisBridge />
          <AppRoutes />
        </LiveLabProvider>
      </AnalysisProvider>
    </BrowserRouter>
  )
}
