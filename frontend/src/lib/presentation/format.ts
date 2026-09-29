export function formatRawConfidence(value: number | null): string {
  return value === null ? 'Unknown' : `${(value * 100).toFixed(1)}% raw / uncalibrated`
}

