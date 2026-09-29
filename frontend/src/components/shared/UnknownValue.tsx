import { HelpCircle } from 'lucide-react'

export function UnknownValue({ label, explanation }: { label: string; explanation: string }) {
  return <div className="unknown-value"><HelpCircle size={15} aria-hidden="true" /><div><span>{label}</span><strong>Not assessed</strong><small>{explanation}</small></div></div>
}
