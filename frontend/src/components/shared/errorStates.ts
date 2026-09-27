interface SafeErrorState { title: string; message: string; nextAction: string }

const states: Readonly<Record<string, SafeErrorState>> = {
  NO_IPSEC: { title: 'No IPsec traffic detected', message: 'The capture does not contain recognizable IKE or ESP traffic.', nextAction: 'Choose a capture from the IPsec gateway transit interface.' },
  INVALID_CAPTURE: { title: 'Capture could not be parsed', message: 'The file is not a readable classic PCAP capture.', nextAction: 'Export the traffic again as classic PCAP and retry.' },
  INVALID_UPLOAD: { title: 'Upload could not be read', message: 'The local analyzer did not receive a complete capture.', nextAction: 'Choose the original capture again.' },
  PAYLOAD_TOO_LARGE: { title: 'Capture is too large', message: 'The file exceeds the configured local analysis limit.', nextAction: 'Trim the capture to the relevant IPsec session.' },
  UNSUPPORTED_PCAPNG: { title: 'PCAPNG is not supported yet', message: 'This prototype accepts classic PCAP files only.', nextAction: 'Export the capture as classic PCAP and retry.' },
  UNSUPPORTED_LAYOUT: { title: 'Capture layout is not supported', message: 'The current analyzer expects Ethernet and IPv4 outer traffic.', nextAction: 'Capture the gateway transit interface with the supported layout.' },
  UNSUPPORTED_MEDIA_TYPE: { title: 'Upload format is not supported', message: 'The analyzer accepts a raw PCAP upload body.', nextAction: 'Choose a classic PCAP file.' },
  INSUFFICIENT_ESP: { title: 'Not enough ESP traffic', message: 'There are too few encrypted workload packets for traffic inference.', nextAction: 'Capture a longer workload window and retry.' },
  MODEL_UNAVAILABLE: { title: 'Traffic model is unavailable', message: 'Protocol evidence may still be valid, but traffic classification cannot run.', nextAction: 'Start the local analyzer with a validated model bundle.' },
  ANALYZER_FAILURE: { title: 'Local analysis could not complete', message: 'The analyzer stopped before producing a validated result.', nextAction: 'Retry once, then review the local analyzer log if the issue persists.' },
}

const fallback: SafeErrorState = { title: 'Analysis could not complete', message: 'The local analyzer did not return a supported result.', nextAction: 'Choose another capture or retry the local analyzer.' }

export function safeAnalysisError(code: string): SafeErrorState { return states[code] ?? fallback }
