export interface ApiTimingSample {
  path: string;
  method: string;
  status: number;
  durationMs: number;
  recordedAt: string;
}

const MAX_SAMPLES = 50;
const apiSamples: ApiTimingSample[] = [];

export function recordApiLatency(sample: ApiTimingSample): void {
  apiSamples.unshift(sample);
  if (apiSamples.length > MAX_SAMPLES) {
    apiSamples.length = MAX_SAMPLES;
  }
}

export async function trackedFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const started = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const res = await fetch(input, init);
  const ended = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const path = typeof input === 'string' ? input.split('?')[0] : 'request';
  recordApiLatency({
    path,
    method: (init?.method || 'GET').toUpperCase(),
    status: res.status,
    durationMs: Math.round(ended - started),
    recordedAt: new Date().toISOString(),
  });
  return res;
}

export function getPerformanceSummary(): {
  pageLoadMs: number | null;
  avgApiLatencyMs: number | null;
  recentApiSamples: ApiTimingSample[];
} {
  let pageLoadMs: number | null = null;
  if (typeof performance !== 'undefined' && typeof performance.getEntriesByType === 'function') {
    const navEntries = performance.getEntriesByType('navigation') as PerformanceNavigationTiming[];
    if (navEntries.length > 0 && navEntries[0].loadEventEnd > 0) {
      pageLoadMs = Math.round(navEntries[0].loadEventEnd - navEntries[0].startTime);
    }
  }
  const avgApiLatencyMs =
    apiSamples.length > 0
      ? Math.round(apiSamples.reduce((acc, s) => acc + s.durationMs, 0) / apiSamples.length)
      : null;

  return {
    pageLoadMs,
    avgApiLatencyMs,
    recentApiSamples: [...apiSamples],
  };
}
