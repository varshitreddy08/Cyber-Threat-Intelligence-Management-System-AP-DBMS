// All HTTP API calls use relative URLs (/api/...) so Next.js rewrites
// proxy them to FastAPI — works from any device on the network.
export const API = "";

// WebSocket URL dynamically uses the current browser hostname,
// so it works both on localhost and over the local network.
export function wsUrl(path: string): string {
  if (typeof window === "undefined") return `ws://localhost:8000${path}`;
  return `ws://${window.location.hostname}:8000${path}`;
}
