import { VeyraClient } from "@veyra/sdk";

export interface ConnectionInfo {
  apiUrl: string;
  token: string;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export async function discoverConnection(): Promise<ConnectionInfo | null> {
  if (window.__TAURI_INTERNALS__ !== undefined) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<ConnectionInfo>("connection_info");
  }
  const apiUrl = localStorage.getItem("veyra.apiUrl");
  const token = localStorage.getItem("veyra.token");
  return apiUrl !== null && token !== null ? { apiUrl, token } : null;
}

export function saveBrowserConnection(connection: ConnectionInfo): void {
  localStorage.setItem("veyra.apiUrl", connection.apiUrl);
  localStorage.setItem("veyra.token", connection.token);
}

export function createClient(connection: ConnectionInfo): VeyraClient {
  return new VeyraClient({
    baseUrl: connection.apiUrl,
    token: connection.token,
  });
}
