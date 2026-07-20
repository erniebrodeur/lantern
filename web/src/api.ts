import type { Capabilities, HostObservation, HostPage, HostRoute, ProviderEvidence, ProviderStatus, RouteMap, Scan, ScanProfile, ToolActivity } from "./types";

interface ErrorResponse {
  error?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as ErrorResponse;
      if (body.error) message = body.error;
    } catch {
      // Keep the status-based message when the body is not JSON.
    }
    throw new Error(message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function listScans(): Promise<Scan[]> {
  return request<Scan[]>("/api/scans");
}

export function getScan(identifier: string): Promise<Scan> {
  return request<Scan>(`/api/scans/${identifier}`);
}

export function startScan(target: string, profileId: string, osDetection: boolean): Promise<Scan> {
  return request<Scan>("/api/scans", {
    method: "POST",
    body: JSON.stringify({ target, profileId, osDetection }),
  });
}

export function getCapabilities(): Promise<Capabilities> {
  return request<Capabilities>("/api/capabilities");
}

export function refreshProviders(): Promise<ProviderStatus[]> {
  return request<ProviderStatus[]>("/api/capabilities/refresh", { method: "POST" });
}

export function listProfiles(): Promise<ScanProfile[]> {
  return request<ScanProfile[]>("/api/profiles");
}

export function createProfile(argumentText: string): Promise<ScanProfile> {
  return request<ScanProfile>("/api/profiles", {
    method: "POST",
    body: JSON.stringify({ argumentText }),
  });
}

export function updateProfile(identifier: string, argumentText: string): Promise<ScanProfile> {
  return request<ScanProfile>(`/api/profiles/${identifier}`, {
    method: "PUT",
    body: JSON.stringify({ argumentText }),
  });
}

export function deleteProfile(identifier: string): Promise<void> {
  return request<void>(`/api/profiles/${identifier}`, { method: "DELETE" });
}

export function cancelScan(identifier: string): Promise<void> {
  return request<void>(`/api/scans/${identifier}/cancel`, { method: "POST" });
}

export function deleteScan(identifier: string): Promise<void> {
  return request<void>(`/api/scans/${identifier}`, { method: "DELETE" });
}

export function listHosts(scanID: string, limit = 500): Promise<HostPage> {
  return request<HostPage>(`/api/scans/${scanID}/hosts?limit=${limit}`);
}

export function listTools(scanID: string): Promise<ToolActivity[]> {
  return request<ToolActivity[]>(`/api/scans/${scanID}/tools`);
}

export function getHost(scanID: string, hostID: number): Promise<HostObservation> {
  return request<HostObservation>(`/api/scans/${scanID}/hosts/${hostID}`);
}

export function listEvidence(scanID: string, kind?: string, limit = 500): Promise<ProviderEvidence[]> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (kind) query.set("kind", kind);
  return request<ProviderEvidence[]>(`/api/scans/${scanID}/evidence?${query}`);
}

export function mapRoute(scanID: string, target: string): Promise<HostRoute> {
  return request<HostRoute>(`/api/scans/${scanID}/routes`, {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export function listRoutes(scanID: string): Promise<RouteMap> {
  return request<RouteMap>(`/api/scans/${scanID}/routes`);
}
