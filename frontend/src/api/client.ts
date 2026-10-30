import type {
  CommandPreview,
  Explanation,
  Options,
  ScanJob,
  ScanRequest,
  ScanSummary,
} from "../types";

const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? "";

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail)) message = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(message, res.status);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  options: () => request<Options>("/api/options"),
  preview: (body: ScanRequest) =>
    request<CommandPreview>("/api/scans/preview", { method: "POST", body: JSON.stringify(body) }),
  createScan: (body: ScanRequest) =>
    request<ScanJob>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  getScan: (id: string) => request<ScanJob>(`/api/scans/${id}`),
  listScans: () => request<ScanSummary[]>("/api/scans"),
  deleteScan: (id: string) => request<void>(`/api/scans/${id}`, { method: "DELETE" }),
  explain: (
    cveId: string,
    ctx: { product?: string | null; version?: string | null; port?: number; cvss?: number | null; is_exploit?: boolean },
  ) =>
    request<Explanation>(`/api/cves/${cveId}/explain`, { method: "POST", body: JSON.stringify(ctx) }),
  eventsUrl: (id: string) => `${BASE}/api/scans/${id}/events`,
};
