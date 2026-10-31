import axios from "axios";

import type { IndicatorType } from "./utils/validation";

const localApiBaseUrl = `http://${window.location.hostname}:8000/api/v1`;

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? localApiBaseUrl,
  withCredentials: true,
  headers: { "X-Requested-With": "ThreatLens" },
});

export type ScanStatus = "QUEUED" | "RUNNING" | "PARTIAL" | "COMPLETED" | "FAILED" | "CANCELLED";
export type Verdict = "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  progress: number;
  current_stage: string;
  verdict: Verdict | null;
  severity: Severity | null;
  risk_score: number | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface ProviderResult {
  provider_name: string;
  status: string;
  verdict: Verdict | null;
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  undetected_count: number;
  confidence: string | null;
  normalized_data: Record<string, unknown>;
  error_code: string | null;
  checked_at: string;
  from_cache: boolean;
  cache_age_seconds: number | null;
}

export interface ScanResults extends ScanStatusResponse {
  indicator_type: IndicatorType;
  normalized_value: string;
  provider_results: ProviderResult[];
  coverage: Record<string, unknown>;
  explanation: Record<string, unknown>;
}

export interface HistoryItem {
  scan_id: string;
  indicator_type: IndicatorType;
  normalized_value: string;
  status: ScanStatus;
  verdict: Verdict | null;
  severity: Severity | null;
  risk_score: number | null;
  progress: number;
  created_at: string;
  completed_at: string | null;
}

export interface HistoryResponse {
  items: HistoryItem[];
  page: number;
  page_size: number;
  total: number;
  has_next: boolean;
}

export interface DashboardSummary {
  total_scans: number;
  completed_scans: number;
  running_scans: number;
  failed_scans: number;
  average_risk_score: number | null;
  verdict_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  recent_scans: HistoryItem[];
}

export async function createScan(value: string, type?: IndicatorType) {
  const response = await api.post<{ scan_id: string; status: ScanStatus; progress: number }>(
    "/scans",
    { value, type },
  );
  return response.data;
}

export async function getScanStatus(scanId: string) {
  const response = await api.get<ScanStatusResponse>(`/scans/${scanId}`);
  return response.data;
}

export async function getScanResults(scanId: string) {
  const response = await api.get<ScanResults>(`/scans/${scanId}/results`);
  return response.data;
}

export async function getDashboard() {
  const response = await api.get<DashboardSummary>("/dashboard");
  return response.data;
}

export async function getHistory(page = 1, pageSize = 20) {
  const response = await api.get<HistoryResponse>("/history", {
    params: { page, page_size: pageSize },
  });
  return response.data;
}

export function apiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const message = error.response?.data?.error?.message;
    if (typeof message === "string") return message;
    if (error.response?.status === 0) return "The ThreatLens API is not reachable.";
  }
  return "The scan could not be completed. Please try again.";
}
