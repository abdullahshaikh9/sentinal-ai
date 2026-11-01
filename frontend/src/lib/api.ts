import type { ActivityEvent, AdminActivity, AdminAssets, AdminFinding, AdminFindings, AdminHealth, AdminOverview, AdminUser, AdminUsers, Asset, AssetOverview, AssistantResponse, AssistantStatus, AssistantTurn, DashboardOverview, FindingDetail, FindingOverviewItem, HealthResponse, Notification, RemediationChange, RemediationItem, RemediationStatus, ReportHistory, Scan, ScanComparison, ScanDetail, ScanList, SearchResult, User, VerificationAttempt, VerificationOverviewItem } from "../types";

export const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

type ErrorObject = Record<string, unknown>;

function isErrorObject(value: unknown): value is ErrorObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const validationFieldNames: Record<string, string> = {
  email: "Email",
  display_name: "Display name",
  phone_number: "Mobile number",
  password: "Password",
};

function readableValidationErrors(errors: unknown[]): string | null {
  const messages = errors.flatMap((entry) => {
    if (!isErrorObject(entry) || typeof entry.msg !== "string") return [];
    const location = Array.isArray(entry.loc) ? entry.loc.filter((part): part is string => typeof part === "string") : [];
    const field = [...location].reverse().find((part) => part in validationFieldNames);
    const message = entry.msg.replace(/^Value error,\s*/i, "").trim();
    if (!message || /^(?:input should|value error,?\s*$)/i.test(message)) return [];
    return [`${field ? `${validationFieldNames[field]}: ` : ""}${message}`];
  });
  return messages.length ? [...new Set(messages)].slice(0, 4).join(" ") : null;
}

function responseErrorMessage(payload: unknown, status: number): string {
  const fallbackByStatus: Record<number, string> = {
    400: "The request could not be completed. Check the information and try again.",
    409: "An account with that email or phone number already exists. Sign in or use different contact details.",
    422: "Some information is invalid. Review the form and try again.",
    429: "Too many attempts were made. Wait before trying again.",
    502: "A required provider could not complete the request. Please try again later.",
    503: "Verification delivery is temporarily unavailable. Your account may be pending; sign in to resume or resend verification later.",
  };
  const fallback = fallbackByStatus[status] ?? "The Sentinel API returned an unexpected error.";

  const extract = (value: unknown): string | null => {
    if (typeof value === "string") {
      const text = value.trim();
      if (!text || /traceback|sqlalchemy|pymysql|stack trace|internal server error/i.test(text)) return null;
      return text.slice(0, 600);
    }
    if (Array.isArray(value)) return readableValidationErrors(value);
    if (!isErrorObject(value)) return null;
    for (const key of ["detail", "message", "msg", "error"]) {
      if (key in value) {
        const message = extract(value[key]);
        if (message) return message;
      }
    }
    return null;
  };

  return extract(payload) ?? fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  let csrf = document.cookie.match(/(?:^|; )sentinel_csrf=([^;]+)/)?.[1];
  const method = (init?.method ?? "GET").toUpperCase();
  const publicPaths = ["/auth/login", "/auth/register", "/auth/verify-otp", "/auth/resend-otp", "/auth/forgot-password", "/auth/request-reset", "/auth/verify-reset-code", "/auth/verify-reset-otp", "/auth/reset-password"];
  if (!csrf && !["GET", "HEAD", "OPTIONS"].includes(method) && !publicPaths.includes(path)) {
    const tokenResponse = await fetch(`${apiBaseUrl}/auth/csrf`, { credentials: "include" });
    if (!tokenResponse.ok) throw new ApiError(403, "Security session could not be verified. Please sign in again.");
    const tokenData: { csrf_token: string } = await tokenResponse.json();
    csrf = tokenData.csrf_token;
  }
  try {
    response = await fetch(`${apiBaseUrl}${path}`, { ...init, credentials: "include", headers: { ...init?.headers, ...(csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {}) } });
  } catch {
    throw new ApiError(0, "The Sentinel API could not be reached. Check that the backend is running.");
  }
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && path !== "/auth/login" && path !== "/auth/me") window.dispatchEvent(new CustomEvent("sentinel:session-expired"));
    throw new ApiError(response.status, responseErrorMessage(payload, response.status));
  }
  return payload as T;
}

export async function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export async function searchRecords(query: string): Promise<SearchResult[]> {
  const response = await request<{ results: SearchResult[] }>(`/search?q=${encodeURIComponent(query)}`);
  return response.results;
}

export async function getDashboardOverview(): Promise<DashboardOverview> {
  return request<DashboardOverview>("/dashboard/overview");
}

export async function getAssetOverview(limit = 20, offset = 0): Promise<AssetOverview> {
  return request<AssetOverview>(`/assets/overview?limit=${limit}&offset=${offset}`);
}

export function getAdminOverview(): Promise<AdminOverview> { return request<AdminOverview>("/admin/overview"); }
export function getAdminHealth(): Promise<AdminHealth> { return request<AdminHealth>("/admin/health"); }
export function getAdminAssets(filters: { q?: string; limit?: number; offset?: number } = {}): Promise<AdminAssets> {
  const query = new URLSearchParams();
  if (filters.q) query.set("q", filters.q);
  query.set("limit", String(filters.limit ?? 25));
  query.set("offset", String(filters.offset ?? 0));
  return request<AdminAssets>(`/admin/assets?${query}`);
}
export function getAdminFindings(filters: { q?: string; severity?: AdminFinding["severity"]; limit?: number; offset?: number } = {}): Promise<AdminFindings> {
  const query = new URLSearchParams();
  if (filters.q) query.set("q", filters.q);
  if (filters.severity) query.set("severity", filters.severity);
  query.set("limit", String(filters.limit ?? 25));
  query.set("offset", String(filters.offset ?? 0));
  return request<AdminFindings>(`/admin/findings?${query}`);
}
export function getAdminUsers(filters: { q?: string; status?: "active" | "disabled"; limit?: number; offset?: number } = {}): Promise<AdminUsers> {
  const query = new URLSearchParams();
  if (filters.q) query.set("q", filters.q);
  if (filters.status) query.set("status", filters.status);
  query.set("limit", String(filters.limit ?? 25));
  query.set("offset", String(filters.offset ?? 0));
  return request<AdminUsers>(`/admin/users?${query}`);
}
export function getAdminAudit(filters: { q?: string; limit?: number; offset?: number } = {}): Promise<AdminActivity[]> {
  const query = new URLSearchParams();
  if (filters.q) query.set("q", filters.q);
  query.set("limit", String(filters.limit ?? 50));
  query.set("offset", String(filters.offset ?? 0));
  return request<AdminActivity[]>(`/admin/audit?${query}`);
}
export function setAdminUserStatus(userId: number, isActive: boolean, currentPassword: string): Promise<AdminUser> {
  return request<AdminUser>(`/admin/users/${userId}/status`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ is_active: isActive, current_password: currentPassword }) });
}
export function revokeAdminUserSessions(userId: number, currentPassword: string): Promise<{ message: string; revoked_sessions: number }> {
  return request<{ message: string; revoked_sessions: number }>(`/admin/users/${userId}/sessions/revoke`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ current_password: currentPassword }) });
}

export type RegistrationPending = { message: string; verification_token: string; email: string; phone_number: string; email_verification_required: boolean; phone_verification_required: boolean; resend_after_seconds: number };
export type LoginVerificationPending = { verification_required: true; verification_token: string; channels: Array<"email" | "phone">; email_masked: string; phone_masked: string; resend_after_seconds: number };
export type LoginResult = { user: User } | LoginVerificationPending;
export type OtpVerificationResponse = { message: string; channel: "email" | "phone"; verified: boolean; account_verified: boolean; user: User | null };
export type PasswordResetPending = { message: string; reset_token: string; resend_after_seconds: number };
export type PasswordResetVerifyResult = { message: string; password_reset_token: string };
export function register(email: string, displayName: string, phoneNumber: string, password: string): Promise<RegistrationPending> { return request<RegistrationPending>("/auth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, display_name: displayName, phone_number: phoneNumber, password }) }); }
export function verifyOtp(verificationToken: string, channel: "email" | "phone", code: string): Promise<OtpVerificationResponse> { return request<OtpVerificationResponse>("/auth/verify-otp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ verification_token: verificationToken, channel, code }) }); }
export function resendOtp(verificationToken: string, channel: "email" | "phone"): Promise<{ message: string; resend_after_seconds: number }> { return request<{ message: string; resend_after_seconds: number }>("/auth/resend-otp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ verification_token: verificationToken, channel }) }); }
export function requestPasswordReset(email: string): Promise<PasswordResetPending> { return request<PasswordResetPending>("/auth/forgot-password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }) }); }
export function verifyPasswordResetCode(resetToken: string, code: string): Promise<PasswordResetVerifyResult> { return request<PasswordResetVerifyResult>("/auth/verify-reset-code", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reset_token: resetToken, code }) }); }
export function resetPassword(passwordResetToken: string, newPassword: string): Promise<{ message: string }> { return request<{ message: string }>("/auth/reset-password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password_reset_token: passwordResetToken, new_password: newPassword }) }); }
export function login(email: string, password: string): Promise<LoginResult> { return request<LoginResult>("/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) }); }
export function changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> { return request<{ message: string }>("/auth/change-password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) }); }
export function logout(): Promise<void> { return request<void>("/auth/logout", { method: "POST" }); }
export function getCurrentUser(): Promise<User> { return request<User>("/auth/me"); }
export function getAssistantStatus(): Promise<AssistantStatus> { return request<AssistantStatus>("/assistant/status"); }
export function askAssistant(question: string, scanId?: number, findingId?: number, history: AssistantTurn[] = []): Promise<AssistantResponse> { return request<AssistantResponse>("/assistant/query", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question, scan_id: scanId, finding_id: findingId, history: history.slice(-12).map((turn) => ({ role: turn.role, content: turn.content.slice(-4000) })) }) }); }

export function createScan(targetUrl: string, authorizationConfirmed = false, assetId?: number): Promise<Scan> {
  return request<Scan>("/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_url: targetUrl, authorization_confirmed: authorizationConfirmed, asset_id: assetId }),
  });
}

export function getAssets(): Promise<Asset[]> { return request<Asset[]>("/assets"); }
export function registerAsset(targetUrl: string, authorizationConfirmed: boolean): Promise<Asset> { return request<Asset>("/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target_url: targetUrl, authorization_confirmed: authorizationConfirmed }) }); }
export function downloadReport(scanId: number): Promise<Response> { return fetch(`${apiBaseUrl}/scans/${scanId}/report.pdf`, { credentials: "include" }); }
export function downloadFindingsCsv(scanId: number): Promise<Response> { return fetch(`${apiBaseUrl}/scans/${scanId}/findings.csv`, { credentials: "include" }); }
export function getReportHistory(limit = 50, offset = 0): Promise<ReportHistory[]> { return request<ReportHistory[]>(`/reports?limit=${limit}&offset=${offset}`); }
export function requestVerification(findingId: number): Promise<VerificationAttempt> { return request<VerificationAttempt>(`/findings/${findingId}/verification`, { method: "POST" }); }
export function getVerifications(findingId: number): Promise<VerificationAttempt[]> { return request<VerificationAttempt[]>(`/findings/${findingId}/verification`); }
export function getFindingsOverview(): Promise<FindingOverviewItem[]> { return request<FindingOverviewItem[]>("/findings/overview"); }
export function getVerificationOverview(): Promise<VerificationOverviewItem[]> { return request<VerificationOverviewItem[]>("/verification/overview"); }
export function getActivity(limit = 50, offset = 0): Promise<ActivityEvent[]> { return request<ActivityEvent[]>(`/activity?limit=${limit}&offset=${offset}`); }
export function getNotifications(limit = 30): Promise<Notification[]> { return request<Notification[]>(`/notifications?limit=${limit}`); }
export function markNotificationRead(notificationId: number): Promise<Notification> { return request<Notification>(`/notifications/${notificationId}/read`, { method: "PATCH" }); }
export function getRemediation(): Promise<RemediationItem[]> { return request<RemediationItem[]>("/remediation"); }
export function updateRemediation(findingId: number, status: RemediationStatus): Promise<RemediationItem> { return request<RemediationItem>(`/findings/${findingId}/remediation`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) }); }
export function getRemediationHistory(findingId: number): Promise<RemediationChange[]> { return request<RemediationChange[]>(`/findings/${findingId}/remediation/history`); }
export function compareScans(earlierScanId: number, laterScanId: number): Promise<ScanComparison> { return request<ScanComparison>(`/scans/compare?earlier_scan_id=${earlierScanId}&later_scan_id=${laterScanId}`); }

export function getScans(filters: { limit?: number; offset?: number; q?: string; status?: string; date_from?: string; date_to?: string; asset_id?: number } = {}): Promise<ScanList> {
  const query = new URLSearchParams();
  if (filters.limit !== undefined) query.set("limit", String(filters.limit));
  if (filters.offset !== undefined) query.set("offset", String(filters.offset));
  if (filters.q) query.set("q", filters.q);
  if (filters.status) query.set("status", filters.status);
  if (filters.date_from) query.set("date_from", filters.date_from);
  if (filters.date_to) query.set("date_to", filters.date_to);
  if (filters.asset_id !== undefined) query.set("asset_id", String(filters.asset_id));
  return request<ScanList>(`/scans${query.size ? `?${query.toString()}` : ""}`);
}

export function getScan(scanId: number): Promise<ScanDetail> {
  return request<ScanDetail>(`/scans/${scanId}`);
}

export function getFinding(findingId: number): Promise<FindingDetail> {
  return request<FindingDetail>(`/findings/${findingId}`);
}

