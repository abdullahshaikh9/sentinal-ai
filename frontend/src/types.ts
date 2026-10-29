export type NavItem = { label: string; path: string; icon: string };

export type HealthResponse = { status: string; service: string };
export type User = { id: number; email: string; display_name: string; created_at: string; email_verified?: boolean; phone_verified?: boolean; phone_masked?: string | null; is_admin?: boolean };
export type AssistantStatus = { configured: boolean; provider: string; message: string; local_guidance_available: boolean };
export type AssistantResponse = { answer: string; provider: string; provider_message?: string | null; scan_id: number | null; finding_id: number | null; evidence_references: string[] };
export type AssistantTurn = { role: "user" | "assistant"; content: string };

export type Finding = {
  id: number;
  stable_id: string | null;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string | null;
  evidence: string | null;
  explanation: string | null;
  remediation: string | null;
  confidence: string | null;
  evidence_data: {
    cookie_name?: string;
    observed_attributes?: string[];
    assessment?: { impact?: string; root_cause?: string; verification_status?: string; references?: string[] };
  } | null;
  dedup_key: string | null;
};

export type FindingDetail = Finding & {
  scan_id: number;
  target_url: string;
  remediation_status?: RemediationStatus;
};
export type FindingOverviewItem = FindingDetail;

export type Scan = {
  id: number;
  target_url: string;
  normalized_url: string | null;
  status: "pending" | "running" | "completed" | "partial" | "failed";
  risk_score: number | null;
  risk_level: string | null;
  error_message: string | null;
  redirects: string[];
  checks: Record<string, "completed" | "failed" | "skipped" | "inconclusive">;
  check_details?: Record<string, unknown>;
  created_at: string;
  completed_at: string | null;
};

export type ScanDetail = Scan & { findings: Finding[] };
export type ScanList = { items: Scan[]; total: number; limit: number; offset: number };

export type Asset = { id: number; target_url: string; normalized_url: string; authorization_confirmed: boolean; created_at: string };
export type AssetSecurity = Asset & { latest_scan_id: number | null; latest_scan_status: Scan["status"] | null; last_scan_at: string | null; latest_risk_score: number | null; latest_risk_level: string | null; latest_checks: Record<string, string>; scan_count: number; latest_findings: number; latest_open_findings: number };
export type AssetOverview = { items: AssetSecurity[]; total: number; limit: number; offset: number };
export type VerificationAttempt = { id: number; scan_id: number; finding_id: number | null; status: string; summary: string | null; evidence: string | null; created_at: string };
export type VerificationOverviewItem = { finding_id: number; scan_id: number; target_url: string; title: string; stable_id: string | null; attempts: VerificationAttempt[] };
export type ActivityEvent = { id: number; event_type: string; summary: string; scan_id: number | null; finding_id: number | null; created_at: string };
export type Notification = { id: number; event_type: string; title: string; message: string; scan_id: number | null; finding_id: number | null; read_at: string | null; created_at: string };
export type RemediationStatus = "open" | "in_progress" | "fixed" | "accepted_risk";
export type RemediationItem = { finding_id: number; scan_id: number; target_url: string; title: string; severity: Finding["severity"]; remediation: string | null; status: RemediationStatus; updated_at: string | null };
export type RemediationChange = { id: number; finding_id: number; from_status: RemediationStatus | null; to_status: RemediationStatus; changed_by: number; created_at: string };
export type ComparedFinding = { stable_id: string; title: string; severity: Finding["severity"] };
export type ScanComparison = { earlier_scan_id: number; later_scan_id: number; target_url: string; risk_score_before: number | null; risk_score_after: number | null; risk_score_delta: number | null; new_findings: ComparedFinding[]; no_longer_observed: ComparedFinding[]; still_present: ComparedFinding[]; severity_changes: Array<{ stable_id: string; title: string; before: string; after: string }>; limitation: string };
export type ReportHistory = { id: number; scan_id: number; target_url: string; report_type: string; created_at: string };
export type SearchResult = { kind: "asset" | "scan" | "finding"; id: number; label: string; description: string; href: string };
export type DashboardOverview = {
  assets_total: number;
  assets_scanned: number;
  scans_total: number;
  scans_by_status: Record<Scan["status"], number>;
  findings_by_severity: Record<Finding["severity"], number>;
  open_findings: number;
  resolved_findings: number;
  high_critical_open: number;
  awaiting_verification: number;
  verification_outcomes: Record<string, number>;
  recent_scans: Array<Scan & { findings_count: number }>;
  assets: Array<Asset & { latest_scan_id: number | null; latest_scan_status: Scan["status"] | null; last_scan_at: string | null; open_findings: number }>;
  risk_history: Array<{ scan_id: number; recorded_at: string; risk_score: number }>;
  activity: ActivityEvent[];
};

export type AdminActivity = { id: number; event_type: string; summary: string; actor_user_id: number | null; actor_email: string | null; owner_user_id: number | null; owner_email: string | null; scan_id: number | null; finding_id: number | null; created_at: string };
export type AdminOverview = {
  users_total: number; users_active: number; assets_total: number; assets_with_scans: number; scans_total: number;
  scans_by_status: Record<Scan["status"], number>; findings_by_severity: Record<Finding["severity"], number>;
  verification_outcomes: Record<string, number>; reports_last_7_days: number; auth_events_last_24_hours: number;
  failed_login_counters_active: number | null; recent_scans: Array<Scan & { findings_count: number }>;
  risk_history: Array<{ scan_id: number; recorded_at: string; risk_score: number }>; recent_activity: AdminActivity[];
};
export type AdminHealth = {
  backend: string; database: string; ai_provider: string; ai_configured: boolean;
  email_provider: string; email_configured: boolean; sms_provider: string; sms_configured: boolean; provider_health_note: string;
};
export type AdminUser = { id: number; email: string; display_name: string; is_active: boolean; is_admin: boolean; email_verified: boolean; phone_verified: boolean; created_at: string };
export type AdminUsers = { items: AdminUser[]; total: number; limit: number; offset: number };
export type AdminAsset = { id: number; target_url: string; normalized_url: string; owner_id: number | null; owner_email: string | null; authorization_confirmed: boolean; created_at: string; scan_count: number; latest_scan_id: number | null; latest_scan_status: string | null; latest_scan_at: string | null; latest_scan_error: string | null };
export type AdminAssets = { items: AdminAsset[]; total: number; limit: number; offset: number };
export type AdminFinding = Finding & { scan_id: number; target_url: string; owner_id: number | null; owner_email: string | null; remediation_status: RemediationStatus; verification_count: number; latest_verification_status: string | null };
export type AdminFindings = { items: AdminFinding[]; total: number; limit: number; offset: number };

