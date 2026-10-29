import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuth } from "../auth/AuthContext";
import { getAdminAssets, getAdminAudit, getAdminFindings, getAdminHealth, getAdminOverview, getAdminUsers, revokeAdminUserSessions, setAdminUserStatus } from "../lib/api";
import { AdminPage } from "./AdminPage";

vi.mock("../auth/AuthContext", () => ({ useAuth: vi.fn() }));
vi.mock("../lib/api", () => ({
  ApiError: class ApiError extends Error { status = 500; },
  getAdminAssets: vi.fn(), getAdminAudit: vi.fn(), getAdminFindings: vi.fn(), getAdminHealth: vi.fn(), getAdminOverview: vi.fn(), getAdminUsers: vi.fn(),
  revokeAdminUserSessions: vi.fn(), setAdminUserStatus: vi.fn(),
}));

const overview = {
  users_total: 2, users_active: 1, assets_total: 4, assets_with_scans: 3, scans_total: 6,
  scans_by_status: { pending: 1, running: 1, completed: 2, partial: 1, failed: 1 },
  findings_by_severity: { critical: 1, high: 2, medium: 3, low: 1, info: 0 },
  verification_outcomes: { completed: 2, pending: 1 }, reports_last_7_days: 3, auth_events_last_24_hours: 5,
  failed_login_counters_active: null, recent_scans: [], risk_history: [], recent_activity: [],
};
const health = { backend: "healthy", database: "healthy", ai_provider: "none", ai_configured: false, email_provider: "none", email_configured: false, sms_provider: "none", sms_configured: false, provider_health_note: "Configuration status only." };
const accounts = { items: [{ id: 7, email: "person@example.test", display_name: "Example Person", is_active: true, is_admin: false, email_verified: true, phone_verified: true, created_at: "2026-01-01T00:00:00Z" }], total: 1, limit: 25, offset: 0 };
const assets = { items: [], total: 0, limit: 25, offset: 0 };
const findings = { items: [], total: 0, limit: 25, offset: 0 };

describe("Admin Control Center", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAdminOverview).mockResolvedValue(overview);
    vi.mocked(getAdminHealth).mockResolvedValue(health);
    vi.mocked(getAdminAssets).mockResolvedValue(assets);
    vi.mocked(getAdminFindings).mockResolvedValue(findings);
    vi.mocked(getAdminUsers).mockResolvedValue(accounts);
    vi.mocked(getAdminAudit).mockResolvedValue([]);
    vi.mocked(setAdminUserStatus).mockResolvedValue({ ...accounts.items[0], is_active: false });
    vi.mocked(revokeAdminUserSessions).mockResolvedValue({ message: "Active sessions were revoked.", revoked_sessions: 2 });
  });

  it("shows persisted metrics and integration status for configured administrators", async () => {
    vi.mocked(useAuth).mockReturnValue({ user: { id: 1, email: "admin@example.test", display_name: "Admin", created_at: "2026-01-01T00:00:00Z", is_admin: true }, loading: false, error: null, login: vi.fn(), register: vi.fn(), completeAuthentication: vi.fn(), logout: vi.fn() });
    render(<AdminPage />);
    expect(await screen.findByRole("heading", { name: "Admin Control Center" })).toBeInTheDocument();
    expect(await screen.findByText("4", { selector: "p.text-2xl" })).toBeInTheDocument();
    expect(screen.getByText("Database-backed login counters are unavailable until migration 20261028_0009 is applied.")).toBeInTheDocument();
    expect(screen.getByText("Database")).toBeInTheDocument();
    expect(getAdminOverview).toHaveBeenCalledTimes(1);
    expect(getAdminUsers).toHaveBeenCalledWith({ q: "", status: undefined, limit: 25, offset: 0 });
  });

  it("denies the admin view in the client when the session is not allowlisted", () => {
    vi.mocked(useAuth).mockReturnValue({ user: { id: 2, email: "user@example.test", display_name: "User", created_at: "2026-01-01T00:00:00Z", is_admin: false }, loading: false, error: null, login: vi.fn(), register: vi.fn(), completeAuthentication: vi.fn(), logout: vi.fn() });
    render(<AdminPage />);
    expect(screen.getByRole("alert")).toHaveTextContent("Administrator access required");
    expect(getAdminOverview).not.toHaveBeenCalled();
  });

  it("requires explicit re-authentication before disabling an account", async () => {
    vi.mocked(useAuth).mockReturnValue({ user: { id: 1, email: "admin@example.test", display_name: "Admin", created_at: "2026-01-01T00:00:00Z", is_admin: true }, loading: false, error: null, login: vi.fn(), register: vi.fn(), completeAuthentication: vi.fn(), logout: vi.fn() });
    render(<AdminPage />);
    await screen.findByText(/person@example\.test/);
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    expect(screen.getByRole("dialog")).toHaveTextContent("all active sessions will be revoked");
    expect(screen.getByRole("button", { name: "Disable account" })).toBeDisabled();
    expect(setAdminUserStatus).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Your current password"), { target: { value: "current-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Disable account" }));
    await waitFor(() => expect(setAdminUserStatus).toHaveBeenCalledWith(7, false, "current-password"));
    expect(await screen.findByRole("status")).toHaveTextContent("Example Person is now disabled.");
  });
});
