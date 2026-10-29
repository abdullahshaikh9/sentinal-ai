import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { App } from "./App";

const emptyDashboard = {
  assets_total: 0, assets_scanned: 0, scans_total: 0,
  scans_by_status: { pending: 0, running: 0, completed: 0, partial: 0, failed: 0 },
  findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  open_findings: 0, resolved_findings: 0, high_critical_open: 0, awaiting_verification: 0,
  verification_outcomes: { pending: 0, running: 0, inconclusive: 0, failed: 0 },
  recent_scans: [], assets: [], risk_history: [], activity: [],
};

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    const payload = url.endsWith("/auth/me") ? { id: 1, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" } : url.endsWith("/dashboard/overview") ? emptyDashboard : url.endsWith("/assets") ? [] : { items: [] };
    return { ok: true, json: async () => payload } as Response;
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe("Sentinel AI application shell", () => {
  it("shows the public landing page to visitors and links to the existing auth routes", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/auth/me")) return { ok: false, status: 401, json: async () => ({ detail: "Authentication is required." }) } as Response;
      return { ok: true, json: async () => [] } as Response;
    }));
    window.history.pushState({}, "", "/");
    const user = userEvent.setup();
    render(<App />);
    expect(await screen.findByRole("heading", { name: /See what your security checks actually/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Create your workspace" })).toHaveAttribute("href", "/register");
    expect(screen.getByRole("link", { name: "Create account" })).toHaveAttribute("href", "/register");
    const signInLinks = screen.getAllByRole("link", { name: "Sign in" });
    expect(signInLinks).toHaveLength(2);
    expect(signInLinks[0]).toHaveAttribute("href", "/login");

    await user.click(signInLinks[0]);
    expect(await screen.findByRole("heading", { name: "Welcome back" })).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "Register" }));
    expect(await screen.findByRole("heading", { name: "Create workspace access" })).toBeInTheDocument();
  });

  it("redirects authenticated visitors from the public root to the dashboard", async () => {
    window.history.pushState({}, "", "/");
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Security overview" }, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /See what your security checks actually/ })).not.toBeInTheDocument();
    expect(window.location.pathname).toBe("/dashboard");
  });

  it("renders structured registration validation errors as readable field guidance", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: false, status: 401, json: async () => ({ detail: "Authentication is required." }) } as Response;
      return { ok: false, status: 422, json: async () => ({ detail: [{ type: "value_error", loc: ["body", "phone_number"], msg: "Value error, Phone number must use international format.", input: "PRIVATE-PHONE-VALUE" }] }) } as Response;
    }));
    window.history.pushState({}, "", "/register");
    const user = userEvent.setup();
    render(<App />);

    await user.type(await screen.findByLabelText("Display name"), "Test User");
    await user.type(screen.getByLabelText("Email"), "test@example.test");
    await user.type(screen.getByLabelText("Mobile number"), "invalid-number");
    await user.type(screen.getByLabelText("Password"), "StrongPassword123");
    await user.type(screen.getByLabelText("Confirm password"), "StrongPassword123");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Mobile number: Phone number must use international format.");
    expect(alert).not.toHaveTextContent("[object Object]");
    expect(alert).not.toHaveTextContent("PRIVATE-PHONE-VALUE");
  });

  it("shows a duplicate registration response without losing its HTTP status", async () => {
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/auth/me")) return { ok: false, status: 401, json: async () => ({ detail: "Authentication is required." }) } as Response;
      return { ok: false, status: 409, json: async () => ({ detail: "An account with that email or phone number already exists." }) } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/register");
    const user = userEvent.setup(); render(<App />);

    await user.type(await screen.findByLabelText("Display name"), "Test User");
    await user.type(screen.getByLabelText("Email"), "existing@example.test");
    await user.type(screen.getByLabelText("Mobile number"), "+15551234567");
    await user.type(screen.getByLabelText("Password"), "StrongPassword123");
    await user.type(screen.getByLabelText("Confirm password"), "StrongPassword123");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("An account with that email or phone number already exists.");
    expect(window.location.pathname).toBe("/register");
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith("/auth/register"))).toBe(true);
  });

  it("keeps successful registration on the verification flow without displaying codes", async () => {
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: false, status: 401, json: async () => ({ detail: "Authentication is required." }) } as Response;
      if (url.endsWith("/auth/register")) return { ok: true, status: 202, json: async () => ({ message: "Verification messages accepted.", verification_token: "opaque-token", email: "new@example.test", phone_number: "+15551234567", email_verification_required: true, phone_verification_required: true, resend_after_seconds: 60 }) } as Response;
      return { ok: true, json: async () => [] } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/register");
    const user = userEvent.setup(); render(<App />);

    await user.type(await screen.findByLabelText("Display name"), "New User");
    await user.type(screen.getByLabelText("Email"), "new@example.test");
    await user.type(screen.getByLabelText("Mobile number"), "+15551234567");
    await user.type(screen.getByLabelText("Password"), "StrongPassword123");
    await user.type(screen.getByLabelText("Confirm password"), "StrongPassword123");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByRole("heading", { name: "Verify your account" })).toBeInTheDocument();
    expect(screen.getByText("Check for a verification code at n***@example.test")).toBeInTheDocument();
    expect(screen.getByText("Check for a verification code at ********4567")).toBeInTheDocument();
    expect(screen.getByText(/Codes are never shown in this app/)).toBeInTheDocument();
    expect(sessionStorage.getItem("sentinel.pending-verification")).toContain("opaque-token");
    expect(sessionStorage.getItem("sentinel.pending-verification")).not.toContain("583104");
  });

  it("renders the dashboard empty state and primary navigation", async () => {
    window.history.pushState({}, "", "/dashboard");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Security overview" }, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText("No security scans yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Security Scans" })).toBeInTheDocument();
  });

  it("renders dashboard summaries from persisted overview data and does not invent a risk trend", async () => {
    const overview = {
      ...emptyDashboard,
      assets_total: 2, assets_scanned: 1, scans_total: 2,
      scans_by_status: { pending: 0, running: 0, completed: 1, partial: 1, failed: 0 },
      findings_by_severity: { critical: 1, high: 2, medium: 3, low: 1, info: 0 },
      open_findings: 5, resolved_findings: 2, high_critical_open: 3, awaiting_verification: 1,
      recent_scans: [{ id: 6, target_url: "https://owned.example", normalized_url: "https://owned.example", status: "partial", risk_score: 54, risk_level: "medium", error_message: null, redirects: [], checks: { headers: "completed", tls: "skipped" }, asset_id: 5, created_at: "2026-02-01T00:00:00Z", completed_at: null, findings_count: 2 }],
      assets: [{ id: 5, target_url: "https://owned.example", normalized_url: "https://owned.example", authorization_confirmed: true, created_at: "2026-01-01T00:00:00Z", latest_scan_id: 6, latest_scan_status: "partial", last_scan_at: "2026-02-01T00:00:00Z", open_findings: 2 }],
      risk_history: [{ scan_id: 6, recorded_at: "2026-02-01T00:00:00Z", risk_score: 54 }],
    };
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 4, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/dashboard/overview")) return { ok: true, json: async () => overview } as Response;
      return { ok: true, json: async () => [] } as Response;
    }));
    window.history.pushState({}, "", "/dashboard");
    render(<App />);

    expect(await screen.findByText(/Welcome, Test\./)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open findings 5 2 marked fixed/ })).toHaveAttribute("href", "/findings");
    expect(screen.getByRole("link", { name: /3 critical\/high findings are open or in progress/ })).toBeInTheDocument();
    expect(screen.getAllByText("Critical / high open")).toHaveLength(1);
    expect(screen.getByRole("link", { name: /Critical \/ high open/ })).toHaveAttribute("href", "/findings?severity=critical,high");
    expect(screen.getAllByText("Failed / partial scans")).toHaveLength(1);
    expect(screen.getByRole("link", { name: /Failed \/ partial scans/ })).toHaveAttribute("href", "/scans");
    expect(screen.getAllByText("https://owned.example").length).toBeGreaterThan(0);
    expect(screen.queryByRole("img", { name: "Recorded risk scores over time" })).not.toBeInTheDocument();
  });

  it("does not present an API failure as an empty dashboard and allows retry", async () => {
    let dashboardRequests = 0;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 4, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/dashboard/overview")) {
        dashboardRequests += 1;
        return dashboardRequests === 1
          ? { ok: false, status: 503, json: async () => ({ detail: "Dashboard service unavailable." }) } as Response
          : { ok: true, json: async () => emptyDashboard } as Response;
      }
      return { ok: true, json: async () => [] } as Response;
    }));
    window.history.pushState({}, "", "/dashboard");
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Dashboard service unavailable.");
    expect(screen.queryByText("No security scans yet")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Registered assets/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No security scans yet")).toBeInTheDocument();
    expect(dashboardRequests).toBe(2);
  });

  it("activates only Compare scans on its nested route and preserves scan history as the parent route", async () => {
    window.history.pushState({}, "", "/scans/compare");
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Scan comparison" })).toBeInTheDocument();
    const navigation = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    const compareLink = navigation.getByRole("link", { name: "Compare scans" });
    const scansLink = navigation.getByRole("link", { name: "Security Scans" });
    expect(compareLink).toHaveClass("nav-link-active");
    expect(scansLink).not.toHaveClass("nav-link-active");

    await user.click(scansLink);
    expect(await screen.findByRole("heading", { name: "Security scans" })).toBeInTheDocument();
    expect(scansLink).toHaveClass("nav-link-active");
    expect(compareLink).not.toHaveClass("nav-link-active");
    await user.click(compareLink);
    expect(await screen.findByRole("heading", { name: "Scan comparison" })).toBeInTheDocument();
    expect(navigation.getByRole("link", { name: "Compare scans" })).toHaveClass("nav-link-active");
    expect(navigation.getByRole("link", { name: "Security Scans" })).not.toHaveClass("nav-link-active");
    window.history.back();
    expect(await screen.findByRole("heading", { name: "Security scans" })).toBeInTheDocument();
    expect(navigation.getByRole("link", { name: "Security Scans" })).toHaveClass("nav-link-active");
    window.history.forward();
    expect(await screen.findByRole("heading", { name: "Scan comparison" })).toBeInTheDocument();
    expect(navigation.getByRole("link", { name: "Compare scans" })).toHaveClass("nav-link-active");
  });

  it("keeps Security Scans active for a direct scan-detail URL", async () => {
    const scan = { id: 42, target_url: "https://owned.example", normalized_url: "https://owned.example", status: "completed", risk_score: 0, risk_level: "info", error_message: null, redirects: [], checks: {}, created_at: "2026-02-01T00:00:00Z", completed_at: "2026-02-01T00:01:00Z", findings: [] };
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 1, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/scans/42")) return { ok: true, json: async () => scan } as Response;
      if (url.endsWith("/dashboard/overview")) return { ok: true, json: async () => emptyDashboard } as Response;
      return { ok: true, json: async () => [] } as Response;
    }));
    window.history.pushState({}, "", "/scans/42");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "https://owned.example" })).toBeInTheDocument();
    const navigation = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    expect(navigation.getByRole("link", { name: "Security Scans" })).toHaveClass("nav-link-active");
    expect(navigation.getByRole("link", { name: "Compare scans" })).not.toHaveClass("nav-link-active");
  });

  it("shows an asset's latest saved scan, coverage, finding counts, and history link", async () => {
    const asset = { id: 5, target_url: "https://owned.example", normalized_url: "https://owned.example", authorization_confirmed: true, created_at: "2026-01-01T00:00:00Z", latest_scan_id: 12, latest_scan_status: "partial", last_scan_at: "2026-02-01T00:00:00Z", latest_risk_score: 44, latest_risk_level: "medium", latest_checks: { headers: "completed", tls: "skipped" }, scan_count: 3, latest_findings: 2, latest_open_findings: 1 };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 1, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.startsWith("/api/v1/assets/overview")) return { ok: true, json: async () => ({ items: [asset], total: 1, limit: 20, offset: 0 }) } as Response;
      return { ok: true, json: async () => [] } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/domains");
    render(<App />);
    expect(await screen.findByText("1 open / in progress · 2 total")).toBeInTheDocument();
    expect(screen.getByText("1/2 checks")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "3 scans" })).toHaveAttribute("href", "/scans?q=https%3A%2F%2Fowned.example");
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith("/api/v1/assets/overview?limit=20"))).toBe(true);
  });

  it("applies deep-linked severity and finding lifecycle filters to persisted findings", async () => {
    const scan = { id: 7, target_url: "https://owned.example", normalized_url: "https://owned.example", status: "completed", risk_score: 40, risk_level: "medium", error_message: null, redirects: [], checks: { headers: "completed" }, created_at: "2026-02-01T00:00:00Z", completed_at: "2026-02-01T00:01:00Z" };
    const findings = [
      { id: 11, stable_id: "tls.hsts", title: "Critical observation", severity: "critical", category: "transport", evidence: "Saved critical evidence", explanation: "Observed", remediation: "Configure HSTS", confidence: "high", evidence_data: null, dedup_key: "tls.hsts" },
      { id: 12, stable_id: "headers.csp", title: "High observation", severity: "high", category: "header", evidence: "Saved high evidence", explanation: "Observed", remediation: "Add CSP", confidence: "high", evidence_data: null, dedup_key: "headers.csp" },
      { id: 13, stable_id: "headers.xfo", title: "Medium observation", severity: "medium", category: "header", evidence: "Saved medium evidence", explanation: "Observed", remediation: "Set XFO", confidence: "medium", evidence_data: null, dedup_key: "headers.xfo" },
    ];
    const remediation = [
      { finding_id: 11, scan_id: 7, target_url: scan.target_url, title: findings[0].title, severity: "critical", remediation: "Configure HSTS", status: "open", updated_at: null },
      { finding_id: 12, scan_id: 7, target_url: scan.target_url, title: findings[1].title, severity: "high", remediation: "Add CSP", status: "in_progress", updated_at: null },
      { finding_id: 13, scan_id: 7, target_url: scan.target_url, title: findings[2].title, severity: "medium", remediation: "Set XFO", status: "fixed", updated_at: null },
    ];
    const findingsOverview = findings.map((finding) => ({
      ...finding,
      scan_id: 7,
      target_url: scan.target_url,
      remediation_status: remediation.find((item) => item.finding_id === finding.id)?.status ?? "open",
    }));
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 1, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/findings/overview")) return { ok: true, json: async () => findingsOverview } as Response;
      if (url.endsWith("/scans/7")) return { ok: true, json: async () => ({ ...scan, findings }) } as Response;
      if (url.endsWith("/scans")) return { ok: true, json: async () => ({ items: [scan], total: 1 }) } as Response;
      if (url.endsWith("/remediation")) return { ok: true, json: async () => remediation } as Response;
      return { ok: true, json: async () => [] } as Response;
    }));
    window.history.pushState({}, "", "/findings?severity=critical,high&status=in_progress");
    const user = userEvent.setup();
    render(<App />);
    expect(await screen.findByText("High observation")).toBeInTheDocument();
    expect(screen.queryByText("Critical observation")).not.toBeInTheDocument();
    expect(screen.queryByText("Medium observation")).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Filter finding status"), "open");
    expect(await screen.findByText("Critical observation")).toBeInTheDocument();
    expect(screen.queryByText("High observation")).not.toBeInTheDocument();
  });

  it("lets an unverified existing user verify their phone and resumes authentication", async () => {
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: false, status: 401, json: async () => ({ detail: "Authentication is required." }) } as Response;
      if (url.endsWith("/auth/login")) return { ok: true, status: 200, json: async () => ({ verification_required: true, verification_token: "resume-token", channels: ["phone"], email_masked: "t***@example.test", phone_masked: "********4567", resend_after_seconds: 30 }) } as Response;
      if (url.endsWith("/auth/verify-otp")) return { ok: true, status: 200, json: async () => ({ message: "Verification complete.", channel: "phone", verified: true, account_verified: true, user: { id: 2, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z", email_verified: true, phone_verified: true } }) } as Response;
      if (url.endsWith("/dashboard/overview")) return { ok: true, json: async () => emptyDashboard } as Response;
      return { ok: true, status: 200, json: async () => ({ items: [] }) } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/login");
    const user = userEvent.setup();
    render(<App />);

    await user.type(await screen.findByLabelText("Email"), "test@example.test");
    await user.type(screen.getByLabelText("Password"), "StrongPassword123");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Check for a verification code at ********4567")).toBeInTheDocument();
    expect(screen.getByLabelText("Mobile verification code")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Resend code in 30s/ })).toBeDisabled();
    await user.type(screen.getByLabelText("Mobile verification code"), "284619");
    await user.click(screen.getByRole("button", { name: "Verify" }));

    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    expect(await screen.findByText("No security scans yet")).toBeInTheDocument();
    const verifyRequest = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/auth/verify-otp"));
    expect(verifyRequest).toBeDefined();
    expect(JSON.parse(String(verifyRequest?.[1]?.body))).toEqual({ verification_token: "resume-token", channel: "phone", code: "284619" });
    const dashboardRequest = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/dashboard/overview"));
    expect(dashboardRequest?.[1]?.credentials).toBe("include");
    expect(sessionStorage.getItem("sentinel.pending-verification")).toBeNull();
  });

  it("restores a pending verification screen after a page refresh", async () => {
    sessionStorage.setItem("sentinel.pending-verification", JSON.stringify({ token: "refresh-token", channels: ["phone"], emailMasked: "t***@example.test", phoneMasked: "********4567", resendUntil: Date.now() + 15_000 }));
    window.history.pushState({}, "", "/verify");
    render(<App />);

    expect(await screen.findByText("Check for a verification code at ********4567")).toBeInTheDocument();
    expect(screen.getByLabelText("Mobile verification code")).toBeInTheDocument();
  });

  it("loads owned scan evidence and renders local Defensive Guidance", async () => {
    const scan = { id: 44, target_url: "https://observed.example", normalized_url: "https://observed.example", status: "completed", risk_score: 45, risk_level: "medium", error_message: null, redirects: [], checks: { headers: "completed" }, created_at: "2026-01-01T00:00:00Z", completed_at: "2026-01-01T00:01:00Z" };
    const finding = { id: 91, stable_id: "headers.hsts-missing", title: "Missing HSTS", severity: "high", category: "security-header", evidence: "The response did not include Strict-Transport-Security.", explanation: "Downgrade protection was not observed.", remediation: "Set a suitable HSTS policy after validating HTTPS coverage.", confidence: "high", evidence_data: null, dedup_key: "headers.hsts-missing" };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 8, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/assistant/status")) return { ok: true, json: async () => ({ configured: false, provider: "none", local_guidance_available: true, message: "No external AI provider is configured. Select a saved scan." }) } as Response;
      if (url.endsWith("/scans/44")) return { ok: true, json: async () => ({ ...scan, findings: [finding] }) } as Response;
      if (url.endsWith("/scans")) return { ok: true, json: async () => ({ items: [scan] }) } as Response;
      if (url.endsWith("/assistant/query")) return { ok: true, json: async () => ({ answer: "[HIGH] Missing HSTS\\nStored remediation: Set a suitable HSTS policy after validating HTTPS coverage.", provider: "local-evidence", scan_id: 44, finding_id: null, evidence_references: ["scan:44"] }) } as Response;
      return { ok: true, json: async () => ({ items: [] }) } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/assistant");
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Defensive Guidance" })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Saved scan"), "44");
    expect(await screen.findByRole("option", { name: "Missing HSTS" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Prioritize the selected scan findings and explain safe next steps." }));
    await user.click(screen.getByRole("button", { name: "Ask" }));

    expect(await screen.findByText(/Stored remediation: Set a suitable HSTS policy/)).toBeInTheDocument();
    expect(screen.getByText(/local scan guidance/)).toBeInTheDocument();
    expect(screen.getByText("Evidence references: scan:44")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Ask for defensive guidance"), "Why does that matter?");
    await user.click(screen.getByRole("button", { name: "Ask" }));
    expect(await screen.findAllByText(/Stored remediation: Set a suitable HSTS policy/)).toHaveLength(2);
    const queries = fetchMock.mock.calls.filter(([url]) => String(url).endsWith("/assistant/query"));
    expect(JSON.parse(String(queries[0]?.[1]?.body))).toMatchObject({ scan_id: 44, question: "Prioritize the selected scan findings and explain safe next steps.", history: [] });
    expect(JSON.parse(String(queries[1]?.[1]?.body))).toEqual({
      question: "Why does that matter?",
      scan_id: 44,
      history: [
        { role: "user", content: "Prioritize the selected scan findings and explain safe next steps." },
        { role: "assistant", content: "[HIGH] Missing HSTS\\nStored remediation: Set a suitable HSTS policy after validating HTTPS coverage." },
      ],
    });
  });

  it("sends general questions to the assistant without inventing scan context", async () => {
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 8, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/assistant/status")) return { ok: true, json: async () => ({ configured: true, provider: "gemini", local_guidance_available: true, message: "Ready." }) } as Response;
      if (url.endsWith("/assistant/query")) return { ok: true, json: async () => ({ answer: "Use phishing resistant MFA for privileged accounts.", provider: "gemini", scan_id: null, finding_id: null, evidence_references: [] }) } as Response;
      return { ok: true, json: async () => ({ items: [] }) } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/assistant");
    const user = userEvent.setup();
    render(<App />);

    await user.type(await screen.findByLabelText("Ask for defensive guidance"), "How should I harden privileged accounts?");
    await user.click(screen.getByRole("button", { name: "Ask" }));

    expect(await screen.findByText("Use phishing resistant MFA for privileged accounts.")).toBeInTheDocument();
    const query = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/assistant/query"));
    expect(JSON.parse(String(query?.[1]?.body))).toEqual({ question: "How should I harden privileged accounts?", history: [] });
  });

  it("handles an empty scan history without enabling unsupported local guidance", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 8, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/assistant/status")) return { ok: true, json: async () => ({ configured: false, provider: "none", local_guidance_available: true, message: "Select a saved scan." }) } as Response;
      return { ok: true, json: async () => ({ items: [] }) } as Response;
    }));
    window.history.pushState({}, "", "/assistant");
    render(<App />);

    expect(await screen.findByRole("option", { name: "No saved scans" })).toBeInTheDocument();
    expect(screen.getByText(/Run an authorized scan first/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask" })).toBeDisabled();
    expect(screen.getByText(/No recommendations are fabricated without scan evidence/)).toBeInTheDocument();
  });

  it("compares selected scans and explains absence limitations", async () => {
    const scan = (id: number) => ({ id, target_url: "https://same.example", normalized_url: "https://same.example", status: "completed", risk_score: 50 - id * 5, risk_level: "medium", error_message: null, redirects: [], checks: {}, created_at: "2026-01-01T00:00:00Z", completed_at: "2026-01-01T00:01:00Z" });
    const comparison = { earlier_scan_id: 1, later_scan_id: 2, target_url: "https://same.example", risk_score_before: 45, risk_score_after: 40, risk_score_delta: -5, new_findings: [], no_longer_observed: [{ stable_id: "header.hsts", title: "Missing HSTS", severity: "high" }], still_present: [], severity_changes: [], limitation: "A finding absent from the later scan is not proof of remediation." };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 8, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.includes("/scans?")) return { ok: true, json: async () => ({ items: [scan(1), scan(2)] }) } as Response;
      if (url.includes("/scans/compare")) return { ok: true, json: async () => comparison } as Response;
      return { ok: true, json: async () => [] } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/scans/compare");
    const user = userEvent.setup(); render(<App />);
    await user.selectOptions(await screen.findByLabelText("Earlier scan"), "1");
    await user.selectOptions(screen.getByLabelText("Later scan"), "2");
    await user.click(screen.getByRole("button", { name: "Compare" }));
    expect(await screen.findByText("Missing HSTS")).toBeInTheDocument();
    expect(screen.getByText(comparison.limitation)).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("earlier_scan_id=1&later_scan_id=2"))).toBe(true);
  });

  it("updates a finding remediation status through the backend and shows its audit history", async () => {
    const item = { finding_id: 91, scan_id: 44, target_url: "https://observed.example", title: "Missing HSTS", severity: "high", remediation: "Set a suitable HSTS policy.", status: "open", updated_at: null };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 8, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/remediation") && init?.method === "PATCH") return { ok: true, json: async () => ({ ...item, status: "in_progress", updated_at: "2026-01-01T00:01:00Z" }) } as Response;
      if (url.endsWith("/remediation/history")) return { ok: true, json: async () => [{ id: 1, finding_id: 91, from_status: "open", to_status: "in_progress", created_at: "2026-01-01T00:01:00Z" }] } as Response;
      if (url.endsWith("/remediation")) return { ok: true, json: async () => [item] } as Response;
      return { ok: true, json: async () => [] } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/remediation");
    const user = userEvent.setup(); render(<App />);
    await user.selectOptions(await screen.findByLabelText("Status for Missing HSTS"), "in_progress");
    expect(await screen.findByLabelText("Status for Missing HSTS")).toHaveValue("in_progress");
    await user.click(screen.getByRole("button", { name: "View change history" }));
    expect(await screen.findByText(/Open → In Progress/)).toBeInTheDocument();
    const mutation = fetchMock.mock.calls.find(([url, init]) => String(url).endsWith("/remediation") && init?.method === "PATCH");
    expect(JSON.parse(String(mutation?.[1]?.body))).toEqual({ status: "in_progress" });
  });

  it("loads and marks persisted notifications read", async () => {
    const notification = { id: 7, event_type: "report.generated", title: "Report generated", message: "A report is ready.", scan_id: null, finding_id: null, read_at: null, created_at: "2026-01-01T00:00:00Z" };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/me")) return { ok: true, json: async () => ({ id: 8, email: "test@example.test", display_name: "Test User", created_at: "2026-01-01T00:00:00Z" }) } as Response;
      if (url.endsWith("/notifications/7/read")) return { ok: true, json: async () => ({ ...notification, read_at: "2026-01-01T00:01:00Z" }) } as Response;
      if (url.includes("/notifications")) return { ok: true, json: async () => [notification] } as Response;
      if (url.endsWith("/dashboard/overview")) return { ok: true, json: async () => emptyDashboard } as Response;
      return { ok: true, json: async () => ({ items: [] }) } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.pushState({}, "", "/dashboard");
    const user = userEvent.setup(); render(<App />);
    await user.click(await screen.findByRole("button", { name: "Notifications, 1 unread" }));
    expect(await screen.findByText("Report generated")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Mark read" }));
    expect(fetchMock.mock.calls.some(([url, init]) => String(url).endsWith("/notifications/7/read") && init?.method === "PATCH")).toBe(true);
  });
});

