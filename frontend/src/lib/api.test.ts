import { afterEach, describe, expect, it, vi } from "vitest";
import { apiBaseUrl, ApiError, getCurrentUser, getFinding, getScans, login, register, searchRecords, setAdminUserStatus } from "./api";

describe("Sentinel API client", () => {
  afterEach(() => vi.restoreAllMocks());

  it("uses the same-origin API proxy for authenticated scan history", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] }),
    } as Response);

    await getScans();

    expect(apiBaseUrl).toBe("/api/v1");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/scans", { credentials: "include", headers: {} });
  });

  it("URL-encodes global search queries and includes the authenticated session", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, json: async () => ({ results: [] }) } as Response);
    await expect(searchRecords("example.com 50%" )).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/search?q=example.com%2050%25", { credentials: "include", headers: {} });
  });

  it("posts registration to the backend and parses the accepted response", async () => {
    const payload = { message: "pending", verification_token: "opaque-token", email: "person@example.test", phone_number: "+15551234567", email_verification_required: true, phone_verification_required: true, resend_after_seconds: 60 };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, status: 202, json: async () => payload } as Response);

    await expect(register("person@example.test", "Test User", "+15551234567", "StrongPassword123")).resolves.toEqual(payload);

    expect(fetchMock).toHaveBeenCalledWith("/api/v1/auth/register", expect.objectContaining({
      method: "POST",
      credentials: "include",
      body: JSON.stringify({ email: "person@example.test", display_name: "Test User", phone_number: "+15551234567", password: "StrongPassword123" }),
    }));
  });

  it("preserves registration HTTP errors without logging response data", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: false, status: 503, json: async () => ({ detail: "Delivery failed" }) } as Response);

    await expect(register("person@example.test", "Test User", "+15551234567", "StrongPassword123")).rejects.toMatchObject({ status: 503, message: "Delivery failed" } satisfies Partial<ApiError>);
  });

  it("formats FastAPI validation errors without exposing submitted input", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 422,
      json: async () => ({ detail: [{ type: "value_error", loc: ["body", "phone_number"], msg: "Value error, Phone number must use international format.", input: "PRIVATE-PHONE-VALUE" }] }),
    } as Response);

    await expect(register("person@example.test", "Test User", "invalid", "StrongPassword123")).rejects.toMatchObject({
      status: 422,
      message: "Mobile number: Phone number must use international format.",
    } satisfies Partial<ApiError>);
  });

  it("extracts a readable message from structured API errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: false, status: 503, json: async () => ({ detail: { code: "delivery_unavailable", message: "Email or mobile verification delivery failed." } }) } as Response);

    await expect(register("person@example.test", "Test User", "+15551234567", "StrongPassword123")).rejects.toMatchObject({
      status: 503,
      message: "Email or mobile verification delivery failed.",
    } satisfies Partial<ApiError>);
  });

  it("returns a verification challenge response after valid credentials need verification", async () => {
    const pending = { verification_required: true, verification_token: "resume-token", channels: ["phone"], email_masked: "u***@example.test", phone_masked: "********4567", resend_after_seconds: 42 };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, status: 200, json: async () => pending } as Response);

    await expect(login("user@example.test", "StrongPassword123")).resolves.toEqual(pending);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/auth/login", expect.objectContaining({ method: "POST", body: JSON.stringify({ email: "user@example.test", password: "StrongPassword123" }) }));
  });

  it("does not treat a login or initial session check 401 as an expired active session", async () => {
    const dispatch = vi.spyOn(window, "dispatchEvent");
    vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: false, status: 401, json: async () => ({ detail: "Invalid email or password." }) } as Response);

    await expect(login("user@example.test", "invalid-password")).rejects.toMatchObject({ status: 401 });
    await expect(getCurrentUser()).rejects.toMatchObject({ status: 401 });

    expect(dispatch).not.toHaveBeenCalledWith(expect.objectContaining({ type: "sentinel:session-expired" }));
  });

  it("fetches single finding detail with session credentials", async () => {
    const finding = { id: 42, scan_id: 7, target_url: "https://owned.example", title: "HSTS absent", severity: "high", remediation_status: "open" };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, json: async () => finding } as Response);

    await expect(getFinding(42)).resolves.toEqual(finding);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/findings/42", { credentials: "include", headers: {} });
  });

  it("sends administrator mutations with session credentials and the CSRF token", async () => {
    document.cookie = "sentinel_csrf=csrf%2Fvalue; path=/";
    const response = { id: 8, email: "person@example.test", display_name: "Person", is_active: false, is_admin: false, email_verified: true, phone_verified: true, created_at: "2026-01-01T00:00:00Z" };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({ ok: true, json: async () => response } as Response);
    await expect(setAdminUserStatus(8, false, "reauth-password")).resolves.toEqual(response);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/admin/users/8/status", expect.objectContaining({
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": "csrf/value" },
      body: JSON.stringify({ is_active: false, current_password: "reauth-password" }),
    }));
    document.cookie = "sentinel_csrf=; Max-Age=0; path=/";
  });
});
