import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getFindingsOverview, getScans, getScan, getRemediation, getVerificationOverview, getVerifications, requestVerification } from "../lib/api";
import { FindingsPage, VerificationPage } from "./Pages";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return { ...actual, getFindingsOverview: vi.fn(), getScans: vi.fn(), getScan: vi.fn(), getRemediation: vi.fn(), getVerificationOverview: vi.fn(), getVerifications: vi.fn(), requestVerification: vi.fn() };
});

const finding = {
  id: 11, scan_id: 4, target_url: "https://owned.example", stable_id: "headers.hsts", title: "HSTS absent",
  severity: "high" as const, category: "headers", evidence: "No header observed", explanation: "Policy absent",
  remediation: "Set HSTS", confidence: "high", evidence_data: { assessment: { impact: "Browser policy not observed.", root_cause: "Server cause is undetermined.", verification_status: "not_attempted", references: ["https://example.test/security-reference"] } }, dedup_key: "headers.hsts", remediation_status: "fixed" as const,
};
const attempt = { id: 81, scan_id: 4, finding_id: 11, status: "completed", summary: "Saved verification", evidence: "Still observed", created_at: "2026-01-01T00:00:00Z" };

describe("batched findings and verification pages", () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it("loads finding cards and lifecycle status with one overview request while preserving filters", async () => {
    vi.mocked(getFindingsOverview).mockResolvedValue([finding]);
    render(<MemoryRouter initialEntries={["/findings?status=fixed"]}><FindingsPage /></MemoryRouter>);
    expect(await screen.findByText("HSTS absent")).toBeInTheDocument();
    expect(screen.getByText("Browser policy not observed.")).toBeInTheDocument();
    expect(screen.getByText(/Verification: not attempted/)).toBeInTheDocument();
    expect(getFindingsOverview).toHaveBeenCalledTimes(1);
    expect(getScans).not.toHaveBeenCalled();
    expect(getScan).not.toHaveBeenCalled();
    expect(getRemediation).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter finding status" }), { target: { value: "open" } });
    await waitFor(() => expect(screen.getByText("No matching findings")).toBeInTheDocument());
  });

  it("loads all visible verification histories in one request and refreshes after an attempt", async () => {
    vi.mocked(getVerificationOverview).mockResolvedValue([{ finding_id: 11, scan_id: 4, target_url: finding.target_url, title: finding.title, stable_id: finding.stable_id, attempts: [attempt] }]);
    vi.mocked(requestVerification).mockResolvedValue({ ...attempt, id: 82, status: "pending", summary: "Queued" });
    vi.mocked(getVerifications).mockResolvedValue([{ ...attempt, id: 82, status: "running", summary: "Queued" }]);
    render(<MemoryRouter><VerificationPage /></MemoryRouter>);
    expect(await screen.findByText("Saved verification")).toBeInTheDocument();
    expect(getVerificationOverview).toHaveBeenCalledTimes(1);
    expect(getVerifications).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Verify safely" }));
    await waitFor(() => expect(getVerifications).toHaveBeenCalledTimes(1));
    expect(requestVerification).toHaveBeenCalledWith(11);
  });
});
