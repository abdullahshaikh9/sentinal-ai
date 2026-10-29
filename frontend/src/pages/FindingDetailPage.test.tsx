import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getFinding, getVerifications, requestVerification } from "../lib/api";
import { FindingDetailPage } from "./FindingDetailPage";

vi.mock("../lib/api", () => ({
  getFinding: vi.fn(),
  getVerifications: vi.fn(),
  requestVerification: vi.fn(),
}));

describe("FindingDetailPage verification history", () => {
  beforeEach(() => vi.clearAllMocks());

  it("refreshes a queued verification until its saved result is terminal", async () => {
    vi.mocked(getFinding).mockResolvedValue({
      id: 4,
      scan_id: 2,
      target_url: "https://owned.example/",
      title: "HSTS header missing",
      stable_id: "headers.hsts-missing",
      severity: "medium",
      category: "security-header",
      evidence: "The saved fixture observed no HSTS header.",
      explanation: "The observation may leave transport policy unclear.",
      remediation: "Review and configure an appropriate HSTS policy.",
      confidence: "high",
      evidence_data: { assessment: { impact: "The observed policy gap has context-dependent impact.", root_cause: "Server cause is not determined.", verification_status: "not_attempted", references: ["https://example.test/hsts"] } },
      dedup_key: "headers.hsts-missing",
    });
    vi.mocked(getVerifications)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ id: 8, scan_id: 2, finding_id: 4, status: "running", summary: "Queued", evidence: null, created_at: "2026-01-01T00:00:00Z" }])
      .mockResolvedValueOnce([{ id: 8, scan_id: 2, finding_id: 4, status: "failed", summary: "The original observation was reproduced.", evidence: "HSTS was absent.", created_at: "2026-01-01T00:00:00Z" }]);
    vi.mocked(requestVerification).mockResolvedValue({ id: 8, scan_id: 2, finding_id: 4, status: "pending", summary: "Queued", evidence: null, created_at: "2026-01-01T00:00:00Z" });

    render(
      <MemoryRouter initialEntries={["/findings/4"]}>
        <Routes><Route path="/findings/:findingId" element={<FindingDetailPage />} /></Routes>
      </MemoryRouter>,
    );

    await screen.findByText("The saved fixture observed no HSTS header.");
    expect(screen.getByText("The observed policy gap has context-dependent impact.")).toBeInTheDocument();
    expect(screen.getByText(/Verification status: not attempted/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Verify safely" }));

    expect(await screen.findByText("failed", {}, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText("The original observation was reproduced.")).toBeInTheDocument();
    expect(getVerifications).toHaveBeenCalledTimes(3);
  });
});
