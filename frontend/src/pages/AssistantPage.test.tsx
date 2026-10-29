import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { askAssistant, getAssistantStatus, getScan, getScans } from "../lib/api";
import type { ScanDetail } from "../types";
import { AssistantPage } from "./AssistantPage";

vi.mock("../lib/api", () => ({
  ApiError: class ApiError extends Error { constructor(message: string, public status: number) { super(message); } },
  askAssistant: vi.fn(),
  getAssistantStatus: vi.fn(),
  getScan: vi.fn(),
  getScans: vi.fn(),
}));

const savedScan: ScanDetail = {
  id: 3,
  target_url: "https://owned.example/",
  normalized_url: "https://owned.example/",
  status: "completed",
  risk_score: 15,
  risk_level: "medium",
  error_message: null,
  redirects: [],
  checks: { headers: "completed" },
  created_at: "2026-01-01T00:00:00Z",
  completed_at: "2026-01-01T00:01:00Z",
  findings: [{
    id: 5,
    stable_id: "headers.hsts-missing",
    title: "HSTS header missing",
    severity: "medium",
    category: "security-header",
    evidence: "The saved scan observed no HSTS header.",
    explanation: "Transport policy is unclear.",
    remediation: "Review an appropriate HSTS policy.",
    confidence: "high",
    evidence_data: null,
    dedup_key: "headers.hsts-missing",
  }],
};

describe("AssistantPage provider fallback labels", () => {
  beforeEach(() => vi.clearAllMocks());

  it("uses provider-neutral wording for local fallback answers", async () => {
    const scan = savedScan;
    vi.mocked(getAssistantStatus).mockResolvedValue({ configured: false, provider: "none", message: "No AI provider is configured.", local_guidance_available: true });
    vi.mocked(getScans).mockResolvedValue({ items: [scan], total: 1, limit: 50, offset: 0 });
    vi.mocked(getScan).mockResolvedValue(scan);
    vi.mocked(askAssistant).mockResolvedValue({ answer: "Local evidence guidance.", provider: "local-evidence-fallback", provider_message: "No AI provider is configured.", scan_id: 3, finding_id: null, evidence_references: ["scan:3", "finding:5"] });

    render(<MemoryRouter><AssistantPage /></MemoryRouter>);

    await screen.findByText("External AI is not configured");
    fireEvent.change(await screen.findByLabelText("Saved scan"), { target: { value: "3" } });
    fireEvent.change(screen.getByLabelText("Ask for defensive guidance"), { target: { value: "Summarize this saved scan." } });
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));

    expect(await screen.findByText("Local evidence guidance.")).toBeInTheDocument();
    expect(screen.getByText("Sentinel AI · local evidence fallback")).toBeInTheDocument();
    expect(screen.queryByText(/Gemini unavailable/i)).not.toBeInTheDocument();
  });

  it("allows retrying a failed provider-status request", async () => {
    vi.mocked(getAssistantStatus)
      .mockRejectedValueOnce(new Error("Status service unavailable."))
      .mockResolvedValueOnce({ configured: false, provider: "none", message: "No AI provider is configured.", local_guidance_available: true });
    vi.mocked(getScans).mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });

    render(<MemoryRouter><AssistantPage /></MemoryRouter>);

    expect(await screen.findByRole("alert")).toHaveTextContent("Status service unavailable.");
    fireEvent.click(screen.getByRole("button", { name: "Retry assistant status" }));
    expect(await screen.findByText("External AI is not configured")).toBeInTheDocument();
    expect(getAssistantStatus).toHaveBeenCalledTimes(2);
  });

  it("locks scan and finding context while an Assistant response is pending", async () => {
    vi.mocked(getAssistantStatus).mockResolvedValue({ configured: true, provider: "gemini", message: "Configured.", local_guidance_available: true });
    vi.mocked(getScans).mockResolvedValue({ items: [savedScan], total: 1, limit: 50, offset: 0 });
    vi.mocked(getScan).mockResolvedValue(savedScan);
    let resolveResponse!: (response: Awaited<ReturnType<typeof askAssistant>>) => void;
    vi.mocked(askAssistant).mockReturnValue(new Promise((resolve) => { resolveResponse = resolve; }));

    render(<MemoryRouter><AssistantPage /></MemoryRouter>);
    const scanSelect = await screen.findByLabelText("Saved scan");
    fireEvent.change(scanSelect, { target: { value: "3" } });
    await screen.findByRole("option", { name: "HSTS header missing" });
    fireEvent.change(screen.getByLabelText("Ask for defensive guidance"), { target: { value: "Summarize the evidence." } });
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));

    await waitFor(() => expect(askAssistant).toHaveBeenCalled());
    expect(scanSelect).toBeDisabled();
    expect(screen.getByLabelText("Finding (optional)")).toBeDisabled();
    expect(screen.getByText("Context: scan 3.")).toBeInTheDocument();

    resolveResponse({ answer: "Grounded answer.", provider: "gemini", provider_message: null, scan_id: 3, finding_id: null, evidence_references: ["scan:3", "finding:5"] });
    expect(await screen.findByText("Grounded answer.")).toBeInTheDocument();
  });
});
