import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GlobalSearch } from "./GlobalSearch";
import { searchRecords } from "../lib/api";

vi.mock("../lib/api", () => ({ searchRecords: vi.fn() }));

function Location() {
  const location = useLocation();
  return <output aria-label="Current route">{location.pathname}</output>;
}

describe("GlobalSearch", () => {
  beforeEach(() => {
    vi.mocked(searchRecords).mockReset();
  });
  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it("shows only returned authorized-record results and navigates to their existing pages", async () => {
    vi.mocked(searchRecords).mockResolvedValue([
      { kind: "asset", id: 7, label: "https://owned.example", description: "Authorized asset", href: "/domains" },
      { kind: "scan", id: 9, label: "https://owned.example", description: "Scan completed", href: "/scans/9" },
      { kind: "finding", id: 11, label: "Missing HSTS", description: "High finding · https://owned.example", href: "/findings/11" },
    ]);
    const user = userEvent.setup();
    render(<MemoryRouter><GlobalSearch /><Location /></MemoryRouter>);
    const input = screen.getByRole("combobox", { name: "Search assets, scans, and findings" });
    await user.type(input, "owned");

    const options = await screen.findAllByRole("option");
    expect(options).toHaveLength(3);
    expect(options[0]).toHaveAttribute("href", "/domains");
    expect(options[2]).toHaveAttribute("href", "/findings/11");
    await user.click(options[2]);    await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent("/findings/11"));
    expect(searchRecords).toHaveBeenCalledWith("owned");
  });

  it("shows an honest empty state and safe error state", async () => {
    vi.mocked(searchRecords).mockResolvedValueOnce([]).mockRejectedValueOnce(new Error("Search temporarily unavailable."));
    const user = userEvent.setup();
    render(<MemoryRouter><GlobalSearch /></MemoryRouter>);
    const input = screen.getByRole("combobox", { name: "Search assets, scans, and findings" });
    await user.type(input, "missing");
    expect(await screen.findByText("No matching records in your workspace.")).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "broken");
    expect(await screen.findByRole("alert")).toHaveTextContent("Search temporarily unavailable.");
  });

  it("supports Arrow-key selection and Enter navigation in search results", async () => {
    vi.mocked(searchRecords).mockResolvedValue([
      { kind: "asset", id: 7, label: "https://owned.example", description: "Authorized asset", href: "/domains" },
      { kind: "scan", id: 9, label: "https://owned.example", description: "Scan completed", href: "/scans/9" },
    ]);
    const user = userEvent.setup();
    render(<MemoryRouter><GlobalSearch /><Location /></MemoryRouter>);
    const input = screen.getByRole("combobox", { name: "Search assets, scans, and findings" });
    await user.type(input, "owned");
    await screen.findAllByRole("option");
    await user.keyboard("{ArrowDown}{ArrowDown}");
    expect(input).toHaveAttribute("aria-activedescendant", "global-search-option-1");
    await user.keyboard("{Enter}");
    await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent("/scans/9"));
  });

  it("ignores an older in-flight response after the query changes", async () => {
    let resolveOlder!: (items: Array<{ kind: "scan"; id: number; label: string; description: string; href: string }>) => void;
    let resolveNewer!: (items: Array<{ kind: "scan"; id: number; label: string; description: string; href: string }>) => void;
    vi.mocked(searchRecords).mockImplementation((query) => new Promise<import("../types").SearchResult[]>((resolve) => {
      if (query === "older") resolveOlder = resolve;
      else resolveNewer = resolve;
    }));
    const user = userEvent.setup();
    render(<MemoryRouter><GlobalSearch /></MemoryRouter>);
    const input = screen.getByRole("combobox", { name: "Search assets, scans, and findings" });
    await user.type(input, "older");
    await waitFor(() => expect(searchRecords).toHaveBeenCalledWith("older"));
    await user.clear(input);
    await user.type(input, "newer");
    await waitFor(() => expect(searchRecords).toHaveBeenCalledWith("newer"));
    await act(async () => { resolveNewer([{ kind: "scan", id: 2, label: "New result", description: "New", href: "/scans/2" }]); });
    expect(screen.getByText("New result")).toBeInTheDocument();
    await act(async () => { resolveOlder([{ kind: "scan", id: 1, label: "Old result", description: "Old", href: "/scans/1" }]); });
    expect(screen.queryByText("Old result")).not.toBeInTheDocument();
    expect(screen.getByText("New result")).toBeInTheDocument();
  });
});
