import { useEffect, useMemo, useState } from "react";
import { ArrowRight, FileDown, FileText, LoaderCircle, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { downloadFindingsCsv, downloadReport, getReportHistory, getScans } from "../lib/api";
import type { ReportHistory, Scan } from "../types";

async function saveResponse(response: Response, filename: string) {
  if (!response.ok) throw new Error("The export could not be generated. Check your access and try again.");
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = filename; anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function ReportsPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [history, setHistory] = useState<ReportHistory[] | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selected = scans?.find((scan) => String(scan.id) === selectedId) ?? scans?.[0];
  const matches = useMemo(() => (scans ?? []).filter((scan) => scan.target_url.toLowerCase().includes(query.toLowerCase())), [scans, query]);
  const refreshHistory = () => getReportHistory().then((rows) => setHistory(Array.isArray(rows) ? rows : [])).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Report history could not be loaded."));
  useEffect(() => { getScans({ limit: 100 }).then((result) => setScans(result.items)).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Saved scans could not be loaded.")); refreshHistory(); }, []);
  async function exportFile(type: "pdf" | "csv") {
    if (!selected) return;
    setBusy(true); setError(null);
    try { const response = type === "pdf" ? await downloadReport(selected.id) : await downloadFindingsCsv(selected.id); await saveResponse(response, type === "pdf" ? `sentinel-scan-${selected.id}.pdf` : `sentinel-scan-${selected.id}-findings.csv`); await refreshHistory(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "The selected export could not be generated."); }
    finally { setBusy(false); }
  }
  return <>
    <div className="mb-8"><p className="eyebrow">Evidence exports</p><h1 className="page-title">Reports</h1><p className="page-subtitle">Generate downloadable reports from scans you own. Export history records the request; report files are generated from saved scan data when requested.</p></div>
    {error && <p role="alert" className="mb-5 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</p>}
    {scans === null ? <div className="section-panel flex items-center gap-3 text-sm text-slate-500"><LoaderCircle size={17} className="animate-spin" />Loading saved scans…</div> : scans.length === 0 ? <div className="empty-state"><FileText className="mx-auto mb-3 text-emerald" /><h2 className="font-semibold text-ink">No report sources yet</h2><p className="mt-2 text-sm text-slate-500">Run an authorized assessment before generating a report.</p></div> : <section className="section-panel"><h2 className="text-lg font-semibold text-ink">Generate an export</h2><div className="mt-4 grid gap-3 md:grid-cols-[1fr_1fr_auto_auto]"><label className="relative"><Search size={16} className="absolute left-3 top-3 text-slate-400" /><span className="sr-only">Filter scans by website</span><input className="field-input pl-9" aria-label="Filter scans by website" placeholder="Filter website" value={query} onChange={(event) => setQuery(event.target.value)} /></label><label><span className="sr-only">Report scan</span><select aria-label="Report scan" className="field-input" value={selected?.id ?? ""} onChange={(event) => setSelectedId(event.target.value)}>{matches.map((scan) => <option value={scan.id} key={scan.id}>{scan.target_url} · scan {scan.id}</option>)}</select></label><button className="button-primary" disabled={!selected || busy} onClick={() => void exportFile("pdf")}>{busy ? <LoaderCircle className="animate-spin" size={16} /> : <FileDown size={16} />}PDF report</button><button className="button-secondary" disabled={!selected || busy} onClick={() => void exportFile("csv")}>Findings CSV</button></div>{selected && <div className="mt-5 grid gap-3 sm:grid-cols-3"><div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Scan status</p><p className="mt-1 font-semibold capitalize text-ink">{selected.status}</p></div><div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Observed risk score</p><p className="mt-1 font-semibold text-ink">{selected.risk_score === null ? "Not available" : `${selected.risk_score}/100 · ${selected.risk_level ?? "unclassified"}`}</p></div><div className="rounded-lg bg-slate-50 p-3"><Link to={`/scans/${selected.id}`} className="text-sm font-semibold text-emerald">Review scan details <ArrowRight className="inline" size={15} /></Link></div></div>}</section>}
    <section className="section-panel mt-6"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-lg font-semibold text-ink">Export history</h2><p className="mt-1 text-sm text-slate-500">Persisted from report metadata; older exports may not be recorded.</p></div><button className="button-secondary" onClick={() => void refreshHistory()}>Refresh</button></div>{history === null ? <p className="text-sm text-slate-500">Loading export history…</p> : history.length === 0 ? <p className="text-sm text-slate-500">No report or CSV exports have been recorded.</p> : <div className="space-y-2">{history.map((entry) => <div key={entry.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-slate-50 p-3 text-sm"><div><p className="font-medium text-ink">{entry.target_url}</p><p className="mt-1 text-xs text-slate-500">{entry.report_type.toUpperCase()} · {new Date(entry.created_at).toLocaleString()}</p></div><Link to={`/scans/${entry.scan_id}`} className="text-xs font-semibold text-emerald">View saved scan</Link></div>)}</div>}</section>
  </>;
}
