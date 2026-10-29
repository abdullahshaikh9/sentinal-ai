import { useEffect, useMemo, useState } from "react";
import { Clock3, LoaderCircle, Search, ShieldCheck } from "lucide-react";
import { ApiError, getRemediation, getRemediationHistory, updateRemediation } from "../lib/api";
import type { RemediationChange, RemediationItem, RemediationStatus } from "../types";

const labels: Record<RemediationStatus, string> = { open: "Open", in_progress: "In Progress", fixed: "Fixed", accepted_risk: "Accepted Risk" };
const transitions: Record<RemediationStatus, RemediationStatus[]> = { open: ["in_progress", "accepted_risk"], in_progress: ["open", "fixed", "accepted_risk"], fixed: ["open", "in_progress"], accepted_risk: ["open", "in_progress"] };

export function RemediationPage() {
  const [items, setItems] = useState<RemediationItem[] | null>(null);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [history, setHistory] = useState<Record<number, RemediationChange[]>>({});
  const [historyOpen, setHistoryOpen] = useState<number | null>(null);

  const load = () => { setError(null); getRemediation().then(setItems).catch((reason: unknown) => setError(reason instanceof ApiError ? reason.message : "Remediation tasks could not be loaded.")); };
  useEffect(() => { load(); }, []);

  const visible = useMemo(() => (items ?? []).filter((item) => {
    const matchesStatus = statusFilter === "all" || item.status === statusFilter;
    const matchesText = `${item.title} ${item.target_url} ${item.remediation ?? ""}`.toLowerCase().includes(query.toLowerCase());
    return matchesStatus && matchesText;
  }), [items, query, statusFilter]);

  async function changeStatus(item: RemediationItem, next: RemediationStatus) {
    setBusyId(item.finding_id); setError(null);
    try { const updated = await updateRemediation(item.finding_id, next); setItems((current) => current?.map((row) => row.finding_id === item.finding_id ? updated : row) ?? null); }
    catch (reason) { setError(reason instanceof ApiError ? reason.message : "The remediation status could not be saved."); }
    finally { setBusyId(null); }
  }

  async function toggleHistory(findingId: number) {
    if (historyOpen === findingId) { setHistoryOpen(null); return; }
    setHistoryOpen(findingId);
    if (history[findingId]) return;
    try { const result = await getRemediationHistory(findingId); setHistory((current) => ({ ...current, [findingId]: result })); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Change history could not be loaded."); }
  }

  return <>
    <div className="mb-8"><p className="eyebrow">Action tracking</p><h1 className="page-title">Remediation center</h1><p className="page-subtitle">Track owner-reviewed remediation against persisted findings. A manually selected Fixed status is a workflow record, not independent scan verification. Sentinel does not make changes to your websites.</p></div>
    {error && <div className="mb-5 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700" role="alert">{error}<button onClick={load} className="ml-3 font-semibold underline">Retry</button></div>}
    <div className="mb-5 grid gap-3 md:grid-cols-[1fr_220px]"><label className="relative"><Search className="absolute left-3 top-3 text-slate-400" size={17} /><span className="sr-only">Search remediation</span><input className="field-input pl-10" aria-label="Search remediation" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search finding, target, or action" /></label><select className="field-input" aria-label="Filter remediation status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="all">All statuses</option>{Object.entries(labels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></div>
    {items === null ? <div className="section-panel flex items-center gap-3 text-sm text-slate-500"><LoaderCircle className="animate-spin" size={17} />Loading saved finding status…</div> : visible.length === 0 ? <div className="empty-state"><ShieldCheck className="mx-auto mb-3 text-emerald" /><h2 className="font-semibold text-ink">{items.length ? "No matching remediation tasks" : "No remediation work recorded"}</h2><p className="mt-2 text-sm text-slate-500">{items.length ? "Adjust the search or status filter." : "Status tracking appears when your saved scans contain findings."}</p></div> : <div className="space-y-4">{visible.map((item) => <article className="section-panel" key={item.finding_id}><div className="flex flex-wrap items-start justify-between gap-4"><div className="min-w-0"><p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{item.severity} · scan {item.scan_id}</p><h2 className="mt-1 font-semibold text-ink">{item.title}</h2><p className="mt-1 truncate text-xs text-slate-500">{item.target_url}</p><p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">{item.remediation ?? "No remediation was recorded for this finding."}</p></div><div className="flex min-w-40 items-center gap-2"><label className="sr-only" htmlFor={`remediation-${item.finding_id}`}>Status for {item.title}</label><select id={`remediation-${item.finding_id}`} aria-label={`Status for ${item.title}`} className="field-input" value={item.status} disabled={busyId === item.finding_id} onChange={(event) => void changeStatus(item, event.target.value as RemediationStatus)}>{[item.status, ...transitions[item.status]].map((state) => <option key={state} value={state}>{labels[state]}</option>)}</select>{busyId === item.finding_id && <LoaderCircle className="animate-spin text-emerald" size={17} />}</div></div><div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-3"><span className="text-xs text-slate-500">{item.updated_at ? `Updated ${new Date(item.updated_at).toLocaleString()}` : "No status changes recorded"}</span><button onClick={() => void toggleHistory(item.finding_id)} className="inline-flex items-center gap-2 text-xs font-semibold text-emerald"><Clock3 size={14} />{historyOpen === item.finding_id ? "Hide change history" : "View change history"}</button></div>{historyOpen === item.finding_id && <div className="mt-3 space-y-2" aria-label={`Change history for ${item.title}`}>{history[item.finding_id] === undefined ? <p className="text-sm text-slate-500">Loading audit history…</p> : history[item.finding_id].length === 0 ? <p className="text-sm text-slate-500">No changes have been recorded.</p> : history[item.finding_id].map((change) => <p key={change.id} className="rounded-lg bg-slate-50 p-3 text-xs text-slate-600">{change.from_status ? labels[change.from_status] : "Initial"} → {labels[change.to_status]} · changed by user {change.changed_by} · {new Date(change.created_at).toLocaleString()}</p>)}</div>}</article>)}</div>}
  </>;
}
