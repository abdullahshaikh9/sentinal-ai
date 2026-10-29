import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowRight, Radar, RefreshCw, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { EmptyState } from "../components/EmptyState";
import { useAuth } from "../auth/AuthContext";
import { getDashboardOverview } from "../lib/api";
import type { DashboardOverview, Finding } from "../types";

const date = (value: string | null) => {
  if (!value) return "Not recorded";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Not recorded" : parsed.toLocaleString();
};
const severityOrder: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];
const severityColors: Record<Finding["severity"], string> = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#2563eb", info: "#64748b" };

function Metric({ label, value, note, to }: { label: string; value: string; note: string; to?: string }) {
  const body = <><p className="text-xs font-semibold uppercase tracking-[.12em] text-slate-500">{label}</p><p className="mt-3 text-3xl font-semibold tracking-tight text-ink">{value}</p><p className="mt-2 text-xs text-slate-500">{note}</p></>;
  return to ? <Link to={to} className="metric-card block rounded-xl border border-slate-200 p-5 transition hover:border-emerald focus-visible:outline-offset-2">{body}</Link> : <section className="metric-card rounded-xl border border-slate-200 p-5">{body}</section>;
}

export function DashboardPage() {
  const { user } = useAuth();
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const requestId = useRef(0);
  const load = useCallback(() => {
    const currentRequest = ++requestId.current;
    setError(null);
    setLoading(true);
    getDashboardOverview().then((data) => { if (requestId.current === currentRequest) setOverview(data); }).catch((reason: unknown) => { if (requestId.current === currentRequest) setError(reason instanceof Error ? reason.message : "The security overview could not be loaded."); }).finally(() => { if (requestId.current === currentRequest) setLoading(false); });
  }, []);
  useEffect(() => { load(); return () => { requestId.current += 1; }; }, [load]);

  const severityCounts = useMemo(() => severityOrder.map((severity) => ({ severity, count: overview?.findings_by_severity[severity] ?? 0, fill: severityColors[severity] })), [overview]);
  const failedOrPartial = (overview?.scans_by_status.failed ?? 0) + (overview?.scans_by_status.partial ?? 0);
  const riskHistory = (overview?.risk_history ?? []).map((point) => ({ ...point, date: new Date(point.recorded_at).toLocaleDateString() }));
  const firstName = user?.display_name.trim().split(/\s+/)[0] || "there";

  if (loading && !overview) return <div className="space-y-5" role="status" aria-label="Loading security overview"><div className="section-panel h-28 animate-pulse" /><div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{Array.from({ length: 6 }, (_, index) => <div key={index} className="metric-card h-32 animate-pulse rounded-xl border border-slate-200" />)}</div><div className="grid gap-5 xl:grid-cols-2"><div className="section-panel h-72 animate-pulse" /><div className="section-panel h-72 animate-pulse" /></div></div>;

  return <>
    <div className="mb-8 flex flex-wrap items-start justify-between gap-4">
      <div><p className="eyebrow">Cyber command center</p><h1 className="page-title">Security overview</h1><p className="page-subtitle">Welcome, {firstName}. Review persisted assessment records and follow up on evidence-backed observations.</p><p className="mt-2 text-xs text-slate-500">Risk scores summarize scanner observations; they are not a percentage of security or proof that a target is secure.</p></div>
      <div className="flex flex-wrap gap-2"><Link to="/domains" className="button-secondary">Add asset</Link><Link to="/scans/new" className="button-primary"><Radar size={16} />Start authorized scan <ArrowRight size={16} /></Link></div>
    </div>
    {error && <div role="alert" className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800"><span>{error}</span><button type="button" onClick={load} className="inline-flex items-center gap-2 font-semibold"><RefreshCw size={14} />Retry</button></div>}

    {overview && <>
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <Metric label="Registered assets" value={String(overview?.assets_total ?? 0)} note={`${overview?.assets_scanned ?? 0} with a linked scan`} to="/domains" />
      <Metric label="Open findings" value={String(overview?.open_findings ?? 0)} note={`${overview?.resolved_findings ?? 0} marked fixed`} to="/findings" />
      <Metric label="Critical / high open" value={String(overview?.high_critical_open ?? 0)} note="Open or in-progress records" to="/findings?severity=critical,high" />
      <Metric label="Completed scans" value={String(overview?.scans_by_status.completed ?? 0)} note="Persisted completed records" to="/scans?status=completed" />
      <Metric label="Failed / partial scans" value={String(failedOrPartial)} note={`${overview?.scans_by_status.failed ?? 0} failed · ${overview?.scans_by_status.partial ?? 0} partial`} to="/scans" />
      <Metric label="Awaiting verification" value={String(overview?.awaiting_verification ?? 0)} note="Latest attempt is pending or running" to="/verification" />
    </div>

    <div className="mt-6 flex flex-wrap gap-4 text-sm"><Link to="/findings" className="font-semibold text-emerald">View findings <ArrowRight className="inline" size={14} /></Link><Link to="/scans/compare" className="font-semibold text-emerald">Compare scans <ArrowRight className="inline" size={14} /></Link><Link to="/reports" className="font-semibold text-emerald">View reports <ArrowRight className="inline" size={14} /></Link></div>

    {overview.scans_total === 0 ? <div className="mt-6"><EmptyState title="No security scans yet" description="Start an authorized assessment to create a real baseline. Sentinel will not invent scan statistics." actionLabel="Start a new scan" /></div> : <>
      <div className="mt-6 grid gap-5 xl:grid-cols-[1.15fr_.85fr]">
        <section className="section-panel"><div className="mb-5 flex items-center justify-between gap-3"><div><h2 className="text-lg font-semibold text-ink">Recent assessments</h2><p className="mt-1 text-sm text-slate-500">Latest persisted scans for your account</p></div><Link to="/scans" className="text-sm font-semibold text-emerald">View history</Link></div>
          <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-3 py-3">Target</th><th className="px-3 py-3">State</th><th className="px-3 py-3">Findings</th><th className="px-3 py-3">Risk score</th><th className="px-3 py-3">Check coverage</th><th className="px-3 py-3">Time</th></tr></thead><tbody className="divide-y divide-slate-100">{overview.recent_scans.map((scan) => { const checks = Object.values(scan.checks ?? {}); const complete = checks.filter((value) => value === "completed").length; return <tr key={scan.id}><td className="max-w-[14rem] truncate px-3 py-4"><Link className="font-medium text-ink hover:text-emerald" to={`/scans/${scan.id}`}>{scan.target_url}</Link></td><td className="px-3 py-4 capitalize text-slate-500">{scan.status}</td><td className="px-3 py-4 text-slate-500">{scan.findings_count}</td><td className="px-3 py-4 text-slate-500">{scan.risk_score === null ? "Not available" : `${scan.risk_score}/100`}</td><td className="px-3 py-4 text-slate-500">{checks.length ? `${complete}/${checks.length} checks` : "Not recorded"}</td><td className="whitespace-nowrap px-3 py-4 text-xs text-slate-500">{date(scan.completed_at ?? scan.created_at)}</td></tr>; })}</tbody></table></div>
          <p className="mt-3 text-xs text-slate-500">Risk score is a scanner-derived summary. Skipped, failed, and inconclusive checks do not count as secure.</p>
        </section>
        <section className="section-panel"><div className="mb-4"><h2 className="text-lg font-semibold text-ink">Findings by severity</h2><p className="mt-1 text-sm text-slate-500">Persisted findings across all scans owned by this account</p></div>
          {Object.values(overview.findings_by_severity).reduce((sum, count) => sum + count, 0) === 0 ? <p className="rounded-lg bg-slate-50 p-4 text-sm text-slate-500">No findings were recorded for your scans.</p> : <><div className="h-56 w-full" role="img" aria-label="Persisted finding counts by severity"><ResponsiveContainer width="100%" height="100%"><BarChart data={severityCounts} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}><CartesianGrid stroke="#263a54" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="severity" tick={{ fill: "#9cafc4", fontSize: 11 }} axisLine={{ stroke: "#344963" }} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#9cafc4", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "#101e31", border: "1px solid #344963", borderRadius: 10, color: "#e8f3ff" }} /><Bar dataKey="count" name="Findings" radius={[5, 5, 0, 0]}>{severityCounts.map((row) => <Cell key={row.severity} fill={row.fill} />)}</Bar></BarChart></ResponsiveContainer></div><ul className="mt-3 flex flex-wrap gap-x-4 gap-y-2">{severityCounts.map((row) => <li key={row.severity} className="flex items-center gap-2 text-xs capitalize text-slate-500"><span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: row.fill }} />{row.severity}: {row.count}</li>)}</ul></>}
          <Link to="/findings" className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-emerald">Review findings <ArrowRight size={15} /></Link>
        </section>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <section className="section-panel"><div className="mb-4"><h2 className="text-lg font-semibold text-ink">Action center</h2><p className="mt-1 text-sm text-slate-500">Items derived from current persisted records</p></div><ul className="space-y-2 text-sm">
          {(overview.high_critical_open > 0) && <li className="rounded-lg bg-red-50 p-3 text-red-800"><Link to="/findings?severity=critical,high" className="font-semibold">{overview.high_critical_open} critical/high findings are open or in progress</Link></li>}
          {overview.awaiting_verification > 0 && <li className="rounded-lg bg-amber-50 p-3 text-amber-800"><Link to="/verification" className="font-semibold">{overview.awaiting_verification} finding verification {overview.awaiting_verification === 1 ? "is" : "requests are"} still running</Link></li>}
          {(overview.scans_by_status.failed ?? 0) > 0 && <li className="rounded-lg bg-amber-50 p-3 text-amber-800"><Link to="/scans?status=failed" className="font-semibold">{overview.scans_by_status.failed} failed scans need review</Link></li>}
          {(overview.scans_by_status.partial ?? 0) > 0 && <li className="rounded-lg bg-amber-50 p-3 text-amber-800"><Link to="/scans?status=partial" className="font-semibold">{overview.scans_by_status.partial} partial scans need review</Link><span className="block pt-1 text-xs">Skipped or inconclusive checks are not treated as secure.</span></li>}
          {overview.assets_total > overview.assets_scanned && <li className="rounded-lg bg-slate-50 p-3 text-slate-600"><Link to="/domains" className="font-semibold">{overview.assets_total - overview.assets_scanned} registered assets have no linked scan yet</Link></li>}
          {overview.high_critical_open === 0 && overview.awaiting_verification === 0 && failedOrPartial === 0 && overview.assets_total <= overview.assets_scanned && <li className="rounded-lg bg-slate-50 p-3 text-slate-600">No outstanding items were found in the records summarized here.</li>}
        </ul><div className="mt-5 border-t border-slate-200 pt-4"><h3 className="text-sm font-semibold text-ink">Verification outcomes</h3><p className="mt-1 text-xs text-slate-500">Attempt counts from saved verification records</p><div className="mt-3 flex flex-wrap gap-2">{Object.entries(overview.verification_outcomes).filter(([, count]) => count > 0).map(([state, count]) => <span key={state} className="rounded-full bg-slate-100 px-3 py-1 text-xs capitalize text-slate-600">{state.replaceAll("_", " ")}: {count}</span>)}{Object.values(overview.verification_outcomes).every((count) => count === 0) && <span className="text-xs text-slate-500">No verification attempts recorded.</span>}</div></div></section>

        <section className="section-panel"><div className="mb-4"><h2 className="text-lg font-semibold text-ink">Asset overview</h2><p className="mt-1 text-sm text-slate-500">Latest linked scan and findings for registered assets</p></div>{overview.assets.length === 0 ? <p className="rounded-lg bg-slate-50 p-4 text-sm text-slate-500">No registered assets yet. <Link className="font-semibold text-emerald" to="/domains">Add an authorized asset</Link>.</p> : <div className="space-y-2">{overview.assets.map((asset) => <article key={asset.id} className="rounded-lg bg-slate-50 p-3"><div className="flex flex-wrap items-start justify-between gap-2"><Link to={asset.latest_scan_id ? `/scans/${asset.latest_scan_id}` : "/domains"} className="max-w-full break-all text-sm font-semibold text-ink hover:text-emerald">{asset.normalized_url}</Link><span className="rounded-full bg-slate-100 px-2 py-1 text-xs capitalize text-slate-600">{asset.latest_scan_status ?? "not scanned"}</span></div><p className="mt-2 text-xs text-slate-500">Last scan: {date(asset.last_scan_at)} · Open findings on latest scan: {asset.open_findings}</p></article>)}</div>}<Link to="/domains" className="mt-3 inline-flex items-center gap-1 text-sm font-semibold text-emerald">All assets <ArrowRight size={15} /></Link></section>
      </div>

      {riskHistory.length > 1 && <section className="section-panel mt-5"><div className="mb-4"><h2 className="text-lg font-semibold text-ink">Recorded risk history</h2><p className="mt-1 text-sm text-slate-500">Actual completed or partial scan scores, in time order; this chart does not imply remediation.</p></div><div className="h-56 w-full" role="img" aria-label="Recorded risk scores over time"><ResponsiveContainer width="100%" height="100%"><LineChart data={riskHistory}><CartesianGrid stroke="#263a54" strokeDasharray="3 3" /><XAxis dataKey="date" tick={{ fill: "#9cafc4", fontSize: 11 }} /><YAxis domain={[0, 100]} tick={{ fill: "#9cafc4", fontSize: 11 }} /><Tooltip contentStyle={{ background: "#101e31", border: "1px solid #344963", borderRadius: 10, color: "#e8f3ff" }} formatter={(value) => [`${value}/100`, "Observed score"]} /><Line type="monotone" dataKey="risk_score" name="Observed score" stroke="#35d4ed" strokeWidth={2} dot={{ r: 3 }} /></LineChart></ResponsiveContainer></div></section>}

      {overview.activity.length > 0 && <section className="section-panel mt-5"><div className="mb-4 flex items-center gap-2"><Activity size={17} className="text-emerald" /><h2 className="font-semibold text-ink">Recent activity</h2><Link to="/activity" className="ml-auto text-xs font-semibold text-emerald">Full log</Link></div><div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">{overview.activity.map((event) => <article key={event.id} className="rounded-lg bg-slate-50 p-3"><p className="text-sm text-slate-600">{event.summary}</p><p className="mt-2 text-[10px] uppercase tracking-wide text-slate-500">{event.event_type} · {date(event.created_at)}</p></article>)}</div></section>}
      {failedOrPartial > 0 && <p className="mt-5 flex items-center gap-2 text-xs text-amber-800"><ShieldAlert size={15} />Failed or partial scans are shown as incomplete; skipped checks are not treated as secure.</p>}
    </>}
    </>}
  </>;
}
