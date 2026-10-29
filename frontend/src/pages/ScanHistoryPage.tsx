import { FormEvent, useEffect, useState } from "react";
import { ArrowLeftRight, ArrowRight, LoaderCircle, Search } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { ApiError, getAssets, getScans } from "../lib/api";
import type { Asset, Scan, ScanList } from "../types";

const pageSize = 20;
const date = (value: string) => new Date(value).toLocaleString();

export function ScanHistoryPage() {
  const [searchParams] = useSearchParams();
  const [result, setResult] = useState<ScanList | null>(null);
  const [query, setQuery] = useState(() => searchParams.get("q") ?? "");
  const [appliedQuery, setAppliedQuery] = useState(() => searchParams.get("q") ?? "");
  const [status, setStatus] = useState(() => ["pending", "running", "completed", "partial", "failed"].includes(searchParams.get("status") ?? "") ? searchParams.get("status") ?? "" : "");
  const [dateFrom, setDateFrom] = useState(searchParams.get("date_from") ?? "");
  const [dateTo, setDateTo] = useState(searchParams.get("date_to") ?? "");
  const [assetId, setAssetId] = useState(searchParams.get("asset_id") ?? "");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  useEffect(() => { getAssets().then((rows) => setAssets(Array.isArray(rows) ? rows : [])).catch(() => setAssets([])); }, []);
  useEffect(() => {
    const urlStatus = searchParams.get("status") ?? "";
    const validStatus = ["pending", "running", "completed", "partial", "failed"].includes(urlStatus) ? urlStatus : "";
    const urlAssetId = searchParams.get("asset_id") ?? "";
    const urlQ = searchParams.get("q") ?? "";
    const urlDateFrom = searchParams.get("date_from") ?? "";
    const urlDateTo = searchParams.get("date_to") ?? "";
    setStatus(validStatus);
    setAssetId(urlAssetId);
    setQuery(urlQ);
    setAppliedQuery(urlQ);
    setDateFrom(urlDateFrom);
    setDateTo(urlDateTo);
    setOffset(0);
  }, [searchParams]);
  useEffect(() => {
    let active = true; setLoading(true); setError(null);
    getScans({ limit: pageSize, offset, q: appliedQuery, status: status || undefined, date_from: dateFrom || undefined, date_to: dateTo || undefined, asset_id: assetId ? Number(assetId) : undefined })
      .then((data) => { if (active) setResult({ ...data, total: data.total ?? data.items.length }); })
      .catch((reason: unknown) => { if (active) setError(reason instanceof ApiError ? reason.message : "Scan history could not be loaded."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [offset, appliedQuery, status, dateFrom, dateTo, assetId, refreshKey]);
  function search(event: FormEvent) { event.preventDefault(); setOffset(0); setAppliedQuery(query.trim()); }
  const scans: Scan[] = result?.items ?? [];
  return <>
    <div className="mb-8 flex flex-wrap items-start justify-between gap-4"><div><p className="eyebrow">Assessment records</p><h1 className="page-title">Security scans</h1><p className="page-subtitle">Search your saved assessments and compare repeated observations.</p></div><div className="flex flex-wrap gap-2"><Link to="/scans/compare" className="button-secondary"><ArrowLeftRight size={16} />Compare scans</Link><Link to="/scans/new" className="button-primary">New scan <ArrowRight size={16} /></Link></div></div>
    <form onSubmit={search} className="section-panel mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-6"><label className="relative min-w-0 xl:col-span-2"><Search className="absolute left-3 top-3 text-slate-400" size={17} /><span className="sr-only">Search scan targets</span><input className="field-input pl-10" aria-label="Search scan targets" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search website URL" /></label><label><span className="sr-only">Filter scan status</span><select className="field-input" aria-label="Filter scan status" value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }}><option value="">All statuses</option>{["pending", "running", "completed", "partial", "failed"].map((item) => <option value={item} key={item}>{item}</option>)}</select></label><label><span className="sr-only">Filter scan start date from</span><input className="field-input" type="date" aria-label="Filter scan start date from" value={dateFrom} onChange={(event) => { setDateFrom(event.target.value); setOffset(0); }} /></label><label><span className="sr-only">Filter scan start date to</span><input className="field-input" type="date" aria-label="Filter scan start date to" value={dateTo} onChange={(event) => { setDateTo(event.target.value); setOffset(0); }} /></label><label><span className="sr-only">Filter by asset</span><select className="field-input" aria-label="Filter by asset" value={assetId} onChange={(event) => { setAssetId(event.target.value); setOffset(0); }}><option value="">All assets</option>{assets.map((asset) => <option value={asset.id} key={asset.id}>{asset.normalized_url}</option>)}</select></label><button className="button-primary" type="submit"><Search size={16} />Search</button></form>
    {error && <p role="alert" className="mb-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}<button type="button" onClick={() => setRefreshKey((value) => value + 1)} className="ml-3 font-semibold underline">Retry</button></p>}
    {loading && !result ? <div className="section-panel flex items-center gap-3 text-sm text-slate-500"><LoaderCircle size={17} className="animate-spin" />Loading saved scans…</div> : scans.length === 0 ? <div className="empty-state"><h2 className="font-semibold text-ink">{result?.total ? "No scans on this page" : "No matching scans"}</h2><p className="mt-2 text-sm text-slate-500">{result?.total ? "Use the pagination controls to view other records." : "Adjust the search or start an authorized scan to create an assessment record."}</p></div> : <section className="section-panel"><div className="mb-4 flex flex-wrap justify-between gap-3"><p className="text-sm text-slate-500">Showing {offset + 1}–{Math.min(offset + scans.length, result?.total ?? 0)} of {result?.total ?? scans.length} records</p>{loading && <LoaderCircle size={16} className="animate-spin text-emerald" aria-label="Refreshing scans" />}</div><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-3 py-3">Target</th><th className="px-3 py-3">Status</th><th className="px-3 py-3">Observed risk</th><th className="px-3 py-3">Started</th><th className="px-3 py-3">Details</th></tr></thead><tbody className="divide-y divide-slate-100">{scans.map((scan) => <tr key={scan.id}><td className="max-w-xs truncate px-3 py-4 font-medium text-ink">{scan.target_url}</td><td className="px-3 py-4 capitalize text-slate-600">{scan.status}</td><td className="px-3 py-4 text-slate-600">{scan.risk_score === null ? "Not available" : `${scan.risk_score}/100 · ${scan.risk_level ?? "unclassified"}`}</td><td className="whitespace-nowrap px-3 py-4 text-slate-500">{date(scan.created_at)}</td><td className="px-3 py-4"><Link className="font-semibold text-emerald" to={`/scans/${scan.id}`}>Open <ArrowRight size={14} className="inline" /></Link></td></tr>)}</tbody></table></div><div className="mt-5 flex justify-end gap-2"><button className="button-secondary" disabled={offset === 0 || loading} onClick={() => setOffset((value) => Math.max(0, value - pageSize))}>Previous</button><button className="button-secondary" disabled={loading || offset + scans.length >= (result?.total ?? 0)} onClick={() => setOffset((value) => value + pageSize)}>Next</button></div></section>}
  </>;
}
