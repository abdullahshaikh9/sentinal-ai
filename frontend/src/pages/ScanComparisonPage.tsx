import { useEffect, useState } from "react";
import { ArrowDown, ArrowLeftRight, ArrowUp, LoaderCircle } from "lucide-react";
import { compareScans, getScans } from "../lib/api";
import type { Scan, ScanComparison } from "../types";

export function ScanComparisonPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [earlier, setEarlier] = useState("");
  const [later, setLater] = useState("");
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { getScans({ limit: 100 }).then((result) => setScans(result.items)).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Scans could not be loaded.")); }, []);
  const selectable = scans?.filter((scan) => scan.status === "completed" || scan.status === "partial") ?? [];
  const left = selectable.find((scan) => String(scan.id) === earlier);
  const comparisonGroups: Array<[string, ScanComparison["new_findings"]]> = comparison ? [["New observations", comparison.new_findings], ["No longer observed", comparison.no_longer_observed], ["Still present", comparison.still_present]] : [];
  const sameTarget = selectable.filter((scan) => left && (scan.normalized_url ?? scan.target_url).replace(/\/$/, "").toLowerCase() === (left.normalized_url ?? left.target_url).replace(/\/$/, "").toLowerCase());
  async function run() {
    if (!earlier || !later) return;
    setBusy(true); setError(null); setComparison(null);
    try { setComparison(await compareScans(Number(earlier), Number(later))); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "The scans could not be compared."); }
    finally { setBusy(false); }
  }
  return <>
    <div className="mb-8"><p className="eyebrow">Historical analysis</p><h1 className="page-title">Scan comparison</h1><p className="page-subtitle">Compare saved observations for the same authorized target. A later absence does not prove a fix.</p></div>
    {error && <p role="alert" className="mb-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</p>}
    {scans === null ? <div className="section-panel flex items-center gap-3 text-sm text-slate-500"><LoaderCircle size={17} className="animate-spin" />Loading saved scans…</div> : selectable.length < 2 ? <div className="empty-state"><h2 className="font-semibold text-ink">More scan history is needed</h2><p className="mt-2 text-sm text-slate-500">Comparison requires two completed or partial scans of the same target.</p></div> : <section className="section-panel"><div className="grid gap-4 md:grid-cols-[1fr_auto_1fr_auto] md:items-end"><label className="text-sm font-medium text-ink">Earlier scan<select className="field-input mt-2" value={earlier} onChange={(event) => { setEarlier(event.target.value); setLater(""); setComparison(null); }}><option value="">Choose earlier scan</option>{selectable.map((scan) => <option key={scan.id} value={scan.id}>{scan.target_url} · #{scan.id}</option>)}</select></label><ArrowLeftRight className="hidden text-emerald md:block" /><label className="text-sm font-medium text-ink">Later scan<select className="field-input mt-2" value={later} onChange={(event) => { setLater(event.target.value); setComparison(null); }} disabled={!earlier}><option value="">Choose later scan</option>{sameTarget.filter((scan) => String(scan.id) !== earlier).map((scan) => <option key={scan.id} value={scan.id}>{scan.target_url} · #{scan.id}</option>)}</select></label><button className="button-primary" disabled={!earlier || !later || busy} onClick={() => void run()}>{busy ? <LoaderCircle size={16} className="animate-spin" /> : <ArrowLeftRight size={16} />}Compare</button></div></section>}
    {comparison && <div className="mt-6 space-y-5"><section className="section-panel"><p className="eyebrow">Observed risk score</p><h2 className="text-lg font-semibold text-ink">{comparison.risk_score_before === null || comparison.risk_score_after === null ? "Score unavailable for one or both scans" : <>{comparison.risk_score_before}/100 → {comparison.risk_score_after}/100 {comparison.risk_score_delta !== null && (comparison.risk_score_delta > 0 ? <ArrowUp className="inline text-red-400" /> : comparison.risk_score_delta < 0 ? <ArrowDown className="inline text-emerald" /> : "· no change")}{comparison.risk_score_delta !== null && comparison.risk_score_delta !== 0 ? ` (${comparison.risk_score_delta > 0 ? "+" : ""}${comparison.risk_score_delta})` : ""}</>}</h2><p className="mt-2 text-sm leading-6 text-slate-500">{comparison.limitation}</p><p className="mt-2 text-xs text-slate-500">Scoring method: severity weights are critical 40, high 25, medium 15, low 5, info 0; totals are capped at 100. The delta is later score minus earlier score.</p></section><div className="grid gap-4 md:grid-cols-2">{comparisonGroups.map(([heading, findings]) => <section className="section-panel" key={heading}><h2 className="mb-3 font-semibold text-ink">{heading} <span className="text-sm text-slate-500">({findings.length})</span></h2>{findings.length === 0 ? <p className="text-sm text-slate-500">No records in this category.</p> : <ul className="space-y-2">{findings.map((finding, idx) => <li key={`${finding.stable_id}-${idx}`} className="rounded-lg bg-slate-50 p-3 text-sm"><span className="font-medium text-ink">{finding.title}</span><span className="ml-2 rounded-full bg-slate-200 px-2 py-1 text-[10px] uppercase text-slate-700">{finding.severity}</span></li>)}</ul>}</section>)}{comparison.severity_changes.length > 0 && <section className="section-panel md:col-span-2"><h2 className="font-semibold text-ink">Severity changed</h2><ul className="mt-3 space-y-2">{comparison.severity_changes.map((item, idx) => <li key={`${item.stable_id}-${idx}`} className="rounded-lg bg-slate-50 p-3 text-sm"><span className="font-medium text-ink">{item.title}</span><span className="ml-3 text-slate-500">{item.before} → {item.after}</span></li>)}</ul></section>}</div></div>}
  </>;
}
