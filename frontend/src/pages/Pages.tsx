import { FormEvent, ReactNode, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AlertCircle, ArrowLeft, ArrowRight, FileDown, LoaderCircle, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { EmptyState } from "../components/EmptyState";
import { ApiError, createScan, downloadFindingsCsv, downloadReport, getActivity, getAssetOverview, getAssets, getFindingsOverview, getScan, getVerificationOverview, getVerifications, registerAsset, requestVerification } from "../lib/api";
import type { Finding, ScanDetail, VerificationAttempt, VerificationOverviewItem } from "../types";

function formatDate(value: string | null) { return value ? new Date(value).toLocaleString() : "Not recorded"; }
function StatusBadge({ status }: { status: string }) { const styles: Record<string, string> = { completed: "bg-emerald-50 text-emerald-700", running: "bg-amber-50 text-amber-700", pending: "bg-slate-100 text-slate-600", partial: "bg-amber-50 text-amber-700", failed: "bg-red-50 text-red-700" }; return <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${styles[status] ?? styles.pending}`}>{status}</span>; }
function SeverityBadge({ severity }: { severity: Finding["severity"] }) { const styles: Record<Finding["severity"], string> = { critical: "bg-red-100 text-red-800", high: "bg-red-50 text-red-700", medium: "bg-amber-100 text-amber-800", low: "bg-slate-100 text-slate-700", info: "bg-blue-50 text-blue-700" }; return <span className={`rounded-full px-2.5 py-1 text-xs font-semibold uppercase ${styles[severity]}`}>{severity}</span>; }
function ApiState({ message, onRetry }: { message: string; onRetry?: () => void }) { return <div className="rounded-xl border border-red-200 bg-red-50 p-5 text-sm text-red-800" role="alert"><div className="flex items-start gap-3"><AlertCircle size={18} className="mt-0.5 shrink-0" /><div><p className="font-semibold">Unable to load Sentinel data</p><p className="mt-1">{message}</p>{onRetry && <button onClick={onRetry} className="mt-3 inline-flex items-center gap-2 rounded-lg border border-red-300 bg-white px-3 py-2 text-xs font-semibold"><RefreshCw size={14} />Retry</button>}</div></div></div>; }
function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) { return <div className="mb-8 flex flex-wrap items-start justify-between gap-4"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1 className="page-title">{title}</h1>{description && <p className="page-subtitle">{description}</p>}</div>{action}</div>; }
function Metric({ label, value, note }: { label: string; value: string; note: string }) { return <div className="section-panel"><p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p><p className="mt-2 text-2xl font-semibold text-ink">{value}</p><p className="mt-1 text-xs text-slate-500">{note}</p></div>; }
function LoadingPanel({ label }: { label: string }) { return <div className="section-panel flex items-center gap-3 text-sm text-slate-500"><LoaderCircle className="animate-spin" size={18} />{label}</div>; }

export function NewScan() {
  const navigate = useNavigate(); const [targetUrl, setTargetUrl] = useState(""); const [assetId, setAssetId] = useState(""); const [assets, setAssets] = useState<import("../types").Asset[]>([]); const [authorized, setAuthorized] = useState(false); const [error, setError] = useState<string | null>(null); const [submitting, setSubmitting] = useState(false);
  useEffect(() => { getAssets().then(setAssets).catch(() => setAssets([])); }, []);
  async function submit(event: FormEvent) { event.preventDefault(); if (submitting) return; setError(null); if (!authorized) { setError("Confirm that you are authorized to assess this target."); return; } try { const parsed = new URL(targetUrl.trim()); if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS targets are allowed."); } catch (reason) { setError(reason instanceof Error && reason.message !== "Invalid URL" ? reason.message : "Enter a valid HTTP or HTTPS website URL."); return; } setSubmitting(true); try { const scan = await createScan(targetUrl.trim(), true, assetId ? Number(assetId) : undefined); navigate(`/scans/${scan.id}`); } catch (reason) { setError(reason instanceof Error ? reason.message : "The scan could not be started."); setSubmitting(false); } }
  return <><Link to="/scans" className="mb-6 inline-flex items-center gap-2 text-sm text-slate-500 hover:text-ink"><ArrowLeft size={16} />Back to scans</Link><PageHeader eyebrow="Assessment" title="Start a new scan" description="Assess a publicly accessible website you are authorized to test." /><form onSubmit={submit} className="section-panel max-w-2xl"><label className="field-label" htmlFor="target">Target URL</label><input id="target" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} className="field-input" placeholder="https://example.com" autoComplete="url" required />{assets.length > 0 && <><label className="field-label mt-5" htmlFor="asset">Registered asset (optional)</label><select id="asset" value={assetId} onChange={(event) => { const chosenId = event.target.value; setAssetId(chosenId); const chosen = assets.find((a) => String(a.id) === chosenId); if (chosen) setTargetUrl(chosen.normalized_url); }} className="field-input"><option value="">No registered asset</option>{assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.normalized_url}</option>)}</select></>}<p className="mt-2 text-xs leading-5 text-slate-500">The backend validates DNS, blocks private and metadata addresses, revalidates redirects, and enforces bounded request limits.</p><label className="mt-5 flex items-start gap-3 text-sm text-slate-600"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-0.5 accent-emerald" />I confirm that I am authorized to assess this website.</label>{error && <p className="mt-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700" role="alert">{error}</p>}<button disabled={submitting} className="button-primary mt-6 disabled:cursor-not-allowed disabled:bg-slate-300">{submitting && <LoaderCircle size={16} className="animate-spin" />}{submitting ? "Starting assessment…" : "Start assessment"}</button></form></>;
}



export function ScanDetailPage() {
  const { scanId } = useParams(); const [scan, setScan] = useState<ScanDetail | null>(null); const [error, setError] = useState<string | null>(null); const [downloading, setDownloading] = useState<"pdf" | "csv" | null>(null); const [downloadError, setDownloadError] = useState<string | null>(null); const id = Number(scanId);
  async function download(type: "pdf" | "csv") { if (!scan) return; setDownloading(type); setDownloadError(null); try { const response = type === "pdf" ? await downloadReport(scan.id) : await downloadFindingsCsv(scan.id); if (!response.ok) throw new Error("The export could not be generated."); const url = URL.createObjectURL(await response.blob()); const a = document.createElement("a"); a.href = url; a.download = type === "pdf" ? `sentinel-scan-${scan.id}.pdf` : `sentinel-scan-${scan.id}-findings.csv`; a.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (reason) { setDownloadError(reason instanceof Error ? reason.message : "The export failed."); } finally { setDownloading(null); } }
  useEffect(() => { let active = true; let timer: number | undefined; const load = async () => { try { const result = await getScan(id); if (!active) return; setScan(result); if (result.status === "pending" || result.status === "running") timer = window.setTimeout(load, 1500); } catch (reason) { if (active) setError(reason instanceof ApiError ? reason.message : "The scan could not be loaded."); } }; if (Number.isInteger(id) && id > 0) load(); else setError("This scan identifier is invalid."); return () => { active = false; if (timer) window.clearTimeout(timer); }; }, [id]);
  if (error) return <ApiState message={error} />; if (!scan) return <LoadingPanel label="Loading assessment…" />; const checkEntries = Object.entries(scan.checks); const completedChecks = checkEntries.filter(([, value]) => value === "completed").length;
  return <><Link to="/scans" className="mb-6 inline-flex items-center gap-2 text-sm text-slate-500 hover:text-ink"><ArrowLeft size={16} />Back to scans</Link><PageHeader eyebrow={`Assessment #${scan.id}`} title={scan.target_url} description={`Started ${formatDate(scan.created_at)}`} action={<div className="flex flex-wrap items-center gap-2"><StatusBadge status={scan.status} />{(scan.status === "completed" || scan.status === "partial") && <><button onClick={() => void download("pdf")} disabled={downloading !== null} className="button-secondary text-xs">{downloading === "pdf" ? <LoaderCircle size={14} className="animate-spin" /> : <FileDown size={14} />}PDF</button><button onClick={() => void download("csv")} disabled={downloading !== null} className="button-secondary text-xs">{downloading === "csv" ? <LoaderCircle size={14} className="animate-spin" /> : <FileDown size={14} />}CSV</button></>}</div>} />{downloadError && <p role="alert" className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{downloadError}</p>}{scan.status === "partial" && <div className="mb-6 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800"><p className="font-semibold">Assessment incomplete</p><p className="mt-1">{scan.error_message ?? "Some checks could not be completed; these results are partial."}</p></div>}{scan.status === "failed" && <div className="mb-6"><ApiState message={scan.error_message ?? "The assessment failed before a complete result was saved."} /></div>}<div className="mb-6 grid gap-4 sm:grid-cols-3"><Metric label="Risk score" value={scan.risk_score === null ? "—" : `${scan.risk_score}/100`} note={scan.risk_level ? `Classified ${scan.risk_level}; accumulated observations` : "Not available"} /><Metric label="Findings" value={String(scan.findings.length)} note="Evidence-backed observations" /><Metric label="Checks" value={`${completedChecks}/${checkEntries.length}`} note="Completed; other states disclosed" /></div>{checkEntries.length > 0 && <section className="section-panel mb-6"><h2 className="text-lg font-semibold text-ink">Check coverage</h2><p className="mt-1 text-sm text-slate-500">Skipped and inconclusive checks are not treated as secure.</p><div className="mt-4 grid gap-2 sm:grid-cols-2">{checkEntries.map(([name, status]) => <div key={name} className="flex justify-between rounded-lg bg-slate-50 px-3 py-2 text-sm"><span className="capitalize text-slate-700">{name}</span><span className="font-semibold text-slate-500">{status}</span></div>)}</div></section>}{(scan.status === "completed" || scan.status === "partial") && <section className="section-panel"><div className="mb-5"><h2 className="text-lg font-semibold text-ink">Evidence-backed findings</h2><p className="mt-1 text-sm text-slate-500">Observations are not proof of exploitability.</p></div>{scan.findings.length === 0 ? <p className="rounded-lg bg-emerald-50 p-4 text-sm text-emerald-800">No findings were generated by the completed checks.</p> : <div className="space-y-4">{scan.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}</div>}</section>}</>;
}

function FindingCard({ finding, target }: { finding: Finding; target?: string }) { const assessment = finding.evidence_data?.assessment; return <article className="rounded-lg border border-slate-200 bg-white p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="font-semibold text-ink">{finding.title}</p><p className="mt-1 text-xs text-slate-500">{target && `${target} · `}{finding.category ?? "general"} · {finding.stable_id ?? `finding-${finding.id}`} · confidence {finding.confidence ?? "not recorded"}</p></div><SeverityBadge severity={finding.severity} /></div><div className="mt-4 grid gap-4 text-sm md:grid-cols-3"><div><p className="font-semibold text-slate-600">Evidence</p><p className="mt-1 leading-6 text-slate-500">{finding.evidence ?? "No evidence recorded."}</p>{finding.evidence_data?.cookie_name && <p className="mt-2 text-xs text-slate-500">Cookie: {finding.evidence_data.cookie_name}; observed attributes: {finding.evidence_data.observed_attributes?.join(", ") || "none"}</p>}</div><div><p className="font-semibold text-slate-600">What it means</p><p className="mt-1 leading-6 text-slate-500">{finding.explanation ?? "No explanation recorded."}</p>{assessment?.impact && <p className="mt-2 text-xs leading-5 text-slate-500"><span className="font-semibold">Potential impact: </span>{assessment.impact}</p>}{assessment?.root_cause && <p className="mt-2 text-xs leading-5 text-slate-500"><span className="font-semibold">Root cause: </span>{assessment.root_cause}</p>}</div><div><p className="font-semibold text-slate-600">Remediation</p><p className="mt-1 leading-6 text-slate-500">{finding.remediation ?? "No remediation recorded."}</p><p className="mt-2 text-xs text-slate-500">Verification: {assessment?.verification_status?.replaceAll("_", " ") ?? "not recorded"}</p>{assessment?.references?.map((reference) => <p key={reference} className="mt-1 break-all text-xs text-emerald">{reference}</p>)}</div></div></article>; }

export function FindingsPage() {
  const [items, setItems] = useState<import("../types").FindingOverviewItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState(() => {
    const requested = (searchParams.get("severity") ?? "all").split(",").filter((value) => ["critical", "high", "medium", "low", "info"].includes(value));
    return requested.length ? requested.join(",") : "all";
  });
  const [findingStatus, setFindingStatus] = useState(() => ["open", "in_progress", "fixed", "accepted_risk"].includes(searchParams.get("status") ?? "") ? searchParams.get("status") ?? "all" : "all");
  useEffect(() => {
    const requested = (searchParams.get("severity") ?? "all").split(",").filter((value) => ["critical", "high", "medium", "low", "info"].includes(value));
    setSeverity(requested.length ? requested.join(",") : "all");
    const requestedStatus = searchParams.get("status") ?? "";
    setFindingStatus(["open", "in_progress", "fixed", "accepted_risk"].includes(requestedStatus) ? requestedStatus : "all");
  }, [searchParams]);
  useEffect(() => {
    let active = true;
    setError(null);
    getFindingsOverview().then((result) => { if (active) setItems(result); })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Finding details could not be loaded."); });
    return () => { active = false; };
  }, [reloadKey]);

  const rows = (items ?? [])
    .map((finding) => ({ finding, target: finding.target_url, scanId: finding.scan_id }))
    .filter(({ finding, target }) => {
      const searchable = `${finding.title} ${finding.stable_id ?? ""} ${target}`.toLowerCase();
      const matchesQuery = searchable.includes(query.toLowerCase());
      const matchesSeverity = severity === "all" || severity.split(",").includes(finding.severity);
      const matchesStatus = findingStatus === "all" || (finding.remediation_status ?? "open") === findingStatus;
      return matchesQuery && matchesSeverity && matchesStatus;
    });

  return (
    <>
      <PageHeader title="Findings" description="Search evidence-backed observations returned by completed or partial scans." />
      {error ? (
        <ApiState message={error} onRetry={() => setReloadKey((key) => key + 1)} />
      ) : items === null ? (
        <LoadingPanel label="Loading findings…" />
      ) : (
        <>
          <div className="mb-5 grid gap-3 md:grid-cols-[1fr_180px_190px]">
            <label className="relative">
              <Search className="absolute left-3 top-3 text-slate-400" size={17} />
              <span className="sr-only">Search findings</span>
              <input value={query} onChange={(event) => setQuery(event.target.value)} className="field-input pl-10" placeholder="Search findings or targets" aria-label="Search findings" />
            </label>
            <label>
              <span className="sr-only">Filter severity</span>
              <select value={severity} onChange={(event) => setSeverity(event.target.value)} className="field-input" aria-label="Filter severity">
                <option value="all">All severities</option>
                <option value="critical,high">Critical and high</option>
                {["critical", "high", "medium", "low", "info"].map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
            <label>
              <span className="sr-only">Filter finding status</span>
              <select value={findingStatus} onChange={(event) => setFindingStatus(event.target.value)} className="field-input" aria-label="Filter finding status">
                <option value="all">All finding statuses</option>
                <option value="open">Open</option>
                <option value="in_progress">In progress</option>
                <option value="fixed">Fixed</option>
                <option value="accepted_risk">Accepted risk</option>
              </select>
            </label>
          </div>
          {rows.length === 0 ? (
            <EmptyState title="No matching findings" description={items.length ? "No persisted finding matches the current filters." : "Start an authorized scan to populate evidence-backed findings."} />
          ) : (
            <div className="space-y-4">
              {rows.map(({ finding, target, scanId }) => (
                <div key={`${scanId}-${finding.id}`}>
                  <FindingCard finding={finding} target={target} />
                  <Link to={`/scans/${scanId}`} className="ml-5 mt-2 inline-flex text-xs font-semibold text-emerald">
                    View assessment <ArrowRight size={14} />
                  </Link>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </>
  );
}

export function AssetsPage() {
  const pageSize = 20;
  const [overview, setOverview] = useState<import("../types").AssetOverview | null>(null);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [saving, setSaving] = useState(false);
  const load = () => { setError(null); getAssetOverview(pageSize, offset).then(setOverview).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Assets could not be loaded.")); };
  useEffect(load, [offset]);
  async function addAsset(event: FormEvent) {
    event.preventDefault();
    if (!authorized || saving) { if (!authorized) setError("Confirm authorization before registering an asset."); return; }
    setSaving(true); setError(null);
    try { await registerAsset(targetUrl, true); setTargetUrl(""); setAuthorized(false); load(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "The asset could not be registered."); }
    finally { setSaving(false); }
  }
  const assets = overview?.items ?? [];
  return <>
    <PageHeader title="Websites & assets" description="Persisted authorized targets. Registration does not independently verify ownership." />
    <section className="section-panel mb-6 max-w-3xl"><h2 className="text-lg font-semibold text-ink">Register an asset</h2><form onSubmit={addAsset} className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]"><input value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} className="field-input" placeholder="https://example.com" aria-label="Website URL" required /><button disabled={saving} className="button-primary">{saving && <LoaderCircle size={15} className="animate-spin" />}{saving ? "Registering…" : "Register"}</button></form><label className="mt-3 flex items-start gap-3 text-sm text-slate-600"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-0.5 accent-emerald" />I confirm that I am authorized to assess this website.</label></section>
    {error && <p role="alert" className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}<button type="button" className="ml-3 font-semibold underline" onClick={load}>Retry</button></p>}
    {overview === null ? <LoadingPanel label="Loading asset security summaries…" /> : assets.length === 0 ? <EmptyState title="No assets registered" description="Register an authorized website above. Registration does not claim independent domain ownership verification." /> : <section className="section-panel"><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-3 py-3">Website</th><th className="px-3 py-3">Latest status</th><th className="px-3 py-3">Latest findings</th><th className="px-3 py-3">Observed risk</th><th className="px-3 py-3">Coverage</th><th className="px-3 py-3">Last scan</th><th className="px-3 py-3">History</th></tr></thead><tbody className="divide-y divide-slate-100">{assets.map((asset) => { const completedChecks = Object.values(asset.latest_checks).filter((state) => state === "completed").length; const coverage = Object.keys(asset.latest_checks).length ? `${completedChecks}/${Object.keys(asset.latest_checks).length} checks` : "Not recorded"; return <tr key={asset.id}><td className="max-w-[16rem] break-all px-3 py-4 font-medium text-ink">{asset.normalized_url}</td><td className="px-3 py-4">{asset.latest_scan_status ? <StatusBadge status={asset.latest_scan_status} /> : <span className="text-slate-500">Not scanned</span>}</td><td className="whitespace-nowrap px-3 py-4 text-slate-600">{asset.latest_open_findings} open / in progress · {asset.latest_findings} total</td><td className="whitespace-nowrap px-3 py-4 text-slate-600">{asset.latest_risk_score === null ? "Not available" : `${asset.latest_risk_score}/100 · ${asset.latest_risk_level ?? "unclassified"}`}</td><td className="whitespace-nowrap px-3 py-4 text-slate-500">{coverage}</td><td className="whitespace-nowrap px-3 py-4 text-slate-500">{formatDate(asset.last_scan_at)}</td><td className="whitespace-nowrap px-3 py-4"><Link className="font-semibold text-emerald" to={`/scans?q=${encodeURIComponent(asset.normalized_url)}`}>{asset.scan_count} scans</Link>{asset.latest_scan_id && <Link className="ml-2 text-xs text-slate-500" to={`/scans/${asset.latest_scan_id}`}>Latest</Link>}</td></tr>; })}</tbody></table></div><div className="mt-5 flex justify-end gap-2"><button className="button-secondary" disabled={offset === 0} onClick={() => setOffset((value) => Math.max(0, value - pageSize))}>Previous</button><button className="button-secondary" disabled={offset + assets.length >= overview.total} onClick={() => setOffset((value) => value + pageSize)}>Next</button></div></section>}
  </>;
}



function VerificationRow({ item }: { item: VerificationOverviewItem }) {
  const { finding_id: findingId, title, stable_id: stableId, target_url: target } = item;
  const [attempts, setAttempts] = useState<VerificationAttempt[]>(item.attempts); const [loading, setLoading] = useState(false); const [running, setRunning] = useState(false); const [error, setError] = useState<string | null>(null);
  useEffect(() => { setAttempts(item.attempts); }, [item.attempts]);
  async function load() { setLoading(true); try { setAttempts(await getVerifications(findingId)); setError(null); } catch (reason) { setError(reason instanceof Error ? reason.message : "Verification history could not be loaded."); } finally { setLoading(false); } }
  async function verify() { setRunning(true); setError(null); try { await requestVerification(findingId); await load(); } catch (reason) { setError(reason instanceof Error ? reason.message : "Verification could not be requested."); } finally { setRunning(false); } }
  return <article className="section-panel"><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold text-ink">{title}</h2><p className="mt-1 text-xs text-slate-500">{target} · {stableId ?? "logical check"}</p></div><button onClick={verify} disabled={running} className="button-secondary">{running && <LoaderCircle size={15} className="animate-spin" />}Verify safely</button></div><p className="mt-3 text-sm text-slate-600">Verification repeats the supported bounded observation. A missing observation later is reported as inconclusive, not proof of remediation.</p>{error && <p className="mt-3 text-sm text-red-700">{error}</p>}{loading ? <p className="mt-4 text-sm text-slate-500">Loading verification history…</p> : attempts.length === 0 ? <p className="mt-4 text-sm text-slate-500">No verification attempts recorded.</p> : <div className="mt-4 space-y-2">{attempts.map((attempt) => <div key={attempt.id} className="rounded-lg bg-slate-50 p-3 text-sm"><div className="flex justify-between gap-3"><span className="font-semibold capitalize text-slate-700">{attempt.status}</span><span className="text-xs text-slate-500">{formatDate(attempt.created_at)}</span></div><p className="mt-1 text-slate-600">{attempt.summary ?? "No summary recorded."}</p>{attempt.evidence && <p className="mt-1 text-xs text-slate-500">Evidence: {attempt.evidence}</p>}</div>)}</div>}</article>;
}
export function VerificationPage() {
  const [items, setItems] = useState<VerificationOverviewItem[] | null>(null); const [error, setError] = useState<string | null>(null); const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => { let active = true; setError(null); getVerificationOverview().then((result) => { if (active) setItems(result); }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Verification targets could not be loaded."); }); return () => { active = false; }; }, [reloadKey]);
  return <><PageHeader title="Verification" description="Re-check supported observations without exploit payloads or production changes." />{error ? <ApiState message={error} onRetry={() => setReloadKey((key) => key + 1)} /> : items === null ? <LoadingPanel label="Loading verification targets…" /> : items.length === 0 ? <EmptyState title="No findings to verify" description="Verification becomes available after a persisted finding is returned by a scan." /> : <div className="space-y-4">{items.map((item) => <VerificationRow key={item.finding_id} item={item} />)}</div>}</>;
}
export function ActivityPage() { const [events, setEvents] = useState<import("../types").ActivityEvent[] | null>(null); const [error, setError] = useState<string | null>(null); const load = () => { setError(null); getActivity().then(setEvents).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Activity could not be loaded.")); }; useEffect(load, []); return <><PageHeader title="Activity log" description="Persisted events generated by the Sentinel application." />{error ? <ApiState message={error} onRetry={load} /> : events === null ? <LoadingPanel label="Loading activity…" /> : events.length === 0 ? <EmptyState title="No activity recorded" description="Historical events before activity logging was enabled are not fabricated." /> : <section className="section-panel"><div className="space-y-3">{events.map((event) => <div key={event.id} className="flex gap-4 border-b border-slate-100 pb-3 last:border-0"><div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-emerald" /><div><p className="font-medium text-ink">{event.summary}</p><p className="mt-1 text-xs text-slate-500">{event.event_type} · {formatDate(event.created_at)}{event.scan_id ? ` · scan ${event.scan_id}` : ""}{event.finding_id ? ` · finding ${event.finding_id}` : ""}</p></div></div>)}</div></section>}</>; }
function UnavailablePage({ title, description, detail }: { title: string; description: string; detail: string }) { return <><PageHeader title={title} description={description} /><section className="section-panel max-w-2xl"><div className="flex items-start gap-3"><ShieldAlert className="mt-0.5 text-amber-600" size={21} /><div><h2 className="font-semibold text-ink">Capability unavailable</h2><p className="mt-2 text-sm leading-6 text-slate-600">{detail}</p></div></div></section></>; }
export function Placeholder({ title, description }: { title: string; description: string }) { return <UnavailablePage title={title} description={description} detail="This capability is not exposed by the current backend, so Sentinel does not display mock data or non-functional controls." />; }

