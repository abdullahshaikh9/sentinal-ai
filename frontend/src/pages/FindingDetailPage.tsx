import { useEffect, useState } from "react";
import { ArrowLeft, LoaderCircle } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { getFinding, getVerifications, requestVerification } from "../lib/api";
import type { FindingDetail, VerificationAttempt } from "../types";

export function FindingDetailPage() {
  const { findingId } = useParams();
  const id = Number(findingId);
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [attempts, setAttempts] = useState<VerificationAttempt[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!Number.isInteger(id) || id <= 0) {
      setError("This finding identifier is invalid.");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    Promise.all([getFinding(id), getVerifications(id)])
      .then(([findingData, verifications]) => {
        setFinding(findingData);
        setAttempts(verifications);
      })
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "The finding could not be loaded."))
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    if (!attempts.some((attempt) => attempt.status === "pending" || attempt.status === "running")) return;
    let active = true;
    const timer = window.setTimeout(() => {
      getVerifications(id)
        .then((latest) => { if (active) setAttempts(latest); })
        .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Verification history could not be refreshed."); });
    }, 1000);
    return () => { active = false; window.clearTimeout(timer); };
  }, [attempts, id]);

  async function verify() {
    setRunning(true);
    setError(null);
    try {
      await requestVerification(id);
      setAttempts(await getVerifications(id));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Verification could not be requested.");
    } finally {
      setRunning(false);
    }
  }

  if (loading) return <div className="section-panel flex items-center gap-3 text-sm text-slate-500"><LoaderCircle className="animate-spin" size={18} />Loading finding evidence…</div>;
  if (error || !finding) return <section className="section-panel text-sm text-red-700" role="alert">{error ?? "The finding could not be loaded."}</section>;
  const assessment = finding.evidence_data?.assessment;

  return (
    <>
      <Link to="/findings" className="mb-6 inline-flex items-center gap-2 text-sm text-slate-500 hover:text-ink">
        <ArrowLeft size={16} />Back to findings
      </Link>
      <div className="mb-8 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">Finding detail · scan {finding.scan_id}</p>
          <h1 className="page-title">{finding.title}</h1>
          <p className="page-subtitle">{finding.target_url} · {finding.category ?? "general"} · confidence {finding.confidence ?? "not recorded"}</p>
        </div>
        <button onClick={verify} disabled={running} className="button-primary">
          {running && <LoaderCircle size={16} className="animate-spin" />}
          Verify safely
        </button>
      </div>
      {error && <p role="alert" className="mb-5 text-sm text-red-700">{error}</p>}
      <div className="grid gap-6 lg:grid-cols-3">
        <section className="section-panel lg:col-span-2">
          <h2 className="text-lg font-semibold text-ink">Observed evidence</h2>
          <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-600">{finding.evidence ?? "No evidence was recorded."}</p>
          {finding.evidence_data && <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-50 p-4 text-xs text-slate-600">{JSON.stringify(finding.evidence_data, null, 2)}</pre>}
          <div className="mt-6 border-t border-slate-100 pt-5">
            <h2 className="text-lg font-semibold text-ink">Why it matters</h2>
            <p className="mt-3 text-sm leading-6 text-slate-600">{finding.explanation ?? "No explanation was recorded for this observation."}</p>
            {assessment?.impact && <p className="mt-3 text-sm leading-6 text-slate-600"><span className="font-semibold">Potential impact: </span>{assessment.impact}</p>}
            {assessment?.root_cause && <p className="mt-3 text-sm leading-6 text-slate-600"><span className="font-semibold">Root cause: </span>{assessment.root_cause}</p>}
          </div>
        </section>
        <aside className="space-y-6">
          <section className="section-panel">
            <h2 className="text-lg font-semibold text-ink">Remediation</h2>
            <p className="mt-3 text-sm leading-6 text-slate-600">{finding.remediation ?? "No remediation guidance was recorded."}</p>
            <p className="mt-4 text-xs leading-5 text-slate-500">Suggested guidance only. Sentinel does not modify production websites automatically.</p>
            <p className="mt-3 text-xs text-slate-500">Verification status: {assessment?.verification_status?.replaceAll("_", " ") ?? "not recorded"}</p>
            {assessment?.references?.map((reference) => <p key={reference} className="mt-2 break-all text-xs text-emerald">{reference}</p>)}
          </section>
          <section className="section-panel">
            <h2 className="text-lg font-semibold text-ink">Verification history</h2>
            {attempts.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">No verification attempts recorded.</p>
            ) : (
              <div className="mt-3 space-y-3">
                {attempts.map((attempt) => (
                  <div key={attempt.id} className="rounded-lg bg-slate-50 p-3 text-sm">
                    <div className="flex justify-between gap-3">
                      <span className="font-semibold capitalize text-slate-700">{attempt.status}</span>
                      <span className="text-xs text-slate-500">{new Date(attempt.created_at).toLocaleString()}</span>
                    </div>
                    <p className="mt-2 leading-5 text-slate-600">{attempt.summary ?? "No summary recorded."}</p>
                  </div>
                ))}
              </div>
            )}
          </section>
        </aside>
      </div>
    </>
  );
}
