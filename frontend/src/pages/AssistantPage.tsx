import { FormEvent, useEffect, useMemo, useState } from "react";
import { Bot, LoaderCircle, Send, Trash2 } from "lucide-react";
import { ApiError, askAssistant, getAssistantStatus, getScan, getScans } from "../lib/api";
import { AssistantMarkdown } from "../components/AssistantMarkdown";
import type { AssistantStatus, AssistantTurn, Finding, Scan, ScanDetail } from "../types";

type Message = { role: "user" | "assistant"; text: string; references?: string[]; provider?: string; providerMessage?: string };

export function AssistantPage() {
  const [status, setStatus] = useState<AssistantStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<number, ScanDetail>>({});
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<number | "">("");
  const [findingId, setFindingId] = useState<number | "">("");
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = () => {
    setStatusError(null);
    getAssistantStatus().then(setStatus).catch((reason: unknown) => setStatusError(reason instanceof Error ? reason.message : "Assistant status could not be loaded."));
  };

  const loadScans = () => {
    setScanError(null);
    setScans(null);
    getScans().then((result) => setScans(result.items)).catch((reason: unknown) => {
      setScans([]);
      setScanError(reason instanceof Error ? reason.message : "Saved scans could not be loaded.");
    });
  };

  useEffect(() => {
    loadStatus();
    loadScans();
  }, []);

  useEffect(() => {
    if (scanId === "") return;
    if (details[scanId]) { setDetailsError(null); return; }
    let active = true;
    setDetailsLoading(true);
    setDetailsError(null);
    getScan(scanId).then((detail) => {
      if (active) setDetails((current) => ({ ...current, [scanId]: detail }));
    }).catch((reason: unknown) => {
      if (active) setDetailsError(reason instanceof Error ? reason.message : "The selected scan could not be loaded.");
    }).finally(() => { if (active) setDetailsLoading(false); });
    return () => { active = false; };
  }, [scanId, details]);

  const selectedDetail = scanId === "" ? undefined : details[scanId];
  const findings = useMemo<Finding[]>(() => selectedDetail?.findings ?? [], [selectedDetail]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = question.trim();
    if (trimmed.length < 3 || trimmed.length > 4000) { setError("Ask a question between 3 and 4000 characters."); return; }
    if (!status?.configured && scanId === "") { setError("Select a saved scan to get local defensive guidance, or configure an AI provider for general questions."); return; }
    setBusy(true); setError(null); setMessages((current) => [...current, { role: "user", text: trimmed }]); setQuestion("");
    try {
      const history: AssistantTurn[] = messages.slice(-12).map(({ role, text }) => ({ role, content: text }));
      const response = await askAssistant(trimmed, scanId === "" ? undefined : scanId, findingId === "" ? undefined : findingId, history);
      setMessages((current) => [...current, { role: "assistant", text: response.answer, references: response.evidence_references, provider: response.provider, providerMessage: response.provider_message ?? undefined }]);
    } catch (reason) {
      const message = reason instanceof ApiError ? reason.message : "The guidance request failed safely. Please try again.";
      setError(message);
      if (reason instanceof ApiError && reason.status === 503) setStatus((current) => current ? { ...current, configured: false, message } : current);
    } finally { setBusy(false); }
  };

  const canAsk = !busy && status !== null && (status.configured || (status.local_guidance_available && scanId !== ""));

  return <>
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div><h1 className="text-2xl font-semibold text-ink">Defensive Guidance</h1><p className="mt-1 text-sm text-slate-500">Get safe recommendations grounded in saved Sentinel scan findings.</p></div>
      <button onClick={() => setMessages([])} disabled={messages.length === 0} className="button-secondary"><Trash2 size={16} />Clear session</button>
    </div>
    {statusError && <div className="section-panel mb-5 text-sm text-red-700" role="alert"><p>{statusError}</p><button type="button" onClick={loadStatus} className="mt-2 font-semibold underline">Retry assistant status</button></div>}
    {status && !status.configured && <section className="section-panel mb-5 border-amber-200 bg-amber-50"><h2 className="font-semibold text-amber-900">External AI is not configured</h2><p className="mt-2 text-sm leading-6 text-amber-800">{status.message}</p></section>}
    <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
      <aside className="section-panel h-fit">
        <h2 className="font-semibold text-ink">Evidence context</h2>
        <p className="mt-1 text-xs leading-5 text-slate-500">Only scans and findings owned by your account can be used. Selecting a scan enables local evidence-based guidance.</p>
        <label htmlFor="assistant-scan" className="mt-4 block text-sm font-medium text-slate-700">Saved scan</label>
        <select id="assistant-scan" value={scanId} onChange={(event) => { setScanId(event.target.value ? Number(event.target.value) : ""); setFindingId(""); setDetailsError(null); setMessages([]); }} className="field-input mt-1" disabled={scans === null || busy}>
          <option value="">{scans === null ? "Loading saved scans…" : scans.length === 0 ? "No saved scans" : "No scan context"}</option>
          {(scans ?? []).map((scan) => <option key={scan.id} value={scan.id}>{scan.target_url} · scan {scan.id}</option>)}
        </select>
        {scanError && <div className="mt-3 text-xs text-red-700" role="alert"><p>{scanError}</p><button type="button" onClick={loadScans} className="mt-2 font-semibold underline">Retry loading scans</button></div>}
        {scans?.length === 0 && !scanError && <p className="mt-3 text-xs text-slate-500">Run an authorized scan first. No recommendations are fabricated without scan evidence.</p>}
        {scanId !== "" && <>
          <label htmlFor="assistant-finding" className="mt-4 block text-sm font-medium text-slate-700">Finding (optional)</label>
          <select id="assistant-finding" value={findingId} onChange={(event) => { setFindingId(event.target.value ? Number(event.target.value) : ""); setMessages([]); }} className="field-input mt-1" disabled={busy || detailsLoading || !selectedDetail}>
            <option value="">All scan findings</option>
            {findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.title}</option>)}
          </select>
          {detailsLoading && <p className="mt-2 text-xs text-slate-500">Loading scan findings…</p>}
          {detailsError && <p className="mt-2 text-xs text-red-700" role="alert">{detailsError}</p>}
          {selectedDetail && findings.length === 0 && <p className="mt-2 text-xs text-slate-500">This scan has no persisted findings. Guidance will report that result without claiming the target is secure.</p>}
          <p className="mt-3 text-xs text-slate-500">Context: scan {scanId}{findingId !== "" ? `, finding ${findingId}` : ""}.</p>
        </>}
      </aside>
      <section className="section-panel flex min-h-[520px] flex-col">
        <div className="flex items-center gap-2 border-b border-slate-100 pb-4"><Bot size={20} className="text-emerald" /><div><h2 className="font-semibold text-ink">Defensive guidance</h2><p className="text-xs text-slate-500">Read-only recommendations. Sentinel does not scan, exploit, or change websites from this page.</p></div></div>
        <div className="flex-1 space-y-4 py-5">
          {messages.length === 0 ? <div className="rounded-xl bg-slate-50 p-5 text-sm text-slate-600"><p className="font-medium text-ink">Ask about saved evidence or defensive security</p><div className="mt-3 flex flex-wrap gap-2">{["Prioritize the selected scan findings and explain safe next steps.", "What recorded evidence supports the selected finding?", "What stored remediation applies to this scan?"] .map((suggestion) => <button key={suggestion} type="button" onClick={() => setQuestion(suggestion)} className="rounded-full border border-slate-200 bg-white px-3 py-2 text-left text-xs hover:border-emerald">{suggestion}</button>)}</div></div> : messages.map((message, index) => <div key={`${message.role}-${index}`} className={message.role === "user" ? "ml-8 rounded-xl bg-emerald/10 p-4 text-sm text-slate-700" : "mr-8 rounded-xl bg-slate-50 p-4 text-sm leading-6 text-slate-700"}><p className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">{message.role === "user" ? "You" : "Sentinel AI"}{message.provider === "gemini" ? " · Gemini" : message.provider === "local-evidence" ? " · local scan guidance" : message.provider === "local-evidence-fallback" ? " · local evidence fallback" : ""}</p>{message.role === "assistant" ? <AssistantMarkdown content={message.text} /> : <p className="whitespace-pre-wrap">{message.text}</p>}{message.provider === "local-evidence-fallback" && <p className="mt-2 text-xs text-amber-700">{message.providerMessage ?? "The AI provider was unavailable; this is a deterministic summary of stored findings."}</p>}{message.references && message.references.length > 0 && <p className="mt-3 text-xs text-slate-500">Evidence references: {message.references.join(", ")}</p>}</div>)}
          {busy && <div className="flex items-center gap-2 text-sm text-slate-500"><LoaderCircle size={16} className="animate-spin" />Preparing evidence-grounded guidance…</div>}
        </div>
        {error && <p role="alert" className="mb-3 text-sm text-red-700">{error}</p>}
        <form onSubmit={submit} className="flex gap-2 border-t border-slate-100 pt-4"><label htmlFor="assistant-question" className="sr-only">Ask for defensive guidance</label><textarea id="assistant-question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about the selected scan evidence…" rows={2} maxLength={4000} className="field-input min-h-[52px] flex-1 resize-y" disabled={!canAsk} /><button disabled={!canAsk} className="button-primary self-end"><Send size={16} />Ask</button></form>
        {!status?.configured && scanId === "" && <p className="mt-2 text-xs text-slate-500">Select a saved scan to enable local defensive guidance.</p>}
      </section>
    </div>
  </>;
}
