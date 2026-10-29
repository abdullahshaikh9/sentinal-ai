import { FormEvent, useEffect, useState } from "react";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { changePassword, getAssistantStatus } from "../lib/api";
import { useAuth } from "../auth/AuthContext";
import type { AssistantStatus } from "../types";

export function SettingsPage() {
  const { user } = useAuth();
  const [assistant, setAssistant] = useState<AssistantStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);
  useEffect(() => { getAssistantStatus().then(setAssistant).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Provider status could not be loaded.")); }, []);
  async function submitPassword(event: FormEvent) {
    event.preventDefault(); setPasswordError(null); setPasswordMessage(null);
    if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword) || newPassword.length < 12) { setPasswordError("Use at least 12 characters with upper, lower, and numeric characters."); return; }
    if (newPassword !== confirmation) { setPasswordError("New password confirmation does not match."); return; }
    setPasswordBusy(true);
    try { const response = await changePassword(currentPassword, newPassword); setPasswordMessage(response.message); setCurrentPassword(""); setNewPassword(""); setConfirmation(""); }
    catch (reason) { setPasswordError(reason instanceof Error ? reason.message : "The password could not be changed."); }
    finally { setPasswordBusy(false); }
  }
  return <>
    <div className="mb-8"><p className="eyebrow">Workspace</p><h1 className="page-title">Settings</h1><p className="page-subtitle">Review account verification and backend-backed security configuration.</p></div>
    <div className="grid max-w-5xl gap-5 lg:grid-cols-2">
      <section className="section-panel"><h2 className="text-lg font-semibold text-ink">Account and verification</h2><dl className="mt-5 space-y-4 text-sm"><div><dt className="text-slate-500">Display name</dt><dd className="mt-1 font-medium text-ink">{user?.display_name}</dd></div><div><dt className="text-slate-500">Email</dt><dd className="mt-1 font-medium text-ink">{user?.email}</dd></div><div><dt className="text-slate-500">Email verification</dt><dd className={`mt-1 flex items-center gap-2 ${user?.email_verified ? "text-emerald-700" : "text-amber-700"}`}>{user?.email_verified ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}{user?.email_verified ? "Verified" : "Not verified"}</dd></div><div><dt className="text-slate-500">Mobile number</dt><dd className="mt-1 font-medium text-ink">{user?.phone_masked ?? "No phone number returned"}</dd></div><div><dt className="text-slate-500">Mobile verification</dt><dd className={`mt-1 flex items-center gap-2 ${user?.phone_verified ? "text-emerald-700" : "text-amber-700"}`}>{user?.phone_verified ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}{user?.phone_verified ? "Verified" : "Not verified"}</dd></div><div><dt className="text-slate-500">Session protection</dt><dd className="mt-1 flex items-center gap-2 text-emerald-700"><CheckCircle2 size={16} />HttpOnly session cookie and CSRF protection active</dd></div></dl><p className="mt-5 border-t border-slate-200 pt-4 text-xs leading-5 text-slate-500">Profile editing, password reset, and session-device management are not exposed by the current backend.</p></section>
      <section className="section-panel"><h2 className="text-lg font-semibold text-ink">AI provider</h2>{error ? <p role="alert" className="mt-4 text-sm text-red-700">{error}</p> : assistant === null ? <p className="mt-4 text-sm text-slate-500">Checking provider availability…</p> : <><p className={`mt-4 flex items-center gap-2 text-sm ${assistant.configured ? "text-emerald-700" : "text-amber-700"}`}>{assistant.configured ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}{assistant.configured ? `Configured provider: ${assistant.provider}` : "Provider unavailable"}</p><p className="mt-3 text-sm leading-6 text-slate-600">{assistant.message}</p></>}</section>
      <section className="section-panel"><h2 className="text-lg font-semibold text-ink">Change password</h2><p className="mt-2 text-sm text-slate-500">Changing your password signs out other active sessions.</p><form className="mt-4 space-y-3" onSubmit={(event) => void submitPassword(event)}><label className="block text-sm text-slate-600">Current password<input aria-label="Current password" type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} className="field-input mt-1" required /></label><label className="block text-sm text-slate-600">New password<input aria-label="New password" type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} className="field-input mt-1" required minLength={12} /></label><label className="block text-sm text-slate-600">Confirm new password<input aria-label="Confirm new password" type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} className="field-input mt-1" required minLength={12} /></label><button disabled={passwordBusy} className="button-primary">{passwordBusy ? "Updating…" : "Change password"}</button>{passwordMessage && <p role="status" className="text-sm text-emerald-700">{passwordMessage}</p>}{passwordError && <p role="alert" className="text-sm text-red-700">{passwordError}</p>}</form></section>
      <section className="section-panel"><h2 className="text-lg font-semibold text-ink">Notifications</h2><p className="mt-2 text-sm leading-6 text-slate-600">In-app notifications are created for scan completion, important findings, report exports, and remediation status changes. Push and SMS alerts are not configured.</p></section>
      <section className="section-panel"><h2 className="text-lg font-semibold text-ink">Scanner safety</h2><p className="mt-2 text-sm leading-6 text-slate-600">Mandatory SSRF defenses, DNS validation, redirect revalidation, TLS verification, request timeouts, response limits, authorization checks, and bounded scan behavior are enforced by the backend.</p></section>
    </div>
  </>;
}
