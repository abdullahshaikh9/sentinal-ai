import { FormEvent, ReactNode, useEffect, useState } from "react";
import { CheckCircle2, Eye, EyeOff, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, resendOtp, verifyOtp, requestPasswordReset, verifyPasswordResetCode, resetPassword } from "../lib/api";
import type { LoginVerificationPending } from "../lib/api";
import { useAuth } from "../auth/AuthContext";
import type { User } from "../types";

const PENDING_VERIFICATION_KEY = "sentinel.pending-verification";
type PendingVerification = { token: string; channels: Array<"email" | "phone">; emailMasked: string; phoneMasked: string; resendUntil: number };

function savePendingVerification(value: PendingVerification) {
  sessionStorage.setItem(PENDING_VERIFICATION_KEY, JSON.stringify(value));
}

function loadPendingVerification(): PendingVerification | null {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(PENDING_VERIFICATION_KEY) ?? "null") as Partial<PendingVerification> | null;
    if (parsed && typeof parsed.token === "string" && Array.isArray(parsed.channels) && typeof parsed.emailMasked === "string" && typeof parsed.phoneMasked === "string") {
      return { token: parsed.token, channels: parsed.channels.filter((channel): channel is "email" | "phone" => channel === "email" || channel === "phone"), emailMasked: parsed.emailMasked, phoneMasked: parsed.phoneMasked, resendUntil: typeof parsed.resendUntil === "number" ? parsed.resendUntil : Date.now() };
    }
  } catch {
    sessionStorage.removeItem(PENDING_VERIFICATION_KEY);
  }
  return null;
}

function maskPhone(phone: string) {
  return `${"*".repeat(Math.max(0, phone.length - 4))}${phone.slice(-4)}`;
}

function maskEmail(email: string) {
  const [local, domain] = email.split("@");
  return `${local?.slice(0, 1) ?? ""}***@${domain ?? ""}`;
}

function pendingFromLogin(result: LoginVerificationPending): PendingVerification {
  return { token: result.verification_token, channels: result.channels, emailMasked: result.email_masked, phoneMasked: result.phone_masked, resendUntil: Date.now() + result.resend_after_seconds * 1000 };
}

function AuthShell({ children }: { children: ReactNode }) {
  return <main className="auth-shell flex min-h-screen items-center justify-center px-4 py-10"><section className="auth-card w-full max-w-md rounded-2xl border p-8"><div className="mb-8 flex items-center gap-3"><div className="rounded-xl bg-emerald/10 p-3 text-emerald"><ShieldCheck size={24} /></div><div><h1 className="text-xl font-bold text-ink">Sentinel AI</h1><p className="text-sm text-slate-500">Evidence-based security operations</p></div></div>{children}</section></main>;
}

function PasswordField({ id, value, onChange, label = "Password" }: { id: string; value: string; onChange: (value: string) => void; label?: string }) {
  const [visible, setVisible] = useState(false);
  return <div><label htmlFor={id} className="mb-1 block text-sm font-medium text-slate-700">{label}</label><div className="relative"><input id={id} required type={visible ? "text" : "password"} value={value} onChange={(event) => onChange(event.target.value)} className="w-full rounded-lg border border-slate-300 px-3 py-2 pr-10 outline-none focus:border-emerald" autoComplete={id === "password" ? "current-password" : "new-password"} /><button type="button" aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} onClick={() => setVisible(!visible)} className="absolute right-3 top-2.5 text-slate-400">{visible ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></div>;
}

function passwordMessage(password: string): string | null {
  return password.length < 12 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) ? "Use at least 12 characters with upper, lower, and numeric characters." : null;
}

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  useEffect(() => { document.title = "Sign In · Sentinel AI"; }, []);
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (busy) return; setBusy(true); setError(null);
    try {
      const result = await login(email, password);
      if ("verification_required" in result) { savePendingVerification(pendingFromLogin(result)); navigate("/verify", { replace: true }); }
      else navigate("/dashboard", { replace: true });
    } catch (err) { setError(err instanceof ApiError ? err.message : "Unable to sign in."); } finally { setBusy(false); }
  };
  return <AuthShell><h2 className="mb-1 text-2xl font-semibold text-ink">Welcome back</h2><p className="mb-6 text-sm text-slate-500">Sign in to access your security workspace.</p><form onSubmit={submit} className="space-y-4"><div><label htmlFor="email" className="mb-1 block text-sm font-medium text-slate-700">Email</label><input id="email" required type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-emerald" autoComplete="email" /></div><div><PasswordField id="password" value={password} onChange={setPassword} /><div className="mt-1 flex justify-end"><Link to="/forgot-password" className="text-xs font-semibold text-emerald hover:underline">Forgot password?</Link></div></div>{error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}<button type="submit" disabled={busy} className="w-full rounded-lg bg-emerald px-4 py-2.5 font-semibold text-white disabled:opacity-60">{busy ? "Signing in…" : "Sign in"}</button></form><p className="mt-6 text-center text-sm text-slate-500">Need an account? <Link className="font-semibold text-emerald" to="/register">Register</Link></p></AuthShell>;
}

export function ForgotPasswordPage() {
  const navigate = useNavigate();
  useEffect(() => { document.title = "Forgot Password · Sentinel AI"; }, []);

  const [step, setStep] = useState<"request" | "verify" | "reset" | "success">("request");
  const [email, setEmail] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [code, setCode] = useState("");
  const [passwordResetToken, setPasswordResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [resendUntil, setResendUntil] = useState(0);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (resendUntil <= 0) return;
    const update = () => setSecondsLeft(Math.max(0, Math.ceil((resendUntil - Date.now()) / 1000)));
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [resendUntil]);

  const handleRequestSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const result = await requestPasswordReset(email);
      setResetToken(result.reset_token);
      setResendUntil(Date.now() + result.resend_after_seconds * 1000);
      setInfo(result.message);
      setStep("verify");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to request password reset.");
    } finally {
      setBusy(false);
    }
  };

  const handleVerifySubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!/^\d{6}$/.test(code)) {
      setError("Enter the six-digit verification code.");
      return;
    }
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await verifyPasswordResetCode(resetToken, code);
      setPasswordResetToken(result.password_reset_token);
      setStep("reset");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to verify this code.");
    } finally {
      setBusy(false);
    }
  };

  const handleResend = async () => {
    if (busy || secondsLeft > 0) return;
    setBusy(true);
    setError(null);
    try {
      const result = await requestPasswordReset(email);
      setResetToken(result.reset_token);
      setResendUntil(Date.now() + result.resend_after_seconds * 1000);
      setInfo("A new verification code has been sent if the account exists.");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to resend reset code.");
    } finally {
      setBusy(false);
    }
  };

  const handleResetSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    const strengthError = passwordMessage(newPassword);
    if (strengthError) {
      setError(strengthError);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await resetPassword(passwordResetToken, newPassword);
      setStep("success");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to reset password.");
    } finally {
      setBusy(false);
    }
  };

  if (step === "success") {
    return (
      <AuthShell>
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-emerald/10 text-emerald">
            <CheckCircle2 size={28} />
          </div>
          <h2 className="mb-1 text-2xl font-semibold text-ink">Password reset complete</h2>
          <p className="mb-6 text-sm text-slate-500">
            Your password has been reset successfully. All previous active sessions were signed out.
          </p>
          <button
            type="button"
            onClick={() => navigate("/login", { replace: true })}
            className="w-full rounded-lg bg-emerald px-4 py-2.5 font-semibold text-white hover:bg-emerald/90"
          >
            Sign in with new password
          </button>
        </div>
      </AuthShell>
    );
  }

  if (step === "reset") {
    return (
      <AuthShell>
        <h2 className="mb-1 text-2xl font-semibold text-ink">Set new password</h2>
        <p className="mb-6 text-sm text-slate-500">Choose a new strong password for your Sentinel AI account.</p>
        <form onSubmit={handleResetSubmit} className="space-y-4">
          <PasswordField id="new-password" value={newPassword} onChange={setNewPassword} label="New password" />
          <p className="-mt-2 text-xs text-slate-500">At least 12 characters, with upper, lower, and numeric characters.</p>
          <PasswordField id="confirm-password" value={confirmPassword} onChange={setConfirmPassword} label="Confirm new password" />
          {error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}
          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-emerald px-4 py-2.5 font-semibold text-white disabled:opacity-60"
          >
            {busy ? "Resetting password…" : "Reset password"}
          </button>
        </form>
        <p className="mt-6 text-center text-sm text-slate-500">
          <Link className="font-semibold text-emerald" to="/login">Back to sign in</Link>
        </p>
      </AuthShell>
    );
  }

  if (step === "verify") {
    return (
      <AuthShell>
        <h2 className="mb-1 text-2xl font-semibold text-ink">Enter reset code</h2>
        <p className="mb-6 text-sm text-slate-500">
          Check <span className="font-medium text-slate-700">{maskEmail(email)}</span> for your six-digit verification code.
        </p>
        {info && <p className="mb-4 rounded-lg bg-emerald/10 p-3 text-sm text-emerald">{info}</p>}
        <form onSubmit={handleVerifySubmit} className="space-y-4">
          <div>
            <label htmlFor="reset-code" className="mb-1 block text-sm font-medium text-slate-700">Verification code</label>
            <input
              id="reset-code"
              aria-label="Verification code"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="123456"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-center text-lg tracking-widest outline-none focus:border-emerald"
            />
          </div>
          {error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}
          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-emerald px-4 py-2.5 font-semibold text-white disabled:opacity-60"
          >
            {busy ? "Verifying…" : "Verify code"}
          </button>
        </form>
        <div className="mt-4 flex items-center justify-between text-xs">
          <button
            type="button"
            onClick={() => void handleResend()}
            disabled={busy || secondsLeft > 0}
            className="font-semibold text-emerald disabled:opacity-50"
          >
            {secondsLeft > 0 ? `Resend code in ${secondsLeft}s` : "Resend code"}
          </button>
          <button
            type="button"
            onClick={() => { setStep("request"); setCode(""); setError(null); }}
            className="text-slate-500 hover:text-slate-700"
          >
            Use a different email
          </button>
        </div>
        <p className="mt-6 text-center text-sm text-slate-500">
          <Link className="font-semibold text-emerald" to="/login">Back to sign in</Link>
        </p>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <h2 className="mb-1 text-2xl font-semibold text-ink">Reset your password</h2>
      <p className="mb-6 text-sm text-slate-500">
        Enter your account email to receive a six-digit verification code.
      </p>
      <form onSubmit={handleRequestSubmit} className="space-y-4">
        <div>
          <label htmlFor="reset-email" className="mb-1 block text-sm font-medium text-slate-700">Email</label>
          <input
            id="reset-email"
            required
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-emerald"
            autoComplete="email"
          />
        </div>
        {error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-lg bg-emerald px-4 py-2.5 font-semibold text-white disabled:opacity-60"
        >
          {busy ? "Sending code…" : "Send reset code"}
        </button>
      </form>
      <p className="mt-6 text-center text-sm text-slate-500">
        Remember your password? <Link className="font-semibold text-emerald" to="/login">Sign in</Link>
      </p>
    </AuthShell>
  );
}

function VerificationStep({ pending, onComplete }: { pending: PendingVerification; onComplete: (user: User) => void }) {
  const [codes, setCodes] = useState<Record<string, string>>({ email: "", phone: "" });
  const [channels, setChannels] = useState(pending.channels);
  const [resendUntil, setResendUntil] = useState(pending.resendUntil);
  const [secondsLeft, setSecondsLeft] = useState(Math.max(0, Math.ceil((pending.resendUntil - Date.now()) / 1000)));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const update = () => setSecondsLeft(Math.max(0, Math.ceil((resendUntil - Date.now()) / 1000)));
    update(); const timer = window.setInterval(update, 1000); return () => window.clearInterval(timer);
  }, [resendUntil]);

  const verify = async (channel: "email" | "phone") => {
    const code = codes[channel] ?? "";
    if (!/^\d{6}$/.test(code)) { setError("Enter the six-digit verification code."); return; }
    setBusy(true); setError(null);
    try {
      const result = await verifyOtp(pending.token, channel, code);
      const remaining = channels.filter((item) => item !== channel);
      setChannels(remaining);
      const nextPending = { ...pending, channels: remaining, resendUntil };
      savePendingVerification(nextPending);
      if (result.account_verified && result.user) { sessionStorage.removeItem(PENDING_VERIFICATION_KEY); onComplete(result.user); }
      else setError(result.message);
    } catch (err) { setError(err instanceof ApiError ? err.message : "Unable to verify this code."); }
    finally { setBusy(false); }
  };

  const resend = async (channel: "email" | "phone") => {
    setBusy(true); setError(null);
    try {
      const result = await resendOtp(pending.token, channel);
      const until = Date.now() + result.resend_after_seconds * 1000;
      setResendUntil(until); savePendingVerification({ ...pending, channels, resendUntil: until });
      setError("The delivery provider accepted the request. Check your email or phone shortly.");
    } catch (err) { setError(err instanceof ApiError ? err.message : "Unable to resend the code."); }
    finally { setBusy(false); }
  };

  const channelPanel = (channel: "email" | "phone", title: string, destination: string) => channels.includes(channel) ? <div className="rounded-lg border border-slate-200 p-4"><p className="text-sm font-medium text-slate-700">{title}</p><p className="mb-3 text-xs text-slate-500">Check for a verification code at {destination}</p><form onSubmit={(event) => { event.preventDefault(); void verify(channel); }} className="flex gap-2"><input aria-label={`${title} code`} inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={codes[channel] ?? ""} onChange={(event) => setCodes({ ...codes, [channel]: event.target.value.replace(/\D/g, "").slice(0, 6) })} className="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-2" /><button type="submit" disabled={busy} className="rounded-lg bg-emerald px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">{busy ? "Verifying…" : "Verify"}</button></form><button type="button" onClick={() => void resend(channel)} disabled={busy || secondsLeft > 0} className="mt-2 text-xs font-semibold text-emerald disabled:opacity-50">{secondsLeft > 0 ? `Resend code in ${secondsLeft}s` : "Resend code"}</button></div> : null;

  return <div><h2 className="mb-1 text-2xl font-semibold text-ink">Verify your account</h2><p className="mb-6 text-sm text-slate-500">Complete each required verification to finish signing in. Codes are never shown in this app.</p><div className="space-y-4">{channelPanel("email", "Email verification", pending.emailMasked)}{channelPanel("phone", "Mobile verification", pending.phoneMasked)}{error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}</div><p className="mt-5 text-center text-sm text-slate-500"><Link to="/login" className="font-semibold text-emerald">Return to sign in</Link></p></div>;
}

export function VerifyPage() {
  const { completeAuthentication } = useAuth();
  const navigate = useNavigate();
  useEffect(() => { document.title = "Verify Account · Sentinel AI"; }, []);
  const [pending] = useState(loadPendingVerification);
  if (!pending || pending.channels.length === 0) return <AuthShell><h2 className="text-xl font-semibold text-ink">Verification session unavailable</h2><p className="mt-2 text-sm text-slate-500">Sign in again to securely resume account verification.</p><Link to="/login" className="mt-5 inline-block font-semibold text-emerald">Return to sign in</Link></AuthShell>;
  return <AuthShell><VerificationStep pending={pending} onComplete={(user) => { completeAuthentication(user); navigate("/dashboard", { replace: true }); }} /></AuthShell>;
}

export function RegisterPage() {
  const { register } = useAuth(); const navigate = useNavigate();
  useEffect(() => { document.title = "Create Account · Sentinel AI"; }, []);
  const [email, setEmail] = useState(""); const [displayName, setDisplayName] = useState(""); const [phone, setPhone] = useState(""); const [password, setPassword] = useState(""); const [confirmation, setConfirmation] = useState(""); const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (busy) return; const strengthError = passwordMessage(password); if (strengthError) { setError(strengthError); return; } if (password !== confirmation) { setError("Passwords do not match."); return; }
    setBusy(true); setError(null);
    try { const result = await register(email, displayName, phone, password); savePendingVerification({ token: result.verification_token, channels: ["email", "phone"], emailMasked: maskEmail(result.email), phoneMasked: maskPhone(result.phone_number), resendUntil: Date.now() + result.resend_after_seconds * 1000 }); navigate("/verify", { replace: true }); }
    catch (err) { setError(err instanceof ApiError ? err.message : "Unable to create the account."); }
    finally { setBusy(false); }
  };
  return <AuthShell><h2 className="mb-1 text-2xl font-semibold text-ink">Create workspace access</h2><p className="mb-6 text-sm text-slate-500">Verify both your email and mobile number to keep scans and assets private.</p><form onSubmit={submit} className="space-y-4"><div><label htmlFor="displayName" className="mb-1 block text-sm font-medium text-slate-700">Display name</label><input id="displayName" required value={displayName} onChange={(event) => setDisplayName(event.target.value)} className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-emerald" autoComplete="name" /></div><div><label htmlFor="register-email" className="mb-1 block text-sm font-medium text-slate-700">Email</label><input id="register-email" required type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-emerald" autoComplete="email" /></div><div><label htmlFor="phone" className="mb-1 block text-sm font-medium text-slate-700">Mobile number</label><input id="phone" required type="tel" placeholder="+15551234567" value={phone} onChange={(event) => setPhone(event.target.value)} className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-emerald" autoComplete="tel" /></div><PasswordField id="register-password" value={password} onChange={setPassword} /><p className="-mt-2 text-xs text-slate-500">At least 12 characters, with upper, lower, and numeric characters.</p><PasswordField id="password-confirmation" value={confirmation} onChange={setConfirmation} label="Confirm password" />{error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}<button type="submit" disabled={busy} className="w-full rounded-lg bg-emerald px-4 py-2.5 font-semibold text-white disabled:opacity-60">{busy ? "Creating account…" : "Create account"}</button></form><p className="mt-6 text-center text-sm text-slate-500">Already registered? <Link className="font-semibold text-emerald" to="/login">Sign in</Link></p></AuthShell>;
}
