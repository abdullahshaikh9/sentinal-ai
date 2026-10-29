import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { LoaderCircle } from "lucide-react";
import { AuthProvider, RequireAuth } from "./auth/AuthContext";
import { AppLayout } from "./layout/AppLayout";
import { LoginPage, RegisterPage, VerifyPage } from "./pages/AuthPages";
import { LandingPage } from "./pages/LandingPage";

const DashboardPage = lazy(() => import("./pages/DashboardPage").then((module) => ({ default: module.DashboardPage })));
const AdminPage = lazy(() => import("./pages/AdminPage").then((module) => ({ default: module.AdminPage })));
const AssistantPage = lazy(() => import("./pages/AssistantPage").then((module) => ({ default: module.AssistantPage })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then((module) => ({ default: module.SettingsPage })));
const FindingDetailPage = lazy(() => import("./pages/FindingDetailPage").then((module) => ({ default: module.FindingDetailPage })));
const RemediationPage = lazy(() => import("./pages/RemediationPage").then((module) => ({ default: module.RemediationPage })));
const ScanComparisonPage = lazy(() => import("./pages/ScanComparisonPage").then((module) => ({ default: module.ScanComparisonPage })));
const ScanHistoryPage = lazy(() => import("./pages/ScanHistoryPage").then((module) => ({ default: module.ScanHistoryPage })));
const ReportsPage = lazy(() => import("./pages/ReportsPage").then((module) => ({ default: module.ReportsPage })));
const ActivityPage = lazy(() => import("./pages/Pages").then((module) => ({ default: module.ActivityPage })));
const AssetsPage = lazy(() => import("./pages/Pages").then((module) => ({ default: module.AssetsPage })));
const FindingsPage = lazy(() => import("./pages/Pages").then((module) => ({ default: module.FindingsPage })));
const NewScan = lazy(() => import("./pages/Pages").then((module) => ({ default: module.NewScan })));
const ScanDetailPage = lazy(() => import("./pages/Pages").then((module) => ({ default: module.ScanDetailPage })));
const VerificationPage = lazy(() => import("./pages/Pages").then((module) => ({ default: module.VerificationPage })));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage").then((module) => ({ default: module.NotFoundPage })));

function RouteLoadingFallback() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-[#f5f8fc] px-4">
      <div role="status" aria-live="polite" className="flex w-full max-w-sm items-center gap-4 rounded-2xl border border-slate-200 bg-white p-5 text-sm text-slate-600 shadow-sm">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-emerald/10 text-emerald">
          <LoaderCircle size={20} className="animate-spin" aria-hidden="true" />
        </span>
        <span>Loading Sentinel AI workspace…</span>
      </div>
    </main>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Suspense fallback={<RouteLoadingFallback />}>
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/verify" element={<VerifyPage />} />
            <Route element={<RequireAuth><AppLayout /></RequireAuth>}>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/admin" element={<AdminPage />} />
              <Route path="/scans/new" element={<NewScan />} />
              <Route path="/scans" element={<ScanHistoryPage />} />
              <Route path="/scans/compare" element={<ScanComparisonPage />} />
              <Route path="/scans/:scanId" element={<ScanDetailPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/findings/:findingId" element={<FindingDetailPage />} />
              <Route path="/remediation" element={<RemediationPage />} />
              <Route path="/assistant" element={<AssistantPage />} />
              <Route path="/domains" element={<AssetsPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/verification" element={<VerificationPage />} />
              <Route path="/activity" element={<ActivityPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </Suspense>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
