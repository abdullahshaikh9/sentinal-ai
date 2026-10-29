import { useEffect, useState } from "react";
import { Bell, LogOut, Menu, UserRound } from "lucide-react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { getNotifications, markNotificationRead } from "../lib/api";
import type { Notification } from "../types";
import { Sidebar } from "./Sidebar";
import { GlobalSearch } from "../components/GlobalSearch";

function getRouteLabel(pathname: string): string {
  if (pathname === "/dashboard") return "Overview";
  if (pathname === "/domains") return "Websites & Assets";
  if (pathname === "/scans") return "Security Scans";
  if (pathname === "/scans/new") return "New Scan";
  if (pathname === "/scans/compare") return "Compare Scans";
  if (/^\/scans\/\d+$/.test(pathname)) return "Scan Details";
  if (pathname === "/findings") return "Findings";
  if (/^\/findings\/\d+$/.test(pathname)) return "Finding Details";
  if (pathname === "/remediation") return "Remediation";
  if (pathname === "/verification") return "Verification";
  if (pathname === "/reports") return "Reports";
  if (pathname === "/assistant") return "AI Assistant";
  if (pathname === "/activity") return "Activity Log";
  if (pathname === "/settings") return "Settings";
  if (pathname === "/admin") return "Admin Control Center";
  return "Security operations";
}

export function AppLayout() {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[] | null>(null);
  const [notificationError, setNotificationError] = useState<string | null>(null);
  const { user, logout, error } = useAuth();
  const loadNotifications = () => { setNotificationError(null); getNotifications().then((items) => setNotifications(Array.isArray(items) ? items : [])).catch((reason: unknown) => setNotificationError(reason instanceof Error ? reason.message : "Notifications could not be loaded.")); };
  useEffect(() => { loadNotifications(); }, []);
  useEffect(() => {
    const label = getRouteLabel(location.pathname);
    document.title = label === "Security operations" ? "Sentinel AI" : `${label} · Sentinel AI`;
  }, [location.pathname]);
  function toggleNotifications() { const opening = !notificationOpen; setNotificationOpen(opening); if (opening) loadNotifications(); }
  const unreadCount = notifications?.filter((item) => item.read_at === null).length ?? 0;
  async function openNotification(item: Notification) { if (item.read_at) return; try { const updated = await markNotificationRead(item.id); setNotifications((current) => current?.map((entry) => entry.id === updated.id ? updated : entry) ?? null); } catch (reason) { setNotificationError(reason instanceof Error ? reason.message : "The notification could not be marked read."); } }
  const isAdmin = Boolean(user?.is_admin);
  return <div className="cyber-shell flex min-h-screen">{mobileOpen && <div className="fixed inset-0 z-40 bg-[#030914]/80 backdrop-blur-sm lg:hidden" onClick={() => setMobileOpen(false)}><div className="h-full" onClick={(event) => event.stopPropagation()}><Sidebar isAdmin={isAdmin} onClose={() => setMobileOpen(false)} /></div></div>}<div className="hidden lg:block"><Sidebar isAdmin={isAdmin} /></div><div className="min-w-0 flex-1"><header className="command-header flex min-h-16 items-center justify-between gap-3 px-4 sm:px-8"><div className="flex min-w-0 flex-1 items-center gap-3"><button onClick={() => setMobileOpen(true)} className="rounded-lg p-2 text-slate-500 lg:hidden" aria-label="Open navigation"><Menu size={20} /></button><div className="hidden truncate text-xs font-medium uppercase tracking-[0.12em] text-slate-500 md:block">Sentinel workspace <span className="mx-2 text-slate-300">/</span><span className="text-ink">{getRouteLabel(location.pathname)}</span></div><GlobalSearch /></div><div className="flex shrink-0 items-center gap-3"><div className="relative"><button onClick={toggleNotifications} aria-label={`Notifications${unreadCount ? `, ${unreadCount} unread` : ""}`} aria-expanded={notificationOpen} className="relative rounded-lg border border-slate-200 bg-white p-2 text-slate-500 hover:border-emerald hover:text-emerald"><Bell size={17} />{unreadCount > 0 && <span className="absolute -right-1 -top-1 min-w-4 rounded-full bg-emerald px-1 text-[10px] font-bold leading-4 text-white">{unreadCount > 9 ? "9+" : unreadCount}</span>}</button>{notificationOpen && <section className="notification-popover absolute right-0 z-30 mt-3 w-[min(22rem,calc(100vw-2rem))] rounded-xl border border-slate-200 bg-white p-3 shadow-2xl" aria-label="Notifications"><div className="mb-2 flex items-center justify-between px-1"><h2 className="font-semibold text-ink">Notifications</h2><span className="text-xs text-slate-500">{unreadCount} unread</span></div>{notificationError ? <p role="alert" className="p-3 text-sm text-red-700">{notificationError}</p> : notifications === null ? <p className="p-3 text-sm text-slate-500">Loading notifications…</p> : notifications.length === 0 ? <p className="p-3 text-sm text-slate-500">No notifications recorded yet.</p> : <div className="max-h-80 space-y-1 overflow-y-auto">{notifications.map((item) => <div key={item.id} className={`rounded-lg p-3 ${item.read_at ? "" : "bg-emerald/10"}`}><p className="text-sm font-semibold text-ink">{item.title}</p><p className="mt-1 text-xs leading-5 text-slate-600">{item.message}</p><div className="mt-2 flex items-center justify-between gap-2"><time className="text-[10px] text-slate-500">{new Date(item.created_at).toLocaleString()}</time>{item.scan_id && <Link onClick={() => void openNotification(item)} to={`/scans/${item.scan_id}`} className="text-xs font-semibold text-emerald">Open scan</Link>}{!item.scan_id && !item.read_at && <button onClick={() => void openNotification(item)} className="text-xs font-semibold text-emerald">Mark read</button>}</div></div>)}</div>}<button className="mt-2 w-full border-t border-slate-200 pt-2 text-xs font-semibold text-emerald" onClick={loadNotifications}>Refresh notification feed</button></section>}</div><span className="hidden items-center gap-2 text-sm font-medium text-ink sm:flex"><UserRound size={17} className="text-emerald" />{user?.display_name}</span><button onClick={() => void logout()} title="Sign out" aria-label="Sign out" className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-ink"><LogOut size={17} /></button></div></header><main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-8 sm:py-8">{error && <div role="alert" className="mb-5 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">{error}</div>}<Outlet /></main></div></div>;
}

