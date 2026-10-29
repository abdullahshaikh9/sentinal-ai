import { Link, useLocation } from "react-router-dom";
import { Activity, ArrowLeftRight, Bot, ClipboardCheck, FileText, FolderSearch, Gauge, History, Radar, Settings, Shield, ShieldCheck, X } from "lucide-react";
import type { NavItem } from "../types";

const icons = { Gauge, Radar, History, ClipboardCheck, Shield, Bot, FolderSearch, FileText, Settings, Activity, ArrowLeftRight, ShieldCheck };
const items: NavItem[] = [
  { label: "Overview", path: "/dashboard", icon: "Gauge" }, { label: "Websites & Assets", path: "/domains", icon: "FolderSearch" },
  { label: "Security Scans", path: "/scans", icon: "Radar" }, { label: "Findings", path: "/findings", icon: "ClipboardCheck" },
  { label: "Compare scans", path: "/scans/compare", icon: "ArrowLeftRight" },
  { label: "Remediation", path: "/remediation", icon: "Shield" }, { label: "Verification", path: "/verification", icon: "History" },
  { label: "Reports", path: "/reports", icon: "FileText" }, { label: "AI Assistant", path: "/assistant", icon: "Bot" },
  { label: "Activity Log", path: "/activity", icon: "Activity" }, { label: "Settings", path: "/settings", icon: "Settings" }
];

export function Sidebar({ onClose, isAdmin = false }: { onClose?: () => void; isAdmin?: boolean }) {
  const { pathname } = useLocation();
  const navigationItems = isAdmin ? [...items, { label: "Admin Control Center", path: "/admin", icon: "ShieldCheck" }] : items;
  const activePath = (path: string) => {
    if (path === "/scans") return pathname === path || pathname === "/scans/new" || /^\/scans\/\d+$/.test(pathname);
    if (path === "/findings") return pathname === path || /^\/findings\/\d+$/.test(pathname);
    return pathname === path;
  };
  return <aside className="command-sidebar flex min-h-screen w-64 shrink-0 flex-col px-4 py-6 text-slate-300">
    {onClose && <button onClick={onClose} className="absolute right-4 top-4 rounded-lg p-2 text-slate-400 hover:bg-white/10 hover:text-white" aria-label="Close navigation"><X size={18} /></button>}
    <div className="mb-8 flex items-center gap-3 px-3"><div className="brand-mark rounded-xl bg-emerald p-2.5 text-white"><Activity size={19} /></div><div><div className="font-semibold tracking-tight text-white">Sentinel AI</div><div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Cyber command</div></div></div>
    <nav aria-label="Primary navigation" className="flex-1 space-y-1">{navigationItems.map((item) => { const Icon = icons[item.icon as keyof typeof icons]; const isActive = activePath(item.path); return <Link key={item.path} to={item.path} onClick={onClose} aria-current={isActive ? "page" : undefined} className={`nav-link ${isActive ? "nav-link-active" : ""}`}><Icon size={17} />{item.label}</Link>; })}</nav>
    <div className="border-t border-white/10 px-3 pt-5 text-xs leading-5 text-slate-500">Assess responsibly.<br />Only scan assets you are authorized to test.</div>
  </aside>;
}

