import { ArrowRight, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

type EmptyStateProps = { title: string; description: string; actionLabel?: string };

export function EmptyState({ title, description, actionLabel }: EmptyStateProps) {
  return <div className="empty-state">
    <div className="mb-4 inline-flex rounded-full bg-emerald-50 p-3 text-emerald"><ShieldCheck size={24} /></div>
    <h2 className="text-lg font-semibold text-ink">{title}</h2>
    <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">{description}</p>
    {actionLabel && <Link to="/scans/new" className="button-primary mt-5">{actionLabel}<ArrowRight size={16} /></Link>}
  </div>;
}

