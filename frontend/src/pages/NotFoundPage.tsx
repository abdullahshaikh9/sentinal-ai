import { ArrowLeft, MapPinOff } from "lucide-react";
import { Link } from "react-router-dom";

export function NotFoundPage() { return <div className="flex min-h-[60vh] items-center justify-center"><section className="empty-state max-w-xl"><div className="mb-4 inline-flex rounded-full bg-slate-100 p-3 text-slate-500"><MapPinOff size={24} /></div><h1 className="text-xl font-semibold text-ink">Page not found</h1><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">That Sentinel workspace route does not exist. No scan or finding data was changed.</p><Link to="/" className="button-primary mt-5"><ArrowLeft size={16} />Return to overview</Link></section></div>; }
