import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Link } from "react-router-dom";
import { Search } from "lucide-react";
import { searchRecords } from "../lib/api";
import type { SearchResult } from "../types";

export function GlobalSearch() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [focused, setFocused] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const resultLinks = useRef<Array<HTMLAnchorElement | null>>([]);
  const blurTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (blurTimerRef.current !== null) {
        window.clearTimeout(blurTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    const value = query.trim();
    if (value.length < 2) {
      setResults(null);
      setError(null);
      setLoading(false);
      setActiveIndex(-1);
      return;
    }
    let active = true;
    setResults(null);
    setLoading(true);
    setError(null);
    setActiveIndex(-1);
    const timer = window.setTimeout(() => {
      searchRecords(value)
        .then((items) => { if (active) setResults(items); })
        .catch((reason: unknown) => { if (active) { setResults([]); setError(reason instanceof Error ? reason.message : "Search is temporarily unavailable."); } })
        .finally(() => { if (active) setLoading(false); });
    }, 250);
    return () => { active = false; window.clearTimeout(timer); };
  }, [query]);

  const open = focused && query.trim().length >= 2;
  function selectResult() { setFocused(false); setQuery(""); setResults(null); }
  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Escape") { setQuery(""); setFocused(false); setActiveIndex(-1); return; }
    if ((event.key === "ArrowDown" || event.key === "ArrowUp") && results?.length) {
      event.preventDefault();
      setActiveIndex((index) => event.key === "ArrowDown" ? Math.min(index + 1, results.length - 1) : Math.max(index < 0 ? results.length - 1 : index - 1, 0));
    }
    if (event.key === "Enter" && activeIndex >= 0) {
      event.preventDefault();
      resultLinks.current[activeIndex]?.click();
    }
  }

  return <div className="relative w-28 min-w-0 shrink-0 sm:w-auto sm:min-w-40 sm:max-w-xs sm:flex-1">
    <label className="relative block">
      <Search size={15} aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
      <span className="sr-only">Search assets, scans, and findings</span>
      <input
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        onFocus={() => {
          if (blurTimerRef.current !== null) {
            window.clearTimeout(blurTimerRef.current);
            blurTimerRef.current = null;
          }
          setFocused(true);
        }}
        onBlur={() => {
          if (blurTimerRef.current !== null) {
            window.clearTimeout(blurTimerRef.current);
          }
          blurTimerRef.current = window.setTimeout(() => setFocused(false), 120);
        }}
        onKeyDown={handleKeyDown}
        className="field-input h-10 py-2 pl-9 pr-3 text-xs"
        placeholder="Search assets, scans, findings"
        aria-label="Search assets, scans, and findings"
        aria-expanded={open}
        aria-controls="global-search-results"
        aria-activedescendant={activeIndex >= 0 ? `global-search-option-${activeIndex}` : undefined}
        aria-autocomplete="list"
        role="combobox"
      />
    </label>
    {open && <div id="global-search-results" role="listbox" aria-label="Search results" className="absolute left-0 right-0 top-full z-40 mt-2 max-h-80 overflow-y-auto rounded-xl border border-slate-200 bg-white p-2 shadow-xl">
      {loading ? <p role="status" className="px-3 py-2 text-xs text-slate-500">Searching your records…</p>
        : error ? <p role="alert" className="px-3 py-2 text-xs text-red-700">{error}</p>
          : results === null ? <p className="px-3 py-2 text-xs text-slate-500">Enter at least two characters.</p>
            : results.length === 0 ? <p className="px-3 py-2 text-xs text-slate-500">No matching records in your workspace.</p>
              : results.map((item, index) => <Link key={`${item.kind}-${item.id}`} id={`global-search-option-${index}`} ref={(node) => { resultLinks.current[index] = node; }} role="option" aria-selected={activeIndex === index} tabIndex={-1} to={item.href} onClick={selectResult} className={`block rounded-lg px-3 py-2 hover:bg-slate-50 focus:bg-slate-50 focus:outline-none ${activeIndex === index ? "bg-slate-50" : ""}`}>
                <span className="block truncate text-xs font-semibold text-ink">{item.label}</span>
                <span className="mt-1 block truncate text-[10px] capitalize text-slate-500">{item.kind} · {item.description}</span>
              </Link>)}
    </div>}
  </div>;
}
