import type { ScanSummary } from "../types";
import { StatusDot } from "./Badges";

interface Props {
  scans: ScanSummary[];
  activeId: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}

export function ScanHistory({ scans, activeId, onSelect, onDelete }: Props) {
  return (
    <div className="card p-4">
      <h2 className="label">History</h2>
      {scans.length === 0 ? (
        <p className="py-2 text-xs text-ink-400">No scans yet.</p>
      ) : (
        <ul className="-mx-1 max-h-80 space-y-0.5 overflow-y-auto">
          {scans.map((s) => (
            <li key={s.id} className="group flex items-center">
              <button
                type="button"
                onClick={() => onSelect(s.id)}
                className={`flex min-w-0 flex-1 items-center gap-2.5 rounded-lg px-2 py-2 text-left transition ${
                  s.id === activeId ? "bg-ink-800" : "hover:bg-ink-800/60"
                }`}
              >
                <StatusDot status={s.status} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-xs">{s.target}</span>
                  <span className="block text-[11px] text-ink-400">
                    {new Date(s.created_at).toLocaleString()} · {s.open_ports} open · {s.cve_count} CVEs
                  </span>
                </span>
                {!!s.severity_counts?.critical && (
                  <span className="rounded bg-sev-critical/15 px-1.5 text-[11px] font-semibold text-sev-critical">
                    {s.severity_counts.critical}
                  </span>
                )}
              </button>
              <button
                type="button"
                aria-label={`Delete scan of ${s.target}`}
                onClick={() => onDelete(s.id)}
                className="ml-1 rounded px-1.5 py-1 text-xs text-ink-400 opacity-0 transition hover:text-sev-critical group-hover:opacity-100 focus:opacity-100"
              >
                ✕
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
