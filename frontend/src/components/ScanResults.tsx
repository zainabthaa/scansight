import { useMemo, useState } from "react";
import type { CVE, ScanJob, Severity } from "../types";
import { SEVERITY_STYLES, Tag } from "./Badges";
import { CveRow } from "./CveRow";

const FILTERS: (Severity | "all")[] = ["all", "critical", "high", "medium", "low"];

type SortKey = "priority" | "epss" | "cvss";
const SORTS: { id: SortKey; label: string; hint: string }[] = [
  { id: "priority", label: "Priority", hint: "Exploited in the wild first, then EPSS, then CVSS" },
  { id: "epss", label: "EPSS", hint: "Most likely to be exploited in the next 30 days" },
  { id: "cvss", label: "CVSS", hint: "Highest severity score" },
];
// EPSS >= 10% puts a CVE in roughly the top few percent of all CVEs by exploitation likelihood.
const LIKELY_EPSS = 0.1;

const num = (v: number | null) => v ?? -1;
const SORTERS: Record<SortKey, (a: CVE, b: CVE) => number> = {
  priority: (a, b) =>
    Number(b.in_kev) - Number(a.in_kev) || num(b.epss) - num(a.epss) || num(b.cvss) - num(a.cvss),
  epss: (a, b) => num(b.epss) - num(a.epss) || num(b.cvss) - num(a.cvss),
  cvss: (a, b) => num(b.cvss) - num(a.cvss) || num(b.epss) - num(a.epss),
};

export function ScanResults({ job, aiEnabled }: { job: ScanJob; aiEnabled: boolean }) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [sort, setSort] = useState<SortKey>("priority");
  const result = job.result;

  const stats = useMemo(() => {
    const ports = result?.hosts.flatMap((h) => h.ports) ?? [];
    const cves = ports.flatMap((p) => p.cves);
    return {
      open: ports.filter((p) => p.state === "open").length,
      cves: cves.length,
      kev: cves.filter((c) => c.in_kev).length,
      exploits: cves.filter((c) => c.is_exploit).length,
      hasEpss: cves.some((c) => c.epss != null),
      likely: cves.filter((c) => (c.epss ?? 0) >= LIKELY_EPSS).length,
    };
  }, [result]);

  if (job.status === "failed") {
    return (
      <div className="card border-sev-critical/40 p-6">
        <p className="text-sm font-semibold text-sev-critical">Scan failed</p>
        <p className="mt-2 text-sm text-ink-300">{job.error}</p>
        <pre className="mt-4 overflow-x-auto rounded-lg bg-ink-950 p-3 font-mono text-xs text-ink-400">
          {job.command.join(" ")}
        </pre>
      </div>
    );
  }
  if (!result) return null;

  const counts = job.severity_counts;

  return (
    <div className="space-y-5">
      {/* Summary */}
      <div className={`grid grid-cols-2 gap-3 ${stats.hasEpss ? "lg:grid-cols-5" : "lg:grid-cols-4"}`}>
        <Stat label="Open ports" value={stats.open} />
        <Stat label="CVEs found" value={stats.cves} />
        <Stat label="Exploited in the wild" value={stats.kev} tone={stats.kev ? "danger" : undefined} hint="CISA KEV" />
        <Stat label="Public exploits" value={stats.exploits} tone={stats.exploits ? "warn" : undefined} />
        {stats.hasEpss && (
          <Stat label="Likely exploited" value={stats.likely} tone={stats.likely ? "warn" : undefined} hint="EPSS ≥ 10%" />
        )}
      </div>

      {counts && stats.cves > 0 && <SeverityBar counts={counts} />}

      {result.hosts.map((host) => (
        <section key={host.address} className="card overflow-hidden">
          <header className="flex flex-wrap items-center gap-3 border-b border-ink-700/70 px-5 py-4">
            <span className="font-mono text-base">{host.address}</span>
            {host.hostnames.map((h) => (
              <Tag key={h}>{h}</Tag>
            ))}
            <Tag tone={host.status === "up" ? "accent" : "neutral"}>host {host.status}</Tag>
            {host.os_matches[0] && (
              <span className="text-xs text-ink-400">
                OS: {host.os_matches[0].name} ({host.os_matches[0].accuracy}%)
              </span>
            )}
            <span className="ml-auto text-xs text-ink-400">
              {result.elapsed_seconds != null && `${result.elapsed_seconds.toFixed(1)}s · `}nmap {result.nmap_version}
            </span>
          </header>

          {host.ports.length === 0 ? (
            <p className="px-5 py-6 text-sm text-ink-400">
              No open ports found in the scanned range. Try more ports, or a different scan type.
            </p>
          ) : (
            <div className="divide-y divide-ink-700/60">
              {stats.cves > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 px-5 py-3">
                  {FILTERS.map((f) => (
                    <button
                      key={f}
                      type="button"
                      onClick={() => setFilter(f)}
                      className={`rounded-md px-2.5 py-1 text-xs font-medium capitalize ring-1 ring-inset transition ${
                        filter === f
                          ? f === "all"
                            ? "bg-ink-100 text-ink-950 ring-ink-100"
                            : SEVERITY_STYLES[f]
                          : "text-ink-400 ring-ink-700 hover:text-ink-100"
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                  <div className="ml-auto flex items-center gap-1.5 text-xs text-ink-400">
                    <span>Sort</span>
                    {SORTS.filter((o) => o.id !== "epss" || stats.hasEpss).map((o) => (
                      <button
                        key={o.id}
                        type="button"
                        title={o.hint}
                        onClick={() => setSort(o.id)}
                        className={`rounded-md px-2.5 py-1 font-medium ring-1 ring-inset transition ${
                          sort === o.id ? "bg-ink-700 text-ink-100 ring-ink-600" : "ring-ink-700 hover:text-ink-100"
                        }`}
                      >
                        {o.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {host.ports.map((port) => {
                const cves = port.cves
                  .filter((c) => filter === "all" || c.severity === filter)
                  .sort(SORTERS[sort]);
                return (
                  <div key={`${port.protocol}-${port.port}`}>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3">
                      <span className="w-24 font-mono text-sm">
                        {port.port}/{port.protocol}
                      </span>
                      <span
                        className={`w-20 text-xs font-semibold uppercase ${
                          port.state === "open" ? "text-accent" : "text-ink-400"
                        }`}
                      >
                        {port.state}
                      </span>
                      <span className="text-sm text-ink-300">{port.service ?? "unknown"}</span>
                      <span className="text-sm">
                        {[port.product, port.version].filter(Boolean).join(" ")}
                        {port.extrainfo && <span className="text-ink-400"> {port.extrainfo}</span>}
                      </span>
                      {port.cves.length > 0 && (
                        <span className="ml-auto text-xs text-ink-400">{port.cves.length} CVEs</span>
                      )}
                    </div>
                    {cves.length > 0 && (
                      <ul className="mx-5 mb-4 overflow-hidden rounded-xl border border-ink-700/70 bg-ink-850/60">
                        {cves.map((cve) => (
                          <CveRow key={cve.id} cve={cve} port={port} aiEnabled={aiEnabled} />
                        ))}
                      </ul>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>
      ))}

      <p className="text-xs leading-relaxed text-ink-400">
        CVEs are matched from detected product versions. Vendors sometimes backport fixes without
        changing the version string, so verify findings before treating them as confirmed.
      </p>
    </div>
  );
}

function Stat({ label, value, tone, hint }: { label: string; value: number; tone?: "danger" | "warn"; hint?: string }) {
  const color = tone === "danger" ? "text-sev-critical" : tone === "warn" ? "text-sev-high" : "text-ink-100";
  return (
    <div className="card px-4 py-3">
      <p className={`text-2xl font-semibold ${color}`}>{value}</p>
      <p className="mt-0.5 text-xs text-ink-400">
        {label}
        {hint && <span className="ml-1 text-ink-400/70">({hint})</span>}
      </p>
    </div>
  );
}

function SeverityBar({ counts }: { counts: NonNullable<ScanJob["severity_counts"]> }) {
  const entries = (["critical", "high", "medium", "low", "unknown"] as const).filter((k) => counts[k] > 0);
  const total = entries.reduce((sum, k) => sum + counts[k], 0);
  const colors = {
    critical: "bg-sev-critical",
    high: "bg-sev-high",
    medium: "bg-sev-medium",
    low: "bg-sev-low",
    unknown: "bg-sev-unknown",
  };
  return (
    <div className="card px-5 py-4">
      <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full">
        {entries.map((k) => (
          <div key={k} className={colors[k]} style={{ width: `${(counts[k] / total) * 100}%` }} />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-ink-300">
        {entries.map((k) => (
          <span key={k} className="flex items-center gap-1.5 capitalize">
            <span className={`h-2 w-2 rounded-full ${colors[k]}`} />
            {k} <span className="font-mono text-ink-400">{counts[k]}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
