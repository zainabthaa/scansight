import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api/client";
import { Tag } from "./components/Badges";
import { ScanForm } from "./components/ScanForm";
import { ScanHistory } from "./components/ScanHistory";
import { ScanProgress } from "./components/ScanProgress";
import { ScanResults } from "./components/ScanResults";
import { useScanEvents } from "./hooks/useScanEvents";
import type { Options, ScanJob, ScanRequest, ScanSummary } from "./types";

const isFinished = (j: ScanJob | null) => j?.status === "completed" || j?.status === "failed";

export default function App() {
  const [options, setOptions] = useState<Options | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [job, setJob] = useState<ScanJob | null>(null);
  const mainRef = useRef<HTMLElement>(null);

  // Bring the progress/results panel into view when a different scan is shown.
  const jobId = job?.id;
  useEffect(() => {
    if (jobId) mainRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [jobId]);

  const refreshHistory = useCallback(() => {
    api.listScans().then(setHistory).catch(() => undefined);
  }, []);

  useEffect(() => {
    api.options().then(setOptions).catch((e: Error) => setLoadError(e.message));
    refreshHistory();
  }, [refreshHistory]);

  const live = job !== null && !isFinished(job);
  const event = useScanEvents(job?.id ?? null, live);

  // When the progress stream reports a final state, load the full result.
  useEffect(() => {
    if (!job || !event) return;
    if (event.status === "completed" || event.status === "failed") {
      api.getScan(job.id).then((full) => {
        setJob(full);
        refreshHistory();
      });
    }
  }, [event, job, refreshHistory]);

  async function startScan(req: ScanRequest) {
    const created = await api.createScan(req);
    setJob(created);
    refreshHistory();
  }

  async function selectScan(id: string) {
    setJob(await api.getScan(id));
  }

  async function deleteScan(id: string) {
    await api.deleteScan(id).catch(() => undefined);
    if (job?.id === id) setJob(null);
    refreshHistory();
  }

  return (
    <div className="mx-auto max-w-7xl px-4 pb-16 sm:px-6">
      <header className="flex flex-wrap items-center gap-3 py-6">
        <img src="/favicon.svg" alt="" className="h-9 w-9" />
        <div>
          <h1 className="text-lg font-semibold tracking-tight">ScanSight</h1>
          <p className="text-xs text-ink-400">Nmap scanning · CVE enrichment · AI explanations</p>
        </div>
        <div className="ml-auto flex gap-2">
          {options?.demo_mode && <Tag tone="warn">Demo mode: replaying a recorded scan</Tag>}
          {options && (
            <Tag tone={options.ai_enabled ? "accent" : "neutral"}>
              AI: {options.ai_enabled ? options.ai_provider : "off"}
            </Tag>
          )}
        </div>
      </header>

      {loadError && (
        <div className="card mb-6 border-sev-critical/40 p-4 text-sm text-sev-critical">
          Can't reach the API ({loadError}). Is the backend running on port 8000?
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[400px_minmax(0,1fr)]">
        <aside className="min-w-0 space-y-6">
          {options && <ScanForm options={options} busy={live} onSubmit={startScan} />}
          <ScanHistory scans={history} activeId={job?.id ?? null} onSelect={selectScan} onDelete={deleteScan} />
        </aside>

        <main ref={mainRef} className="min-w-0 scroll-mt-6 space-y-6">
          {!job && <EmptyState />}
          {job && live && <ScanProgress target={job.target} event={event} />}
          {job && isFinished(job) && <ScanResults job={job} aiEnabled={!!options?.ai_enabled} />}
        </main>
      </div>

      <footer className="mt-16 border-t border-ink-800 pt-6 text-xs text-ink-400">
        Only scan systems you own or have explicit permission to test. Built with Nmap, FastAPI
        and React.
      </footer>
    </div>
  );
}

function EmptyState() {
  const steps = [
    ["Pick a target", "Use the bundled lab (172.28.0.10) or scanme.nmap.org, Nmap's official test host."],
    ["Choose scan settings", "The command preview shows the exact nmap flags and what each one does."],
    ["Review CVEs", "Detected versions are matched to CVEs, scored, and flagged if exploited in the wild."],
    ["Understand them", "Ask the AI for a plain-language summary of impact and how to fix it."],
  ];
  return (
    <div className="card p-8">
      <h2 className="text-xl font-semibold">Find out what's exposed, and what it means.</h2>
      <p className="mt-2 max-w-xl text-sm text-ink-400">
        ScanSight runs Nmap with safe, allowlisted options, looks up known vulnerabilities for every
        service it finds, and explains them in plain language.
      </p>
      <ol className="mt-8 grid gap-4 sm:grid-cols-2">
        {steps.map(([title, body], i) => (
          <li key={title} className="rounded-xl border border-ink-700/70 bg-ink-850/50 p-4">
            <span className="font-mono text-xs text-accent">0{i + 1}</span>
            <p className="mt-1 text-sm font-medium">{title}</p>
            <p className="mt-1 text-xs leading-relaxed text-ink-400">{body}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}
