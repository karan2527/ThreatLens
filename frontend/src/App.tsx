import { useEffect, useState } from "react";
import {
  AlertCircle,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Fingerprint,
  LayoutDashboard,
  LoaderCircle,
  Menu,
  ShieldCheck,
  X,
} from "lucide-react";

import {
  apiErrorMessage,
  createScan,
  getScanResults,
  getScanStatus,
  type ScanResults,
  type ScanStatusResponse,
} from "./api";
import { indicatorSchema } from "./utils/validation";
import "./styles.css";

const navigation = [
  { label: "Scanner", href: "#scanner", icon: Fingerprint },
  { label: "Dashboard", href: "#dashboard", icon: LayoutDashboard },
  { label: "History", href: "#history", icon: BarChart3 },
];

const terminalStatuses = new Set(["COMPLETED", "FAILED", "CANCELLED", "PARTIAL"]);

function App() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [indicator, setIndicator] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!scanId || (status && terminalStatuses.has(status.status))) return;
    let active = true;
    const poll = async () => {
      try {
        const nextStatus = await getScanStatus(scanId);
        if (active) setStatus(nextStatus);
        if (active && terminalStatuses.has(nextStatus.status)) {
          const nextResults = await getScanResults(scanId);
          setResults(nextResults);
        }
      } catch (requestError) {
        if (active) setError(apiErrorMessage(requestError));
      }
    };
    void poll();
    const interval = window.setInterval(() => void poll(), 1200);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [scanId, status]);

  const submitScan = async () => {
    setError(null);
    setResults(null);
    const parsed = indicatorSchema.safeParse(indicator.trim());
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? "Enter a valid indicator.");
      return;
    }
    setSubmitting(true);
    try {
      const created = await createScan(parsed.data);
      setScanId(created.scan_id);
      setStatus({
        scan_id: created.scan_id,
        status: created.status,
        progress: created.progress,
        current_stage: "queued",
        verdict: null,
        severity: null,
        risk_score: null,
        created_at: new Date().toISOString(),
        started_at: null,
        completed_at: null,
      });
    } catch (requestError) {
      setError(apiErrorMessage(requestError));
    } finally {
      setSubmitting(false);
    }
  };

  const startOver = () => {
    setIndicator("");
    setScanId(null);
    setStatus(null);
    setResults(null);
    setError(null);
  };

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#scanner" aria-label="ThreatLens home">
          <span className="brand-mark" aria-hidden="true"><ShieldCheck size={19} strokeWidth={2.5} /></span>
          <span>ThreatLens</span>
        </a>
        <button className="mobile-menu-button" type="button" aria-label={mobileOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileOpen} onClick={() => setMobileOpen((open) => !open)}>
          {mobileOpen ? <X size={21} /> : <Menu size={21} />}
        </button>
        <nav className={`main-nav ${mobileOpen ? "main-nav-open" : ""}`}>
          {navigation.map(({ label, href, icon: Icon }) => (
            <a key={label} href={href} onClick={() => setMobileOpen(false)}><Icon size={16} aria-hidden="true" />{label}</a>
          ))}
          <a className="nav-help" href="#about" onClick={() => setMobileOpen(false)}><CircleHelp size={16} aria-hidden="true" />About</a>
        </nav>
        <button className="session-button" type="button"><span className="status-dot" aria-hidden="true" />Local session<ChevronDown size={15} aria-hidden="true" /></button>
      </header>

      <main>
        <section className="hero-section" id="scanner">
          <div className="hero-copy">
            <p className="eyebrow"><span className="eyebrow-line" aria-hidden="true" />Threat intelligence, made clear</p>
            <h1>See the signal<br /><em>behind the threat.</em></h1>
            <p className="hero-description">Investigate URLs, domains, IPs, and file hashes with a focused intelligence report built from trusted security sources.</p>
            <div className="hero-actions">
              <a className="button button-primary" href="#scanner-form">Start an investigation<ArrowUpRight size={17} aria-hidden="true" /></a>
              <a className="text-link" href="#about">How it works<ArrowUpRight size={15} aria-hidden="true" /></a>
            </div>
          </div>
          <div className="hero-aside" aria-label="ThreatLens overview">
            <div className="signal-card">
              <div className="signal-card-header"><span className="signal-label">Risk intelligence</span><span className="live-badge"><span className="status-dot" aria-hidden="true" />{status?.status ?? "Ready"}</span></div>
              <div className="signal-score">{results?.risk_score ?? "—"}</div>
              <div className="signal-score-label">{results ? `${results.verdict ?? "UNKNOWN"} assessment` : "Awaiting your first scan"}</div>
              <div className="score-track"><span style={{ width: `${results?.risk_score ?? 6}%` }} /></div>
              <div className="score-scale"><span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span></div>
            </div>
            <div className="hero-note"><span className="note-number">01</span><p>One calm view across multiple threat intelligence providers.</p></div>
          </div>
        </section>

        <section className="scanner-panel" id="scanner-form">
          <div className="section-heading"><div><p className="eyebrow">Investigation workspace</p><h2>{results ? "Investigation complete" : "Start with an indicator"}</h2></div><span className="panel-step">{results ? "03 / 03" : status ? "02 / 03" : "01 / 03"}</span></div>
          <div className="scan-input-shell">
            <div className="input-prefix"><Fingerprint size={19} aria-hidden="true" /></div>
            <input aria-label="Indicator to investigate" placeholder="Paste a URL, domain, IP address, or file hash" type="text" value={indicator} disabled={submitting || Boolean(status && !terminalStatuses.has(status.status))} onChange={(event) => setIndicator(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void submitScan(); }} />
            <button className="button button-dark" type="button" disabled={submitting || Boolean(status && !terminalStatuses.has(status.status))} onClick={() => void submitScan()}>
              {submitting || (status && !terminalStatuses.has(status.status) ? true : false) ? <LoaderCircle className="spin" size={17} aria-hidden="true" /> : <ArrowUpRight size={17} aria-hidden="true" />}
              {submitting ? "Connecting" : status && !terminalStatuses.has(status.status) ? `${status.progress}% · Scanning` : "Investigate"}
            </button>
          </div>
          <div className="input-hints"><span>Supported indicators</span><span>URL&nbsp;&nbsp; / &nbsp;&nbsp;DOMAIN&nbsp;&nbsp; / &nbsp;&nbsp;IP&nbsp;&nbsp; / &nbsp;&nbsp;HASH</span></div>
          {error && <div className="inline-message error-message" role="alert"><AlertCircle size={16} />{error}</div>}
          {status && !results && !error && <div className="progress-message"><LoaderCircle className="spin" size={16} />{status.current_stage.replaceAll("_", " ")} · {status.progress}%</div>}
          {status && terminalStatuses.has(status.status) && !results && !error && <div className="inline-message"><AlertCircle size={16} />Results are not available yet. Try refreshing the results request.</div>}
          {results && <ResultsPanel results={results} onStartOver={startOver} />}
        </section>

        <section className="feature-grid" id="about">
          <article><span className="feature-index">01</span><h3>One clear signal</h3><p>Turn scattered provider results into a measured risk score and useful next action.</p></article>
          <article><span className="feature-index">02</span><h3>Context, not noise</h3><p>See why a result matters with transparent evidence, coverage, and provider detail.</p></article>
          <article><span className="feature-index">03</span><h3>Built for careful work</h3><p>Investigate safely without opening suspicious URLs or exposing your indicator to the browser.</p></article>
        </section>
      </main>
      <footer className="site-footer"><span>ThreatLens <span className="footer-muted">/ Threat intelligence workspace</span></span><span className="footer-muted">Private by default · Local session</span></footer>
    </div>
  );
}

function ResultsPanel({ results, onStartOver }: { results: ScanResults; onStartOver: () => void }) {
  const rationale = results.explanation.verdict_rationale;
  return (
    <div className="results-panel" aria-live="polite">
      <div className="results-header">
        <div><p className="eyebrow">Assessment returned</p><h3>{results.normalized_value}</h3></div>
        <button className="text-link" type="button" onClick={onStartOver}>New investigation <ArrowUpRight size={15} aria-hidden="true" /></button>
      </div>
      <div className="results-summary">
        <div className={`verdict-badge verdict-${(results.verdict ?? "UNKNOWN").toLowerCase()}`}><CheckCircle2 size={17} />{results.verdict ?? "UNKNOWN"}</div>
        <strong>{results.risk_score ?? 0}<small>/ 100</small></strong>
        <span>{results.severity ?? "LOW"} severity</span>
      </div>
      {typeof rationale === "string" && <p className="result-rationale">{rationale}</p>}
      <div className="provider-list">
        {results.provider_results.map((provider) => (
          <div className="provider-row" key={provider.provider_name}><span>{provider.provider_name.replaceAll("_", " ")}</span><span className={`provider-status status-${provider.status.toLowerCase()}`}>{provider.verdict ?? provider.status}</span></div>
        ))}
      </div>
    </div>
  );
}

export default App;
