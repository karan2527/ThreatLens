import { useEffect, useState, type ReactNode } from "react";
import {
  AlertCircle,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Fingerprint,
  Github,
  LayoutDashboard,
  LoaderCircle,
  Menu,
  ShieldCheck,
  X,
} from "lucide-react";

import {
  apiErrorMessage,
  createScan,
  getDashboard,
  getHistory,
  getScanResults,
  getScanStatus,
  type DashboardSummary,
  type HistoryResponse,
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
  const [view, setView] = useState(window.location.hash.slice(1) || "scanner");
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [indicator, setIndicator] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const onHashChange = () => setView(window.location.hash.slice(1) || "scanner");
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (view !== "dashboard" && view !== "history") return;
    setPageError(null);
    const load = async () => {
      try {
        if (view === "dashboard") setDashboard(await getDashboard());
        if (view === "history") setHistory(await getHistory());
      } catch (requestError) {
        setPageError(apiErrorMessage(requestError));
      }
    };
    void load();
  }, [view]);

  useEffect(() => {
    if (!scanId || (status && terminalStatuses.has(status.status))) return;
    let active = true;
    const poll = async () => {
      try {
        const nextStatus = await getScanStatus(scanId);
        if (active) setStatus(nextStatus);
        if (active && terminalStatuses.has(nextStatus.status)) {
          if (nextStatus.status === "FAILED" || nextStatus.status === "CANCELLED") {
            setError(
              nextStatus.status === "FAILED"
                ? "The scan failed while the backend was processing it. Check the backend terminal for details and try again."
                : "The scan was cancelled before it completed.",
            );
          } else {
            const nextResults = await getScanResults(scanId);
            setResults(nextResults);
          }
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
          <a
            className="github-link"
            href="https://github.com/karan2527/ThreadLens"
            target="_blank"
            rel="noreferrer"
            title="Star this repo on GitHub"
            aria-label="Star this repo on GitHub"
          >
            <Github size={16} aria-hidden="true" />GitHub
          </a>
        </nav>
        <button className="session-button" type="button"><span className="status-dot" aria-hidden="true" />Local session<ChevronDown size={15} aria-hidden="true" /></button>
      </header>

      <main>
      {view === "dashboard" && <DashboardView data={dashboard} error={pageError} />}
      {view === "history" && <HistoryView data={history} error={pageError} />}
      {view === "about" && <AboutView />}
      {view === "scanner" && <>
        <section className="hero-section" id="scanner">
          <div className="hero-copy">
            <p className="eyebrow"><span className="eyebrow-line" aria-hidden="true" />Threat intelligence, made clear</p>
            <h1>See the signal<br /><em>behind the threat.</em></h1>
            <p className="hero-description">Investigate URLs, domains, IPs, and file hashes with a focused intelligence assessment built from trusted security sources.</p>
            <div className="hero-capabilities" aria-label="ThreatLens capabilities">
              <span>FOUR INDICATOR TYPES</span>
              <span>DNS + RDAP</span>
              <span>THREAT PROVIDERS</span>
              <span>RISK SCORING</span>
              <span>PROVIDER DETAIL</span>
              <span>PRIVATE HISTORY</span>
            </div>
            <div className="hero-actions">
              <a
                className="button button-primary"
                href="#scanner"
                onClick={() => window.setTimeout(() => document.getElementById("scanner-form")?.scrollIntoView({ behavior: "smooth", block: "start" }), 0)}
              >
                Try now<ArrowUpRight size={17} aria-hidden="true" />
              </a>
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

        <section className="how-it-works-section" id="about">
          <div className="how-it-works-heading">
            <div>
              <p className="eyebrow"><span className="eyebrow-line" aria-hidden="true" />How ThreatLens works</p>
              <h2>From indicator to informed action.</h2>
            </div>
            <p>Everything you need to investigate a suspicious signal, without the noise of disconnected tools.</p>
          </div>
          <div className="how-it-works-grid">
            <article><span className="feature-index">01</span><h3>Choose an indicator</h3><p>Enter a URL, domain, public IP address, or file hash. ThreatLens validates the format before any lookup begins.</p></article>
            <article><span className="feature-index">02</span><h3>Get domain context</h3><p>Domain scans add DNS records, RDAP registration, registrar age, nameserver analysis, SPF, DKIM, DMARC, and configuration anomalies.</p></article>
            <article><span className="feature-index">03</span><h3>Compare evidence</h3><p>Relevant threat-intelligence providers are queried and their results are normalized into one consistent view.</p></article>
            <article><span className="feature-index">04</span><h3>Understand the score</h3><p>Correlation turns provider evidence into a risk score, severity, verdict, coverage, and an explanation of what influenced it.</p></article>
            <article><span className="feature-index">05</span><h3>Review the details</h3><p>Inspect each provider response, status, confidence, cached state, and the supporting intelligence behind the assessment.</p></article>
            <article><span className="feature-index">06</span><h3>Revisit your work</h3><p>Use your private browser session to revisit completed investigations and review dashboard trends over time.</p></article>
          </div>
        </section>
        </>}
      </main>
      <footer className="site-footer"><span>ThreatLens <span className="footer-muted">/ Threat intelligence workspace</span></span><span className="footer-muted">Private by default · Local session</span></footer>
    </div>
  );
}

function DashboardView({ data, error }: { data: DashboardSummary | null; error: string | null }) {
  return (
    <section className="page-section" id="dashboard">
      <PageIntro eyebrow="Session overview" title="Your threat picture" description="A private summary of investigations from this browser session." />
      {error && <div className="inline-message error-message"><AlertCircle size={16} />{error}</div>}
      <div className="metric-grid">
        <Metric label="Total investigations" value={data?.total_scans ?? "—"} />
        <Metric label="Completed" value={data?.completed_scans ?? "—"} />
        <Metric label="In progress" value={data?.running_scans ?? "—"} />
        <Metric label="Average risk score" value={data?.average_risk_score ?? "—"} />
      </div>
      <div className="dashboard-columns">
        <div className="data-card">
          <div className="data-card-heading"><span>Verdict distribution</span><BarChart3 size={17} /></div>
          {Object.entries(data?.verdict_counts ?? {}).map(([label, count]) => <DistributionRow key={label} label={label} count={count} total={data?.total_scans ?? 1} />)}
          {!data && <div className="empty-state">Loading your session data…</div>}
          {data && !Object.keys(data.verdict_counts).length && <div className="empty-state">Complete an investigation to see distribution.</div>}
        </div>
        <div className="data-card">
          <div className="data-card-heading"><span>Recent investigations</span><a className="text-link" href="#history">View all <ArrowUpRight size={14} /></a></div>
          {(data?.recent_scans ?? []).map((item) => <HistoryRow key={item.scan_id} item={item} />)}
          {data && !data.recent_scans.length && <div className="empty-state">No investigations yet.</div>}
        </div>
      </div>
    </section>
  );
}

function HistoryView({ data, error }: { data: HistoryResponse | null; error: string | null }) {
  return (
    <section className="page-section" id="history">
      <PageIntro eyebrow="Investigation archive" title="Your history" description="Every scan stays attached to this private browser session." />
      {error && <div className="inline-message error-message"><AlertCircle size={16} />{error}</div>}
      <div className="history-table">
        <div className="history-table-head"><span>Indicator</span><span>Type</span><span>Verdict</span><span>Score</span><span>Status</span></div>
        {data?.items.map((item) => <HistoryRow key={item.scan_id} item={item} table />)}
        {!data && <div className="empty-state">Loading history…</div>}
        {data && !data.items.length && <div className="empty-state">Your completed investigations will appear here.</div>}
      </div>
      {data && <p className="history-count">{data.total} investigation{data.total === 1 ? "" : "s"} recorded</p>}
    </section>
  );
}

function AboutView() {
  return (
    <section className="page-section about-page" id="about-page">
      <PageIntro eyebrow="How to use ThreatLens" title="Clarity for careful investigation." description="ThreatLens brings multiple public threat intelligence sources into one measured, explainable workspace. Follow the flow below to get the most from every investigation." />
      <div className="about-grid">
        <article className="about-card"><span className="feature-index">01 / INPUT</span><h3>Start with a signal</h3><p>Paste a URL, domain, public IP, or MD5, SHA-1, or SHA-256 hash into the scanner. You can press Enter or select Try now.</p></article>
        <article className="about-card"><span className="feature-index">02 / ANALYZE</span><h3>Let the evidence load</h3><p>ThreatLens checks the relevant sources. Domain inputs receive additional DNS and RDAP intelligence, including mail-security and nameserver checks.</p></article>
        <article className="about-card"><span className="feature-index">03 / INTERPRET</span><h3>Read the assessment</h3><p>Start with the verdict, severity, and score. Then read the rationale and inspect provider rows to understand agreement or conflict.</p></article>
        <article className="about-card"><span className="feature-index">04 / REVISIT</span><h3>Use your workspace</h3><p>Dashboard shows totals and distributions. History keeps completed investigations attached to your private browser session.</p></article>
        <article className="about-card"><span className="feature-index">05 / HISTORY</span><h3>Revisit your work</h3><p>Use the history view to return to completed investigations, compare findings, and keep your browser session organized.</p></article>
        <article className="about-card"><span className="feature-index">06 / SAFE USE</span><h3>Keep context in mind</h3><p>A clean result means no malicious findings were returned by enough relevant checks; it is not a guarantee that an indicator is safe.</p></article>
      </div>
      <div className="about-note"><span className="note-number">NOTE</span><p>ThreatLens never opens submitted URLs. Provider availability depends on configured credentials, network access, quotas, and each provider's terms.</p></div>
    </section>
  );
}

function PageIntro({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <div className="page-intro"><p className="eyebrow"><span className="eyebrow-line" aria-hidden="true" />{eyebrow}</p><h1>{title}</h1><p className="hero-description">{description}</p></div>;
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return <div className="metric-card"><span>{label}</span><strong>{value}</strong></div>;
}

function DistributionRow({ label, count, total }: { label: string; count: number; total: number }) {
  return <div className="distribution-row"><div><span>{label}</span><strong>{count}</strong></div><div className="distribution-track"><span style={{ width: `${Math.min(100, (count / Math.max(1, total)) * 100)}%` }} /></div></div>;
}

function HistoryRow({ item, table = false }: { item: import("./api").HistoryItem; table?: boolean }) {
  return <div className={`history-row ${table ? "history-row-table" : ""}`}><span className="history-indicator">{item.normalized_value}</span><span className="history-type">{item.indicator_type}</span><span className={`provider-status status-${(item.verdict ?? item.status).toLowerCase()}`}>{item.verdict ?? item.status}</span><strong>{item.risk_score ?? "—"}</strong>{table && <span className="history-type">{item.status}</span>}</div>;
}

function ResultsPanel({ results, onStartOver }: { results: ScanResults; onStartOver: () => void }) {
  const rationale = results.explanation.verdict_rationale;
  const domainProvider = results.provider_results.find(
    (provider) => provider.provider_name === "domain_intelligence",
  );
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
      {domainProvider?.status === "SUCCESS" && (
        <DomainIntelligencePanel data={domainProvider.normalized_data} />
      )}
    </div>
  );
}

function DomainIntelligencePanel({ data }: { data: Record<string, unknown> }) {
  const records = asRecord(data.dns_records);
  const registration = asRecord(data.registration);
  const nameservers = asRecord(data.nameservers);
  const email = asRecord(data.email_authentication);
  const spf = asRecord(email.spf);
  const dkim = asRecord(email.dkim);
  const dmarc = asRecord(email.dmarc);
  const anomalies = Array.isArray(data.anomalies)
    ? data.anomalies.filter((item): item is string => typeof item === "string")
    : [];
  return (
    <section className="domain-intelligence" aria-label="Domain intelligence">
      <div className="domain-intelligence-heading">
        <div>
          <p className="eyebrow">Domain intelligence</p>
          <h3>DNS, registration &amp; mail security</h3>
        </div>
        <span className="domain-intelligence-badge">RDAP + DNS</span>
      </div>
      <div className="domain-intelligence-grid">
        <DomainInsight title="Registration">
          <span>{stringValue(registration.registrar, "Registrar unavailable")}</span>
          <small>{formatAge(registration.age_days)}</small>
          <small>Registered {stringValue(registration.registration_date, "date unavailable")}</small>
        </DomainInsight>
        <DomainInsight title="Nameservers">
          <span>{stringValue(nameservers.count, "0")} authoritative records</span>
          <small>{stringValue(nameservers.diversity, "unknown")} operator profile</small>
          <small>{listValue(nameservers.nameservers)}</small>
        </DomainInsight>
        <DomainInsight title="Email authentication">
          <span className="auth-row"><AuthStatus label="SPF" value={spf.valid === true} /></span>
          <span className="auth-row"><AuthStatus label="DKIM" value={dkim.present === true} /></span>
          <span className="auth-row"><AuthStatus label="DMARC" value={dmarc.valid === true} /></span>
        </DomainInsight>
      </div>
      <div className="domain-records">
        <div className="domain-subheading">DNS records</div>
        {["A", "AAAA", "MX", "NS", "TXT", "CNAME"].map((type) => (
          <div className="domain-record-row" key={type}>
            <span>{type}</span>
            <strong>{listValue(records[type])}</strong>
          </div>
        ))}
      </div>
      {anomalies.length > 0 && (
        <div className="domain-anomalies">
          <div className="domain-subheading">Configuration anomalies · {anomalies.length}</div>
          {anomalies.map((anomaly) => <p key={anomaly}>{anomaly}</p>)}
        </div>
      )}
    </section>
  );
}

function DomainInsight({ title, children }: { title: string; children: ReactNode }) {
  return <div className="domain-insight"><span className="domain-subheading">{title}</span>{children}</div>;
}

function AuthStatus({ label, value }: { label: string; value: boolean }) {
  return <><span>{label}</span><strong className={value ? "auth-good" : "auth-missing"}>{value ? "PASS" : "MISSING"}</strong></>;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" || typeof value === "number" ? String(value) : fallback;
}

function listValue(value: unknown): string {
  return Array.isArray(value) && value.length ? value.map(String).join(", ") : "None found";
}

function formatAge(value: unknown): string {
  return typeof value === "number" ? `${value.toLocaleString()} days old` : "Age unavailable";
}

export default App;
