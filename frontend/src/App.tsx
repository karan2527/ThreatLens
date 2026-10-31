import { useState } from "react";
import {
  ArrowUpRight,
  BarChart3,
  ChevronDown,
  CircleHelp,
  Fingerprint,
  LayoutDashboard,
  Menu,
  ShieldCheck,
  X,
} from "lucide-react";

import "./styles.css";

const navigation = [
  { label: "Scanner", href: "#scanner", icon: Fingerprint },
  { label: "Dashboard", href: "#dashboard", icon: LayoutDashboard },
  { label: "History", href: "#history", icon: BarChart3 },
];

function App() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#scanner" aria-label="ThreatLens home">
          <span className="brand-mark" aria-hidden="true">
            <ShieldCheck size={19} strokeWidth={2.5} />
          </span>
          <span>ThreatLens</span>
        </a>

        <button
          className="mobile-menu-button"
          type="button"
          aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={mobileOpen}
          onClick={() => setMobileOpen((open) => !open)}
        >
          {mobileOpen ? <X size={21} /> : <Menu size={21} />}
        </button>

        <nav className={`main-nav ${mobileOpen ? "main-nav-open" : ""}`}>
          {navigation.map(({ label, href, icon: Icon }) => (
            <a key={label} href={href} onClick={() => setMobileOpen(false)}>
              <Icon size={16} aria-hidden="true" />
              {label}
            </a>
          ))}
          <a className="nav-help" href="#about" onClick={() => setMobileOpen(false)}>
            <CircleHelp size={16} aria-hidden="true" />
            About
          </a>
        </nav>

        <button className="session-button" type="button">
          <span className="status-dot" aria-hidden="true" />
          Local session
          <ChevronDown size={15} aria-hidden="true" />
        </button>
      </header>

      <main>
        <section className="hero-section" id="scanner">
          <div className="hero-copy">
            <p className="eyebrow">
              <span className="eyebrow-line" aria-hidden="true" />
              Threat intelligence, made clear
            </p>
            <h1>
              See the signal
              <br />
              <em>behind the threat.</em>
            </h1>
            <p className="hero-description">
              Investigate URLs, domains, IPs, and file hashes with a focused
              intelligence report built from trusted security sources.
            </p>
            <div className="hero-actions">
              <a className="button button-primary" href="#scanner-form">
                Start an investigation
                <ArrowUpRight size={17} aria-hidden="true" />
              </a>
              <a className="text-link" href="#about">
                How it works
                <ArrowUpRight size={15} aria-hidden="true" />
              </a>
            </div>
          </div>

          <div className="hero-aside" aria-label="ThreatLens overview">
            <div className="signal-card">
              <div className="signal-card-header">
                <span className="signal-label">Risk intelligence</span>
                <span className="live-badge">
                  <span className="status-dot" aria-hidden="true" />
                  Ready
                </span>
              </div>
              <div className="signal-score">—</div>
              <div className="signal-score-label">Awaiting your first scan</div>
              <div className="score-track">
                <span />
              </div>
              <div className="score-scale">
                <span>LOW</span>
                <span>MEDIUM</span>
                <span>HIGH</span>
                <span>CRITICAL</span>
              </div>
            </div>
            <div className="hero-note">
              <span className="note-number">01</span>
              <p>One calm view across multiple threat intelligence providers.</p>
            </div>
          </div>
        </section>

        <section className="scanner-panel" id="scanner-form">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Investigation workspace</p>
              <h2>Start with an indicator</h2>
            </div>
            <span className="panel-step">01 / 03</span>
          </div>
          <div className="scan-input-shell">
            <div className="input-prefix">
              <Fingerprint size={19} aria-hidden="true" />
            </div>
            <input
              aria-label="Indicator to investigate"
              placeholder="Paste a URL, domain, IP address, or file hash"
              type="text"
            />
            <button className="button button-dark" type="button">
              Investigate
              <ArrowUpRight size={17} aria-hidden="true" />
            </button>
          </div>
          <div className="input-hints">
            <span>Supported indicators</span>
            <span>URL&nbsp;&nbsp; / &nbsp;&nbsp;DOMAIN&nbsp;&nbsp; / &nbsp;&nbsp;IP&nbsp;&nbsp; / &nbsp;&nbsp;HASH</span>
          </div>
        </section>

        <section className="feature-grid" id="about">
          <article>
            <span className="feature-index">01</span>
            <h3>One clear signal</h3>
            <p>Turn scattered provider results into a measured risk score and useful next action.</p>
          </article>
          <article>
            <span className="feature-index">02</span>
            <h3>Context, not noise</h3>
            <p>See why a result matters with transparent evidence, coverage, and provider detail.</p>
          </article>
          <article>
            <span className="feature-index">03</span>
            <h3>Built for careful work</h3>
            <p>Investigate safely without opening suspicious URLs or exposing your indicator to the browser.</p>
          </article>
        </section>
      </main>

      <footer className="site-footer">
        <span>ThreatLens <span className="footer-muted">/ Threat intelligence workspace</span></span>
        <span className="footer-muted">Private by default · Local session</span>
      </footer>
    </div>
  );
}

export default App;
