import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle, ArrowRight, CheckCircle2, Globe2, Loader2, Radar, Send, Server, ShieldAlert, XCircle,
} from 'lucide-react';
import { api } from '../api';
import {
  CopyButton, Empty, ErrorBox, JsonView, KV, Pill, Spinner, fmtDate, relTime, useAsync, useToast,
} from '../components/ui';

const MODES = {
  darkweb: {
    label: 'Dark web', icon: Globe2, kind: 'ahmia', placeholder: 'acme.example.com, "project falcon", ceo@acme.example.com',
    hint: 'Searches Ahmia through the Tor pool. Letters, digits, @ . - + " \' and spaces, 2–128 characters.',
    valid: (v) => v.length >= 2 && v.length <= 128,
  },
  telegram: {
    label: 'Telegram', icon: Send, kind: 'telegram', placeholder: 'public channel name, e.g. durov',
    hint: 'Reads the last 30 messages of a public channel from its web preview (t.me/s/…). Clearnet, no account needed.',
    valid: (v) => /^@?[A-Za-z0-9_]{4,64}$/.test(v),
  },
  shodan: {
    label: 'Shodan', icon: Server, placeholder: '203.0.113.10 (one of your public IPs)',
    hint: 'Open ports, CVEs and hostnames from Shodan InternetDB. Public IPv4 only; answered immediately.',
    valid: (v) => /^(\d{1,3}\.){3}\d{1,3}$/.test(v),
  },
};

export default function Recon() {
  const [mode, setMode] = useState('darkweb');
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [runId, setRunId] = useState(null);
  const [shodan, setShodan] = useState(null);
  const history = useAsync(() => api.runs({ adhoc: true, kind: ['ahmia', 'telegram'], limit: 15 }), []);
  const health = useAsync(() => api.health(), []);
  const toast = useToast();
  const m = MODES[mode];
  const tor = health.data?.components?.tor;

  const probe = async (e) => {
    e.preventDefault();
    const raw = value.trim();
    const v = mode === 'telegram' ? raw.replace(/^@/, '') : raw;
    if (!m.valid(raw)) {
      setErr(m.hint);
      return;
    }
    setBusy(true);
    setErr(null);
    setShodan(null);
    try {
      if (mode === 'shodan') {
        setRunId(null);
        setShodan(await api.reconShodan(v));
      } else {
        const r = await (mode === 'darkweb' ? api.reconDarkweb(v) : api.reconTelegram(v));
        setRunId(r.run_id);
        toast(`${m.label} probe queued`, 'ok');
      }
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Dark Recon</h1>
          <p className="muted">One-off probes. Findings go through the same pipeline as every scheduled source: scored, matched against your assets, and alerted.</p>
        </div>
        {health.data && (
          <span className={`status-pill ${tor === 'configured' ? '' : 'warn'}`} title="Dark-web probes route through the Tor pool when TOR_PROXY is set">
            <span className={`dot ${tor === 'configured' ? 'dot-ok' : 'dot-bad'}`} />
            {tor === 'configured' ? 'Tor pool configured' : 'Tor not configured: Ahmia goes over clearnet'}
          </span>
        )}
      </div>

      <section className="recon-hero">
        <div className="recon-mark"><Radar size={26} /></div>
        <h2 className="recon-title">What should we look for?</h2>
        <div className="seg recon-modes" role="tablist" aria-label="Probe type">
          {Object.entries(MODES).map(([k, x]) => (
            <button key={k} role="tab" aria-selected={k === mode} className={k === mode ? 'on' : ''}
              onClick={() => { setMode(k); setErr(null); }}>
              <x.icon size={13} /> {x.label}
            </button>
          ))}
        </div>
        <form className="recon-form" onSubmit={probe}>
          <input className="input recon-input" value={value} onChange={(e) => setValue(e.target.value)} placeholder={m.placeholder}
            aria-label={`${m.label} probe target`} autoFocus />
          <button className="btn btn-primary recon-go" disabled={busy || !value.trim()}>
            {busy ? <Loader2 size={15} className="spin" /> : <>Probe <ArrowRight size={15} /></>}
          </button>
        </form>
        <p className="recon-hint">{m.hint}</p>
        <ErrorBox error={err} />
        <p className="fineprint">Probe only for your own organisation's assets. Every probe is written to the audit log.</p>
      </section>

      {runId && <RunCard key={runId} id={runId} onDone={history.reload} />}
      {shodan && <ShodanCard data={shodan} />}

      <section className="card">
        <header className="card-head"><h2>Probe history</h2></header>
        <div className="card-body">
          <ErrorBox error={history.error} onRetry={history.reload} />
          {history.loading && !history.data && <Spinner />}
          {history.data?.length === 0 && <Empty title="No probes yet">Dark-web and Telegram probes you run appear here.</Empty>}
          {history.data?.length > 0 && (
            <div className="table-wrap" style={{ border: 0 }}>
              <table className="table">
                <thead><tr><th>Probe</th><th>Query</th><th>Status</th><th>Results</th><th>New leaks</th><th>Route</th><th>When</th></tr></thead>
                <tbody>
                  {history.data.map((r) => (
                    <tr key={r.id} className={`clickable ${r.id === runId ? 'row-on' : ''}`} onClick={() => { setShodan(null); setRunId(r.id); }}>
                      <td><Pill>{r.kind === 'ahmia' ? 'dark web' : r.kind}</Pill></td>
                      <td className="mono-wrap">{r.query}</td>
                      <td><RunStatus status={r.status} /></td>
                      <td className="mono">{r.results}</td>
                      <td className="mono">{r.new_leaks}</td>
                      <td>{r.kind === 'ahmia' ? (r.via_tor ? <Pill tone="ok">Tor</Pill> : <Pill tone="warn">clearnet</Pill>) : <Pill>clearnet</Pill>}</td>
                      <td className="nowrap muted" title={fmtDate(r.started_at)}>{relTime(r.started_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function RunStatus({ status }) {
  if (status === 'ok') return <span className="chain-ok"><CheckCircle2 size={13} /> done</span>;
  if (status === 'error') return <span className="chain-bad"><XCircle size={13} /> failed</span>;
  return <span className="warn-text"><Loader2 size={13} className="spin" /> running</span>;
}

/** Polls one run every 2 s until it finishes, then shows what came back. */
function RunCard({ id, onDone }) {
  const [run, setRun] = useState(null);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const navigate = useNavigate();
  const started = useRef(Date.now());

  useEffect(() => {
    let alive = true;
    let timer;
    const poll = async () => {
      try {
        const r = await api.run(id);
        if (!alive) return;
        setRun(r);
        setError(null);
        if (r.status === 'running') timer = setTimeout(poll, 2000);
        else onDone?.();
      } catch (e) {
        if (alive) setError(e);
      }
    };
    poll();
    const tick = setInterval(() => setElapsed(Math.round((Date.now() - started.current) / 1000)), 1000);
    return () => { alive = false; clearTimeout(timer); clearInterval(tick); };
  }, [id, onDone]);

  const results = run?.report?.results || [];
  return (
    <section className="card">
      <header className="card-head">
        <h2>{run ? `${run.kind === 'ahmia' ? 'Dark-web' : 'Telegram'} probe · ${run.query}` : 'Probe'}</h2>
        {run && <RunStatus status={run.status} />}
      </header>
      <div className="card-body stack">
        <ErrorBox error={error} />
        {!run && !error && <Spinner />}
        {run?.status === 'running' && (
          <div className="recon-running">
            <Loader2 size={16} className="spin" />
            <span>Querying {run.kind === 'ahmia' ? (run.via_tor ? 'Ahmia through the Tor pool' : 'Ahmia') : 't.me'}… {elapsed}s</span>
            <span className="faint small">Tor circuits are slow; a minute or two is normal.</span>
          </div>
        )}
        {run && run.status !== 'running' && (
          <>
            <div className="mini-stats" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', marginTop: 0 }}>
              <div className="mini-stat"><div className="lbl">Results</div><div className="val">{run.results}</div></div>
              <div className="mini-stat"><div className="lbl">New leaks</div><div className="val">{run.new_leaks}</div></div>
              <div className="mini-stat"><div className="lbl">Route</div><div className="val small-val">{run.kind === 'ahmia' ? (run.via_tor ? 'Tor' : 'Clearnet') : 'Clearnet'}</div></div>
              <div className="mini-stat"><div className="lbl">Finished</div><div className="val small-val">{relTime(run.finished_at)}</div></div>
            </div>
            {run.status === 'error' && (
              <div className="warn-box"><AlertTriangle size={16} /><div><b>The probe failed.</b><div className="small">{run.error}</div></div></div>
            )}
            {run.kind === 'ahmia' && !run.via_tor && run.status === 'ok' && (
              <div className="warn-box"><ShieldAlert size={16} /><div className="small">This query went to Ahmia over the clearnet, not Tor.</div></div>
            )}
            {run.new_leaks > 0 && (
              <button className="btn btn-sm" onClick={() => navigate(`/leaks?source=${run.kind}`)}>
                View {run.new_leaks} new leak{run.new_leaks === 1 ? '' : 's'} <ArrowRight size={13} />
              </button>
            )}
            {run.kind === 'ahmia' && run.status === 'ok' && (results.length === 0 ? (
              <Empty title="Ahmia returned nothing for this query" />
            ) : (
              <ul className="onion-list">
                {results.map((r, i) => (
                  <li key={`${r.url}-${i}`}>
                    <div className="onion-title">{r.title}</div>
                    <div className="onion-url"><code>{r.url}</code> <CopyButton text={r.url} label="Copy" /></div>
                    {r.description && <div className="onion-desc">{r.description}</div>}
                  </li>
                ))}
              </ul>
            ))}
            {run.kind === 'telegram' && run.status === 'ok' && run.results === 0 && (
              <Empty title="No public messages">The channel may not exist, be private, or have its web preview disabled.</Empty>
            )}
          </>
        )}
      </div>
    </section>
  );
}

function ShodanCard({ data }) {
  return (
    <section className="card">
      <header className="card-head"><h2>Shodan exposure · {data.ip}</h2></header>
      <div className="card-body">
        {data.found === false ? (
          <Empty title={`${data.ip} is not in Shodan InternetDB`}>No open ports or CVEs are recorded for this address.</Empty>
        ) : (
          <div className="stack">
            <div className="mini-stats" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', marginTop: 0 }}>
              <div className="mini-stat"><div className="lbl">Open ports</div><div className="val">{data.ports?.length || 0}</div></div>
              <div className="mini-stat"><div className="lbl">Known CVEs</div><div className="val" style={{ color: data.vulns?.length ? 'var(--crit)' : undefined }}>{data.vulns?.length || 0}</div></div>
              <div className="mini-stat"><div className="lbl">Hostnames</div><div className="val">{data.hostnames?.length || 0}</div></div>
            </div>
            {data.ports?.length > 0 && <div className="tags">{data.ports.map((p) => <Pill key={p}>{p}</Pill>)}</div>}
            {data.vulns?.length > 0 && <div className="tags">{data.vulns.map((v) => <Pill key={v} tone="critical">{v}</Pill>)}</div>}
            <KV rows={[
              ['Hostnames', data.hostnames?.join(', ') || '—'],
              ['Tags', data.tags?.join(', ') || '—'],
              ['CPEs', data.cpes?.length ? data.cpes.join(', ') : '—'],
            ]} />
            <JsonView title="raw response" data={data} />
          </div>
        )}
      </div>
    </section>
  );
}
