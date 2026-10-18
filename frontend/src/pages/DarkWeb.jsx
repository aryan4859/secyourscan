import React, { useLayoutEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, Crosshair, Radar } from 'lucide-react';
import { api } from '../api';
import { Card, Empty, ErrorBox, Pill, SeverityBadge, Spinner, relTime, useAsync } from '../components/ui';

const RANGES = [7, 30, 90];
// Categorical slots in fixed order (dataviz reference palette, dark steps);
// a channel keeps its colour whichever channels are present.
const CHANNEL_COLOR = {
  'Tor / onion': '#3987e5',
  Telegram: '#d95926',
  'Paste sites': '#199e70',
  Feeds: '#c98500',
  'Code repositories': '#d55181',
  'Breach catalogues': '#9085e9',
  Ingested: '#5c5c64',
};
const ORDER = Object.keys(CHANNEL_COLOR);

export default function DarkWeb() {
  const [days, setDays] = useState(30);
  const dw = useAsync(() => api.darkweb(days), [days]);
  const navigate = useNavigate();
  const d = dw.data;
  const delta = d && d.totals.prev ? Math.round(((d.totals.mentions - d.totals.prev) / d.totals.prev) * 100) : null;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Dark Web</h1>
          <p>Mentions of your assets across Tor sites, Telegram, paste sites and feeds.</p>
        </div>
        <div className="btn-row">
          <div className="seg" role="group" aria-label="Time range">
            {RANGES.map((r) => <button key={r} className={r === days ? 'on' : ''} onClick={() => setDays(r)}>{r}d</button>)}
          </div>
          <Link className="btn" to="/recon"><Crosshair size={14} /> Probe</Link>
        </div>
      </div>

      <ErrorBox error={dw.error} onRetry={dw.reload} />
      {dw.loading && !d && <Spinner />}

      {d && (
        <>
          <div className="kpi-grid five">
            <Stat label="Mentions" value={d.totals.mentions} sub={delta == null ? `last ${days} days` : `${delta >= 0 ? '+' : ''}${delta}% vs previous`} />
            <Stat label="About your assets" value={d.totals.matched} sub="matched the watchlist" tone={d.totals.matched ? 'warn' : ''} />
            <Stat label="Critical" value={d.totals.critical} sub="severity ≥ 80" tone={d.totals.critical ? 'crit' : ''} />
            <Stat label="Sites" value={d.totals.sites} sub="distinct sources" />
            <Stat label="Tor" value={d.tor ? 'On' : 'Off'} sub={d.tor ? 'routed through the pool' : 'set TOR_PROXY'} tone={d.tor ? '' : 'warn'} />
          </div>

          {d.totals.mentions === 0 ? <Onboarding coverage={d.coverage} /> : (
            <>
              <div className="dash-row wide-left">
                <Card title="Activity" actions={<span className="faint small">mentions per day, by channel</span>}>
                  <ChannelChart data={d.daily} channels={d.channels.map((c) => c.channel)} />
                </Card>
                <Card title="Channels">
                  <ul className="ch-list">
                    {d.channels.map((c) => {
                      const diff = c.count - c.prev;
                      return (
                        <li key={c.channel}>
                          <span className="swatch" style={{ background: CHANNEL_COLOR[c.channel] || CHANNEL_COLOR.Ingested }} />
                          <span className="ch-name">{c.channel}</span>
                          <span className="ch-num">{c.count}</span>
                          <span className={`ch-diff ${diff > 0 ? 'up' : ''}`}>{diff > 0 ? `+${diff}` : diff < 0 ? diff : '±0'}</span>
                          <span className="ch-sub">{c.matched} about you{c.critical ? ` · ${c.critical} critical` : ''}</span>
                        </li>
                      );
                    })}
                  </ul>
                </Card>
              </div>

              <div className="dash-row even">
                <Card title="Where it was posted">
                  {d.sites.length === 0 ? <Empty title="No source URLs recorded" /> : (
                    <div className="table-scroll">
                    <table className="table compact">
                      <thead><tr><th>Site</th><th>Channel</th><th>Mentions</th><th>Worst</th><th>Last</th></tr></thead>
                      <tbody>
                        {d.sites.map((s) => (
                          <tr key={s.site}>
                            <td className="mono small site-cell" title={s.site}>{s.site}</td>
                            <td className="small muted nowrap">{s.channel}</td>
                            <td className="mono">{s.count}</td>
                            <td><SeverityBadge value={s.max_severity} /></td>
                            <td className="nowrap faint small">{relTime(s.last_seen)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    </div>
                  )}
                </Card>
                <Card title="Your terms found">
                  {d.terms.length === 0 ? <Empty title="None of your watched terms appeared">Mentions above did not match the watchlist.</Empty> : (
                    <ul className="term-list">
                      {d.terms.map((t) => (
                        <li key={t.term}>
                          <span className="asset-name">{t.term}</span>
                          {t.vip && <Pill tone="vip">VIP</Pill>}
                          <span className="faint small">{t.type}</span>
                          <span className="term-end"><span className="mono">{t.count}×</span> <SeverityBadge value={t.max_severity} /></span>
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
              </div>

              <Card title="Latest" actions={<Link className="link small" to="/leaks">All leaks</Link>}>
                {d.latest.map((l) => (
                  <div key={l.id} className="stream-row" onClick={() => navigate(`/leaks?id=${encodeURIComponent(l.id)}`)}>
                    <SeverityBadge value={l.severity} />
                    <div className="list-main">
                      <div className="list-title">{l.title}</div>
                      <div className="list-sub">
                        <span className="swatch" style={{ background: CHANNEL_COLOR[l.channel] || CHANNEL_COLOR.Ingested }} /> {l.channel} · {relTime(l.discovered_at)}
                        {l.matches.map((m) => <Pill key={m}>{m}</Pill>)}
                      </div>
                    </div>
                  </div>
                ))}
              </Card>

              <Coverage coverage={d.coverage} />
            </>
          )}
        </>
      )}
    </div>
  );
}

function Stat({ label, value, sub, tone = '' }) {
  return (
    <div className={`kpi ${tone ? `kpi-${tone}` : ''}`}>
      <div className="kpi-head"><span>{label}</span></div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

function Coverage({ coverage }) {
  return (
    <Card title="Collection" actions={<Link className="link small" to="/sources">Manage sources</Link>}>
      {coverage.length === 0 ? <p className="small muted">No scheduled sources yet: probes are the only collection running.</p> : (
        <div className="cov-grid">
          {coverage.map((c) => (
            <div key={c.channel} className="cov">
              <span className="swatch" style={{ background: CHANNEL_COLOR[c.channel] || CHANNEL_COLOR.Ingested }} />
              <div>
                <div className="small">{c.channel}</div>
                <div className="faint small">{c.active}/{c.sources} active · {c.last_run ? `ran ${relTime(c.last_run)}` : 'not run yet'}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function Onboarding({ coverage }) {
  const steps = [
    { done: false, title: 'Add what to look for', text: 'Domains, executive mailboxes, brand and project names.', to: '/watchlist', cta: 'Watchlist' },
    { done: coverage.length > 0, title: 'Schedule collection', text: 'Ahmia searches over Tor, onion sites, Telegram channels and feeds.', to: '/sources', cta: 'Sources' },
    { done: false, title: 'Or probe right now', text: 'One-off dark-web, Telegram or Shodan lookups.', to: '/recon', cta: 'Probes' },
  ];
  return (
    <section className="onboard">
      <Radar size={22} className="onboard-icon" />
      <h2>Nothing collected in this window yet</h2>
      <p className="muted small">Mentions appear here as soon as collectors find material that names your assets.</p>
      <ol className="onboard-steps">
        {steps.map((s, i) => (
          <li key={s.title}>
            <span className={`step-n ${s.done ? 'done' : ''}`}>{s.done ? '✓' : i + 1}</span>
            <div><div className="step-title">{s.title}</div><div className="faint small">{s.text}</div></div>
            <Link className="btn btn-sm" to={s.to}>{s.cta} <ArrowRight size={13} /></Link>
          </li>
        ))}
      </ol>
    </section>
  );
}

function ChannelChart({ data, channels }) {
  const ref = useRef(null);
  const [w, setW] = useState(0);
  const [hover, setHover] = useState(null);
  useLayoutEffect(() => {
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)));
    if (ref.current) ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  const order = ORDER.filter((c) => channels.includes(c)).concat(channels.filter((c) => !ORDER.includes(c)));
  const totals = data.map((d) => order.reduce((s, c) => s + (d[c] || 0), 0));
  const peak = Math.max(...totals, 1);
  const H = 170;
  const padB = 20;
  const plotH = H - padB;
  const step = w / Math.max(data.length, 1);
  const bw = Math.max(Math.min(step - 2, 18), 1);
  return (
    <div className="chart" ref={ref}>
      {w > 0 && (
        <svg width={w} height={H} role="img" aria-label={`Mentions per day, peak ${peak}`} onMouseLeave={() => setHover(null)}>
          <line x1="0" x2={w} y1={plotH} y2={plotH} stroke="var(--grid)" />
          {data.map((d, i) => {
            let acc = 0;
            const segs = order.filter((c) => d[c]);
            return (
              <g key={d.day}>
                {hover === i && <rect className="col-hover" x={i * step} y={0} width={step} height={plotH} />}
                {segs.map((c, si) => {
                  const h = (d[c] / peak) * (plotH - 8);
                  const y = plotH - acc - h;
                  acc += h;
                  return <rect key={c} x={i * step + (step - bw) / 2} y={y} width={bw} height={Math.max(h - (si < segs.length - 1 ? 2 : 0), 1)} rx="2" fill={CHANNEL_COLOR[c] || CHANNEL_COLOR.Ingested} />;
                })}
                <rect className="hit" x={i * step} y={0} width={step} height={plotH} onMouseEnter={() => setHover(i)} />
              </g>
            );
          })}
          <text className="tick" x="0" y={H - 4}>{data[0]?.day.slice(5)}</text>
          <text className="tick" x={w} y={H - 4} textAnchor="end">{data[data.length - 1]?.day.slice(5)}</text>
        </svg>
      )}
      {hover != null && data[hover] && (
        <div className="tip" style={{ left: Math.min(hover * step + step + 8, Math.max(w - 170, 0)), top: 6 }}>
          <div className="tip-title">{data[hover].day} · {totals[hover]} mentions</div>
          {order.filter((c) => data[hover][c]).map((c) => (
            <div key={c} className="tip-row"><span className="swatch" style={{ background: CHANNEL_COLOR[c] }} /> <span>{c}</span> <b>{data[hover][c]}</b></div>
          ))}
        </div>
      )}
      <div className="legend">{order.map((c) => <span key={c}><span className="swatch" style={{ background: CHANNEL_COLOR[c] || CHANNEL_COLOR.Ingested }} /> {c}</span>)}</div>
    </div>
  );
}
