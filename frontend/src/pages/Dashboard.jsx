import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import {
  AlertOctagon, ArrowDownRight, ArrowUpRight, Bug, CheckCircle2, Clock, Crown, Fish, Globe, LockOpen, Minus,
  RefreshCw, ShieldAlert, Skull, Target, TrendingUp, TriangleAlert,
} from 'lucide-react';
import { api } from '../api';
import {
  Card, Empty, ErrorBox, Pill, SeverityBadge, Spinner, relTime, useAsync,
} from '../components/ui';

// Severity is ordered, so charts use one red ramp (validated for the dark
// surface) instead of four hues; the brightest step is the most severe.
const BANDS = ['critical', 'high', 'medium', 'low'];
const BAND_COLOR = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)' };
const BAND_MIN = { critical: 80, high: 60, medium: 30, low: 0 };
const RANGES = [7, 30, 90];

export default function Dashboard() {
  const [days, setDays] = useState(30);
  const ins = useAsync(() => api.insights(days), [days]);
  const stream = useAsync(() => api.leaks({ min_severity: 80, limit: 6 }), []);
  const ext = useAsync(() => api.intelSummary(), []);
  const navigate = useNavigate();

  useEffect(() => {
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') [ins, stream, ext].forEach((x) => x.reload());
    }, 60_000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ins.reload, stream.reload, ext.reload]);

  const d = ins.data;
  const k = d?.kpis;
  const loading = ins.loading && !d;
  const daily = d?.daily || [];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p>Leaks and external exposure for your organisation over the last {days} days.</p>
        </div>
        <div className="btn-row">
          <div className="seg" role="group" aria-label="Time range">
            {RANGES.map((r) => <button key={r} className={r === days ? 'on' : ''} onClick={() => setDays(r)}>{r}d</button>)}
          </div>
          <button className="icon-btn" onClick={() => [ins, stream, ext].forEach((x) => x.reload())} aria-label="Refresh" title="Refresh"><RefreshCw size={15} /></button>
        </div>
      </div>

      <ErrorBox error={ins.error} onRetry={ins.reload} />
      {k && k.exposed_assets.watched === 0 ? (
        <GettingStarted ext={ext.data} />
      ) : d && <Callouts items={[...externalCallouts(ext.data), ...d.callouts]} navigate={navigate} />}

      <div className="kpi-grid" style={{ opacity: ins.loading && d ? 0.6 : 1 }}>
        <Kpi label="New leaks" icon={ShieldAlert} loading={loading} value={k?.leaks.value} prev={k?.leaks.prev} upIsBad
          sub={`last ${days} days`} spark={daily.map((x) => BANDS.reduce((s, b) => s + x[b], 0))} sparkColor="var(--series-1)"
          onClick={() => navigate('/leaks')} />
        <Kpi label="Critical" icon={AlertOctagon} loading={loading} value={k?.critical.value} prev={k?.critical.prev} upIsBad
          sub="severity ≥ 80" spark={daily.map((x) => x.critical)} sparkColor="var(--sev-critical)"
          onClick={() => navigate('/leaks?min=80')} />
        <Kpi label="Exposed assets" icon={Target} loading={loading} value={k?.exposed_assets.value} prev={k?.exposed_assets.prev} upIsBad
          sub={k ? `of ${k.exposed_assets.watched} watched` : ''} onClick={() => navigate('/assets')} />
        <Kpi label="Awaiting triage" icon={Clock} loading={loading} value={k?.awaiting_triage.value}
          sub={k ? (k.mtta_hours != null ? `median ack ${fmtHours(k.mtta_hours)}` : 'critical, unacknowledged') : ''}
          onClick={() => navigate('/leaks?min=80')} />
      </div>

      {ext.data && <ExternalRisk s={ext.data} navigate={navigate} />}

      <div className="dash-row wide-left">
        <Card title="Discoveries" actions={<span className="faint small">per day, by severity</span>}>
          {loading ? <Spinner /> : d && <TrendChart data={daily} />}
        </Card>
        <Card title="Severity">
          {loading ? <Spinner /> : d && <SeverityDonut data={d.severity} onPick={(b) => navigate(`/leaks?min=${BAND_MIN[b]}`)} />}
        </Card>
      </div>

      <div className="dash-row even">
        <Card title="Most exposed assets" actions={<Link className="link small" to="/assets">All</Link>}>
          {loading ? <Spinner /> : d && <AssetTable rows={d.top_assets.slice(0, 6)} navigate={navigate} />}
        </Card>
        <Card title="Critical leaks" actions={<Link className="link small" to="/leaks?min=80">All</Link>}>
          <ErrorBox error={stream.error} onRetry={stream.reload} />
          {stream.loading && !stream.data && <Spinner />}
          {stream.data?.items.length === 0 && <Empty title="Nothing critical">No leak at severity 80 or above.</Empty>}
          {stream.data?.items.map((l) => (
            <div key={l.id} className="stream-row" onClick={() => navigate(`/leaks?id=${encodeURIComponent(l.id)}`)}>
              <SeverityBadge value={l.severity} />
              <div className="list-main">
                <div className="list-title">{l.title || l.snippet?.slice(0, 110) || l.id}</div>
                <div className="list-sub">{l.source} · {relTime(l.discovered_at)}</div>
              </div>
              {!l.acknowledged_at && <Pill tone="critical">new</Pill>}
            </div>
          ))}
        </Card>
      </div>
      {d?.truncated && <p className="fineprint">Figures cover the most recent 20,000 leaks in this window.</p>}
    </div>
  );
}

// ── Pieces ───────────────────────────────────────────────────────────────────

/** First-run checklist, ticked from real state, shown until something is watched. */
function GettingStarted({ ext }) {
  const doms = useAsync(() => api.domains(), []);
  const srcs = useAsync(() => api.sources(), []);
  const verified = (doms.data?.items || []).some((x) => x.verified) || doms.data?.required === false;
  const scanned = ext?.scans?.surface?.status === 'ok' && ext.surface.hosts > 0;
  const steps = [
    { done: verified, title: 'Verify your domain', text: 'Publish one DNS TXT record to prove ownership.', to: '/domains', cta: 'Domains' },
    { done: false, title: 'Add what to watch', text: 'Domains, executive mailboxes, brand names, public IPs.', to: '/watchlist', cta: 'Watchlist' },
    { done: (srcs.data || []).length > 0, title: 'Schedule dark-web collection', text: 'Tor search, onion sites, Telegram channels, feeds.', to: '/sources', cta: 'Sources' },
    { done: !!scanned, title: 'Map your attack surface', text: 'Hosts, ports, TLS, DNS, lookalikes and ransomware sites.', to: '/surface', cta: 'Scan' },
  ];
  const n = steps.filter((x) => x.done).length;
  return (
    <section className="onboard left">
      <div className="onboard-head">
        <div>
          <h2>Set up monitoring</h2>
          <p className="faint small">{n} of {steps.length} done · about ten minutes</p>
        </div>
        <div className="onboard-bar"><span style={{ width: `${(n / steps.length) * 100}%` }} /></div>
      </div>
      <ol className="onboard-steps">
        {steps.map((st, i) => (
          <li key={st.title} className={st.done ? 'is-done' : ''}>
            <span className={`step-n ${st.done ? 'done' : ''}`}>{st.done ? '✓' : i + 1}</span>
            <div><div className="step-title">{st.title}</div><div className="faint small">{st.text}</div></div>
            {!st.done && <Link className="btn btn-sm" to={st.to}>{st.cta} <ArrowRight size={13} /></Link>}
          </li>
        ))}
      </ol>
    </section>
  );
}

function fmtHours(h) {
  if (h < 1) return `${Math.round(h * 60)}m`;
  if (h < 48) return `${h.toFixed(h < 10 ? 1 : 0)}h`;
  return `${Math.round(h / 24)}d`;
}

const CALLOUT = {
  source_surge: { tone: 'c-warn', icon: TrendingUp, kind: 'Source surge',
    text: (c) => `${c.source} ${c.prev ? `+${Math.round(((c.count - c.prev) / c.prev) * 100)}%` : `${c.count} new`} vs prior period`,
    to: (c) => `/leaks?source=${encodeURIComponent(c.source)}` },
  stale_critical: { tone: 'c-crit', icon: AlertOctagon, kind: 'Stale critical',
    text: (c) => `${c.count} unacked > ${c.hours}h`, to: () => '/leaks?min=80' },
  vip_at_risk: { tone: 'c-vip', icon: Crown, kind: 'VIP at risk',
    text: (c) => `${c.count} VIP asset${c.count === 1 ? '' : 's'} exposed ≥ ${c.threshold}`, to: () => '/assets' },
  collector_errors: { tone: 'c-warn', icon: TriangleAlert, kind: 'Collector errors',
    text: (c) => `${c.count} failed run${c.count === 1 ? '' : 's'}`, to: () => '/sources' },
  ransomware_mention: { tone: 'c-crit', icon: Skull, kind: 'Ransomware mention',
    text: (c) => `Named on ${c.count} leak-site post${c.count === 1 ? '' : 's'}`, to: () => '/ransomware' },
  kev_exposure: { tone: 'c-crit', icon: Bug, kind: 'Exploited CVEs',
    text: (c) => `${c.count} KEV finding${c.count === 1 ? '' : 's'} on your hosts`, to: () => '/vulns' },
  lookalikes: { tone: 'c-warn', icon: Fish, kind: 'Lookalike domains',
    text: (c) => `${c.count} high-risk lookalike${c.count === 1 ? '' : 's'}`, to: () => '/brand' },
  certs_expiring: { tone: 'c-warn', icon: LockOpen, kind: 'Certificates',
    text: (c) => `${c.count} expire${c.count === 1 ? 's' : ''} within 30 days`, to: () => '/surface' },
};

function externalCallouts(s) {
  if (!s) return [];
  return [
    s.ransomware.new && { kind: 'ransomware_mention', count: s.ransomware.new },
    s.vulns.kev && { kind: 'kev_exposure', count: s.vulns.kev },
    s.brand.high_risk && { kind: 'lookalikes', count: s.brand.high_risk },
    s.surface.expiring_certs && { kind: 'certs_expiring', count: s.surface.expiring_certs },
  ].filter(Boolean);
}

function ExternalRisk({ s, navigate }) {
  const last = Object.values(s.scans).map((x) => x.finished_at).filter(Boolean).sort().pop();
  const tiles = [
    { to: '/surface', icon: Globe, label: 'Attack surface', value: s.surface.hosts,
      sub: `${s.surface.live} live · ${s.surface.new_7d} new this week`, tone: s.surface.new_7d ? 'warn' : '' },
    { to: '/vulns', icon: Bug, label: 'Exploitable CVEs', value: s.vulns.kev,
      sub: `${s.vulns.open} open · ${s.vulns.by_priority.high} high EPSS`, tone: s.vulns.kev ? 'crit' : '' },
    { to: '/brand', icon: Fish, label: 'Lookalike domains', value: s.brand.high_risk,
      sub: `high risk · ${s.brand.lookalikes} registered`, tone: s.brand.high_risk ? 'warn' : '' },
    { to: '/ransomware', icon: Skull, label: 'Ransomware mentions', value: s.ransomware.hits,
      sub: s.ransomware.new ? `${s.ransomware.new} unacknowledged` : 'on leak sites', tone: s.ransomware.new ? 'crit' : '' },
  ];
  return (
    <section className="ext-risk">
      <div className="ext-head"><h2>External risk</h2><span className="faint small">{last ? `last scan ${relTime(last)}` : 'not scanned yet: open a module and run a scan'}</span></div>
      <div className="kpi-grid">
        {tiles.map((t) => (
          <div key={t.to} className={`kpi clickable ${t.tone ? `kpi-${t.tone}` : ''}`} onClick={() => navigate(t.to)}>
            <div className="kpi-head"><span>{t.label}</span> <t.icon size={16} /></div>
            <div className="kpi-value">{t.value}</div>
            <div className="kpi-sub">{t.sub}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function Callouts({ items, navigate }) {
  if (!items.length) {
    return (
      <div className="callouts">
        <div className="callout c-ok">
          <span className="callout-icon"><CheckCircle2 size={15} /></span>
          <span><div className="callout-kind">All clear</div><div className="callout-text">Nothing needs attention right now</div></span>
        </div>
      </div>
    );
  }
  return (
    <div className="callouts">
      {items.map((c) => {
        const m = CALLOUT[c.kind];
        if (!m) return null;
        return (
          <button key={c.kind} className={`callout ${m.tone}`} onClick={() => navigate(m.to(c))}>
            <span className="callout-icon"><m.icon size={15} /></span>
            <span><div className="callout-kind">{m.kind}</div><div className="callout-text">{m.text(c)}</div></span>
          </button>
        );
      })}
    </div>
  );
}

function Delta({ value, prev, upIsBad }) {
  if (value == null || prev == null) return null;
  if (prev === 0 && value === 0) return <span className="delta"><Minus size={11} /> 0</span>;
  if (prev === 0) return <span className={`delta ${upIsBad ? 'up-bad' : ''}`}><ArrowUpRight size={11} /> new</span>;
  const pct = Math.round(((value - prev) / prev) * 100);
  if (pct === 0) return <span className="delta"><Minus size={11} /> 0%</span>;
  const up = pct > 0;
  const cls = upIsBad ? (up ? 'up-bad' : 'down-good') : '';
  return (
    <span className={`delta ${cls}`} title={`Previous period: ${prev}`}>
      {up ? <ArrowUpRight size={11} /> : <ArrowDownRight size={11} />} {Math.abs(pct)}%
    </span>
  );
}

function Kpi({ label, icon: Icon, value, prev, upIsBad, sub, spark, sparkColor, loading, onClick }) {
  return (
    <div className={`kpi ${onClick ? 'clickable' : ''}`} onClick={onClick}>
      <div className="kpi-head"><span>{label}</span> <Icon size={16} /></div>
      <div className="kpi-row">
        <div>
          <span className="kpi-value">{loading ? '…' : value ?? '—'}</span>
          {!loading && <Delta value={value} prev={prev} upIsBad={upIsBad} />}
        </div>
        {spark && spark.length > 1 && <Sparkline data={spark} color={sparkColor} />}
      </div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

function Sparkline({ data, color }) {
  const W = 96;
  const H = 32;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => [(i / (data.length - 1)) * W, H - 2 - (v / max) * (H - 4)]);
  return (
    <svg className="spark" viewBox={`0 0 ${W} ${H}`} aria-hidden="true">
      <path d={pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join('')} style={{ stroke: color }} />
    </svg>
  );
}

function useWidth() {
  const ref = useRef(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    if (!ref.current) return undefined;
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

function SeverityDonut({ data, onPick }) {
  const [hover, setHover] = useState(null);
  const total = BANDS.reduce((s, b) => s + (data[b] || 0), 0);
  if (!total) return <Empty title="No leaks in this window" />;
  const R = 62;
  const r = 46;
  const C = 75;
  const gap = 0.025; // radians of surface between segments
  let a0 = -Math.PI / 2;
  const arcs = BANDS.filter((b) => data[b]).map((b) => {
    const span = (data[b] / total) * Math.PI * 2;
    const seg = { b, a0: a0 + (span > gap * 2 ? gap / 2 : 0), a1: a0 + span - (span > gap * 2 ? gap / 2 : 0) };
    a0 += span;
    return seg;
  });
  const arcPath = ({ a0: s, a1: e }) => {
    const large = e - s > Math.PI ? 1 : 0;
    const p = (rad, a) => `${(C + rad * Math.cos(a)).toFixed(2)},${(C + rad * Math.sin(a)).toFixed(2)}`;
    if (e - s >= Math.PI * 2 - 0.001) {
      return `M${p(R, s)}A${R},${R} 0 1 1 ${p(R, s + Math.PI)}A${R},${R} 0 1 1 ${p(R, s)}M${p(r, s)}A${r},${r} 0 1 0 ${p(r, s + Math.PI)}A${r},${r} 0 1 0 ${p(r, s)}Z`;
    }
    return `M${p(R, s)}A${R},${R} 0 ${large} 1 ${p(R, e)}L${p(r, e)}A${r},${r} 0 ${large} 0 ${p(r, s)}Z`;
  };
  const shown = hover ? data[hover] : total;
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 150 150" width="150" height="150" role="img" aria-label="Leaks by severity band">
        {arcs.map((a) => (
          <path key={a.b} d={arcPath(a)} fill={BAND_COLOR[a.b]} opacity={hover && hover !== a.b ? 0.35 : 1}
            onMouseEnter={() => setHover(a.b)} onMouseLeave={() => setHover(null)} onClick={() => onPick(a.b)} style={{ cursor: 'pointer' }}>
            <title>{`${a.b}: ${data[a.b]}`}</title>
          </path>
        ))}
        <text x={C} y={C + 4} textAnchor="middle" className="donut-center">{shown}</text>
        <text x={C} y={C + 20} textAnchor="middle" className="donut-label">{hover || 'leaks'}</text>
      </svg>
      <ul className="donut-legend">
        {BANDS.map((b) => (
          <li key={b} className="clickable" onClick={() => onPick(b)} onMouseEnter={() => setHover(b)} onMouseLeave={() => setHover(null)}>
            <span className="swatch" style={{ background: BAND_COLOR[b] }} />
            <span style={{ textTransform: 'capitalize' }}>{b}</span>
            <span className="num">{data[b] || 0}</span>
            <span className="pct">{Math.round(((data[b] || 0) / total) * 100)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function niceMax(v) {
  if (v <= 4) return 4;
  const mag = 10 ** Math.floor(Math.log10(v));
  const n = v / mag;
  return (n <= 2 ? 2 : n <= 5 ? 5 : 10) * mag;
}

function shortDay(iso) {
  const [, m, d] = iso.split('-').map(Number);
  return new Date(2000, m - 1, d).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function TrendChart({ data }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(null);
  const totals = data.map((x) => BANDS.reduce((s, b) => s + x[b], 0));
  const peak = Math.max(...totals, 0);
  const H = 190;
  const padL = 30;
  const padB = 22;
  const plotH = H - padB - 6;
  const W = Math.max(width, 200);
  const plotW = W - padL;
  const ymax = niceMax(peak);
  const step = plotW / Math.max(data.length, 1);
  const bw = Math.max(Math.min(step - 2, 22), 1);
  const y = (v) => 6 + plotH - (v / ymax) * plotH;
  const labelIdx = [...new Set([0, Math.floor((data.length - 1) / 2), data.length - 1])];

  return (
    <div className="chart" ref={ref}>
      {peak === 0 ? <Empty title="No discoveries in this window" /> : width > 0 && (
        <svg width={W} height={H} role="img" aria-label={`Leaks discovered per day, peak ${peak}`} onMouseLeave={() => setHover(null)}>
          <g className="grid">
            {[0, 0.5, 1].map((f) => (
              <g key={f}>
                <line x1={padL} x2={W} y1={y(ymax * f)} y2={y(ymax * f)} />
                <text className="tick" x={padL - 8} y={y(ymax * f) + 4} textAnchor="end">{Math.round(ymax * f)}</text>
              </g>
            ))}
          </g>
          {data.map((x, i) => {
            const cx = padL + i * step + (step - bw) / 2;
            let acc = 0;
            const segs = [...BANDS].reverse().filter((b) => x[b]);
            return (
              <g key={x.day}>
                {hover === i && <rect className="col-hover" x={padL + i * step} y={6} width={step} height={plotH} />}
                {segs.map((b, si) => {
                  const y0 = y(acc);
                  acc += x[b];
                  const y1 = y(acc);
                  const h = Math.max(y0 - y1 - (si < segs.length - 1 ? 2 : 0), 1);
                  return <rect key={b} x={cx} y={y1} width={bw} height={h} rx={Math.min(2, bw / 2)} fill={BAND_COLOR[b]} />;
                })}
                <rect className="hit" x={padL + i * step} y={0} width={step} height={H - padB} onMouseEnter={() => setHover(i)} />
              </g>
            );
          })}
          {labelIdx.map((i) => (
            <text key={i} className="tick" x={padL + i * step + step / 2} y={H - 4}
              textAnchor={i === 0 ? 'start' : i === data.length - 1 ? 'end' : 'middle'}>{shortDay(data[i].day)}</text>
          ))}
        </svg>
      )}
      {hover != null && data[hover] && (
        <div className="tip" style={{ left: Math.min(padL + hover * step + step + 8, W - 170), top: 8 }}>
          <div className="tip-title">{shortDay(data[hover].day)} · {totals[hover]} leaks</div>
          {BANDS.map((b) => (
            <div key={b} className="tip-row">
              <span className="swatch" style={{ background: BAND_COLOR[b] }} /> <span style={{ textTransform: 'capitalize' }}>{b}</span> <b>{data[hover][b]}</b>
            </div>
          ))}
        </div>
      )}
      {peak > 0 && (
        <div className="legend">
          {BANDS.map((b) => <span key={b}><span className="swatch" style={{ background: BAND_COLOR[b] }} /> {b}</span>)}
          <span className="faint" style={{ marginLeft: 'auto' }}>peak {peak}/day</span>
        </div>
      )}
    </div>
  );
}

function bandOf(v) {
  return v >= 80 ? 'critical' : v >= 60 ? 'high' : v >= 30 ? 'medium' : 'low';
}

function AssetTable({ rows, navigate }) {
  if (!rows.length) return <Empty title="No watched asset appeared in this window">Add domains, emails or keywords on the Watchlist to see exposure here.</Empty>;
  return (
    <div className="table-wrap" style={{ border: 0 }}>
      <table className="table asset-table">
        <thead><tr><th>Asset</th><th>Exposure</th><th>Open</th><th>Hits</th><th>Last seen</th></tr></thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.id || a.value} className="clickable"
              onClick={() => navigate(`/leaks?q=${encodeURIComponent(a.value)}`)}>
              <td>
                <div className="asset-name">{a.value} {a.vip && <Pill tone="vip">VIP</Pill>}</div>
                <div className="sub">{a.type}</div>
              </td>
              <td>
                <div className="expo" title={a.exposure ? `Highest open severity: ${a.exposure}` : 'No open leaks'}>
                  <span className="expo-track"><span className="expo-fill" style={{ width: `${a.exposure}%`, background: BAND_COLOR[bandOf(a.exposure)] }} /></span>
                  <span className="expo-num">{a.exposure}</span>
                </div>
              </td>
              <td className="mono">{a.open}</td>
              <td className="mono">{a.hits}</td>
              <td className="nowrap muted">{relTime(a.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

