import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ExternalLink, Maximize2, RefreshCw, Search, X, ZoomIn, ZoomOut } from 'lucide-react';
import { api } from '../api';
import { Empty, ErrorBox, Pill, SeverityBadge, Spinner, StatusPill, relTime, useAsync } from '../components/ui';

// Same severity ramp as the dashboard (validated for the dark surface).
const SEV = (s) => (s >= 80 ? 'var(--sev-critical)' : s >= 60 ? 'var(--sev-high)' : s >= 30 ? 'var(--sev-medium)' : 'var(--sev-low)');
const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'assets', label: 'Assets' },
  { key: 'leaks', label: 'Leaks' },
  { key: 'vip', label: 'VIP only' },
  { key: 'critical', label: 'Critical' },
];
const RANGES = [7, 30, 90];
const TICKS = 320;

// Deterministic 0..1 from a string, so the same graph lays out the same way.
function rand(id, salt) {
  let h = 2166136261 ^ salt;
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 16777619);
  return ((h >>> 0) % 10000) / 10000;
}

/** Plain force layout: pairwise repulsion, springs on links, weak gravity. */
function useForceLayout(graph) {
  const [pos, setPos] = useState(null);
  const [settled, setSettled] = useState(false);
  useEffect(() => {
    if (!graph) return undefined;
    const { nodes, links } = graph;
    const idx = new Map(nodes.map((n, i) => [n.id, i]));
    const N = nodes.length;
    const x = new Float64Array(N);
    const y = new Float64Array(N);
    const vx = new Float64Array(N);
    const vy = new Float64Array(N);
    const assetIds = nodes.filter((n) => n.kind === 'asset').map((n) => n.id);
    const ring = Math.max(120, Math.sqrt(N) * 40);
    const firstAsset = new Map();
    links.forEach((l) => !firstAsset.has(l.source) && firstAsset.set(l.source, l.target));
    nodes.forEach((n, i) => {
      if (n.kind === 'asset') {
        const a = (assetIds.indexOf(n.id) / Math.max(assetIds.length, 1)) * Math.PI * 2;
        x[i] = Math.cos(a) * ring;
        y[i] = Math.sin(a) * ring;
      } else {
        const p = idx.get(firstAsset.get(n.id));
        x[i] = (p != null ? x[p] : 0) + (rand(n.id, 1) - 0.5) * 60;
        y[i] = (p != null ? y[p] : 0) + (rand(n.id, 2) - 0.5) * 60;
      }
    });
    const L = links.map((l) => [idx.get(l.source), idx.get(l.target)]).filter(([a, b]) => a != null && b != null);
    const degree = new Float64Array(N);
    L.forEach(([a, b]) => { degree[a]++; degree[b]++; });

    let tick = 0;
    let raf;
    setSettled(false);
    const step = () => {
      for (let s = 0; s < 8 && tick < TICKS; s++, tick++) {
        const alpha = 1 - tick / TICKS;
        for (let i = 0; i < N; i++) {
          for (let j = i + 1; j < N; j++) {
            let dx = x[j] - x[i];
            let dy = y[j] - y[i];
            let d2 = dx * dx + dy * dy;
            if (d2 < 1) { dx = rand(nodes[i].id, j) - 0.5; dy = rand(nodes[j].id, i) - 0.5; d2 = 1; }
            if (d2 > 250000) continue;
            const f = (900 * alpha) / d2;
            const d = Math.sqrt(d2);
            vx[i] -= (dx / d) * f; vy[i] -= (dy / d) * f;
            vx[j] += (dx / d) * f; vy[j] += (dy / d) * f;
          }
        }
        for (const [a, b] of L) {
          const dx = x[b] - x[a];
          const dy = y[b] - y[a];
          const d = Math.sqrt(dx * dx + dy * dy) || 1;
          const f = ((d - 38) / d) * 0.06 * alpha;
          const wa = 1 / Math.max(degree[a], 1);
          const wb = 1 / Math.max(degree[b], 1);
          vx[a] += dx * f * wa * 2; vy[a] += dy * f * wa * 2;
          vx[b] -= dx * f * wb * 2; vy[b] -= dy * f * wb * 2;
        }
        for (let i = 0; i < N; i++) {
          vx[i] -= x[i] * 0.004 * alpha;
          vy[i] -= y[i] * 0.004 * alpha;
          vx[i] *= 0.6; vy[i] *= 0.6;
          x[i] += vx[i]; y[i] += vy[i];
        }
      }
      setPos({ x: Float64Array.from(x), y: Float64Array.from(y), idx });
      if (tick < TICKS) raf = requestAnimationFrame(step);
      else setSettled(true);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [graph]);
  return [pos, settled];
}

function useSize() {
  const ref = useRef(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useLayoutEffect(() => {
    if (!ref.current) return undefined;
    const ro = new ResizeObserver(([e]) => setSize({ w: Math.floor(e.contentRect.width), h: Math.floor(e.contentRect.height) }));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, size];
}

export default function Topology() {
  const [days, setDays] = useState(30);
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(null);
  const [hover, setHover] = useState(null);
  const graph = useAsync(() => api.topology({ days }), [days]);
  const navigate = useNavigate();
  const g = graph.data;
  const [pos, settled] = useForceLayout(g);
  const [boxRef, { w, h }] = useSize();
  const svgRef = useRef(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const drag = useRef(null);
  const fitted = useRef(false);

  const byId = useMemo(() => new Map((g?.nodes || []).map((n) => [n.id, n])), [g]);
  const neighbors = useMemo(() => {
    const m = new Map();
    (g?.links || []).forEach(({ source, target }) => {
      if (!m.has(source)) m.set(source, new Set());
      if (!m.has(target)) m.set(target, new Set());
      m.get(source).add(target);
      m.get(target).add(source);
    });
    return m;
  }, [g]);

  // Which nodes the active filter keeps; the rest are dimmed, never moved.
  const visible = useMemo(() => {
    if (!g) return new Set();
    const keep = new Set();
    const isCrit = (n) => n.kind === 'leak' && n.severity >= 80;
    for (const n of g.nodes) {
      if (filter === 'all'
        || (filter === 'assets' && n.kind === 'asset')
        || (filter === 'leaks' && n.kind === 'leak')
        || (filter === 'vip' && n.kind === 'asset' && n.vip)
        || (filter === 'critical' && isCrit(n))) keep.add(n.id);
    }
    if (filter === 'vip' || filter === 'critical') {
      [...keep].forEach((id) => neighbors.get(id)?.forEach((nb) => keep.add(nb)));
    }
    return keep;
  }, [g, filter, neighbors]);

  const focus = hover || selected;
  const lit = useMemo(() => (focus ? new Set([focus, ...(neighbors.get(focus) || [])]) : null), [focus, neighbors]);

  const fit = useCallback(() => {
    if (!pos || !w || !h || !g?.nodes.length) return;
    let x0 = Infinity; let y0 = Infinity; let x1 = -Infinity; let y1 = -Infinity;
    for (let i = 0; i < pos.x.length; i++) {
      x0 = Math.min(x0, pos.x[i]); x1 = Math.max(x1, pos.x[i]);
      y0 = Math.min(y0, pos.y[i]); y1 = Math.max(y1, pos.y[i]);
    }
    const k = Math.min(2.5, Math.min(w / (x1 - x0 + 80), h / (y1 - y0 + 80)));
    setView({ k, x: w / 2 - ((x0 + x1) / 2) * k, y: h / 2 - ((y0 + y1) / 2) * k });
  }, [pos, w, h, g]);

  useEffect(() => { fitted.current = false; setSelected(null); }, [g]);
  useEffect(() => { setSelected(null); }, [filter]);
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && setSelected(null);
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);
  useEffect(() => {
    if (pos && !fitted.current && w) fit();
    if (settled && !fitted.current) { fit(); fitted.current = true; }
  }, [pos, settled, w, fit]);

  const zoomAt = useCallback((factor, cx, cy) => {
    setView((v) => {
      const k = Math.min(8, Math.max(0.15, v.k * factor));
      const f = k / v.k;
      return { k, x: cx - (cx - v.x) * f, y: cy - (cy - v.y) * f };
    });
  }, []);

  useEffect(() => {
    const el = svgRef.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [zoomAt, g]);

  const centerOn = (id) => {
    const i = pos?.idx.get(id);
    if (i == null) return;
    setView((v) => {
      const k = Math.max(v.k, 1.6);
      return { k, x: w / 2 - pos.x[i] * k, y: h / 2 - pos.y[i] * k };
    });
    setSelected(id);
  };

  const jump = (e) => {
    e.preventDefault();
    const q = query.trim().toLowerCase();
    if (!q || !g) return;
    const hit = g.nodes.find((n) => n.kind === 'asset' && n.label?.toLowerCase().includes(q))
      || g.nodes.find((n) => n.label?.toLowerCase().includes(q));
    if (hit) centerOn(hit.id);
  };

  const onPointerDown = (e) => {
    const id = e.target.closest?.('[data-id]')?.getAttribute('data-id') || null;
    drag.current = { sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y, moved: false, id };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onPointerMove = (e) => {
    const d = drag.current;
    if (!d) return;
    if (Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy) > 3) d.moved = true;
    setView((v) => ({ ...v, x: d.vx + e.clientX - d.sx, y: d.vy + e.clientY - d.sy }));
  };
  const onPointerUp = () => {
    const d = drag.current;
    drag.current = null;
    if (d && !d.moved) setSelected(d.id);
  };

  const counts = useMemo(() => {
    const c = { asset: 0, leak: 0 };
    g?.nodes.forEach((n) => { c[n.kind]++; });
    return c;
  }, [g]);

  const sel = selected ? byId.get(selected) : null;
  // Label the busiest assets up front; the rest appear on zoom, hover or selection.
  const labelled = useMemo(() => new Set((g?.nodes || []).filter((n) => n.kind === 'asset')
    .sort((a, b) => b.hits - a.hits).slice(0, 10).map((n) => n.id)), [g]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Topology</h1>
          <p className="muted">Your watched assets and the leaks that matched them. Assets that share a leak sit in the same cluster. Only watch matches make links; names and addresses found inside leaks never become nodes.</p>
        </div>
        <div className="btn-row">
          <div className="seg" role="group" aria-label="Time range">
            {RANGES.map((r) => <button key={r} className={r === days ? 'on' : ''} onClick={() => setDays(r)}>{r}d</button>)}
          </div>
          <button className="btn" onClick={graph.reload}><RefreshCw size={14} /> Re-layout</button>
        </div>
      </div>

      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Filter nodes">
          {FILTERS.map((f) => <button key={f.key} className={f.key === filter ? 'on' : ''} onClick={() => setFilter(f.key)}>{f.label}</button>)}
        </div>
        <form className="topo-search" onSubmit={jump}>
          <Search size={14} />
          <input className="input bare" placeholder="Jump to node by label…" value={query} onChange={(e) => setQuery(e.target.value)} />
        </form>
        <div className="btn-row">
          <button className="icon-btn" onClick={() => zoomAt(1 / 1.3, w / 2, h / 2)} aria-label="Zoom out"><ZoomOut size={16} /></button>
          <button className="icon-btn" onClick={fit} aria-label="Fit to view"><Maximize2 size={16} /></button>
          <button className="icon-btn" onClick={() => zoomAt(1.3, w / 2, h / 2)} aria-label="Zoom in"><ZoomIn size={16} /></button>
        </div>
      </div>

      <ErrorBox error={graph.error} onRetry={graph.reload} />
      <section className="topo-card" ref={boxRef}>
        <div className="topo-head">
          <div><div className="topo-title">Exposure graph</div><div className="faint small">Force-directed · drag to pan, scroll to zoom</div></div>
          {g && <span className="topo-count mono">{counts.asset} assets · {counts.leak} leaks · {g.links.length} links</span>}
        </div>
        {graph.loading && !g && <div className="topo-center"><Spinner label="Loading graph…" /></div>}
        {g && g.nodes.length === 0 && (
          <div className="topo-center"><Empty title="Nothing to draw yet">Add assets on the Watchlist; leaks that match them appear here.</Empty></div>
        )}
        {g && g.nodes.length > 0 && pos && w > 0 && (
          <svg ref={svgRef} className="topo-svg" width={w} height={h} onPointerDown={onPointerDown} onPointerMove={onPointerMove}
            onPointerUp={onPointerUp} role="img" aria-label={`Graph of ${counts.asset} assets and ${counts.leak} leaks`}>
            <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
              {g.links.map((l) => {
                const a = pos.idx.get(l.source);
                const b = pos.idx.get(l.target);
                if (a == null || b == null) return null;
                const on = visible.has(l.source) && visible.has(l.target);
                const hot = lit && lit.has(l.source) && lit.has(l.target);
                return (
                  <line key={`${l.source}-${l.target}`} x1={pos.x[a]} y1={pos.y[a]} x2={pos.x[b]} y2={pos.y[b]}
                    className={`topo-link ${hot ? 'hot' : ''}`} opacity={!on ? 0.05 : lit && !hot ? 0.12 : 1} strokeWidth={1 / view.k} />
                );
              })}
              {g.nodes.map((n) => {
                const i = pos.idx.get(n.id);
                const on = visible.has(n.id);
                const dim = !on || (lit && !lit.has(n.id));
                const r = n.kind === 'asset' ? 6 + Math.min(n.hits, 20) * 0.35 : 4;
                const fill = n.kind === 'asset' ? (n.vip ? 'var(--vip)' : 'var(--series-1)') : SEV(n.severity);
                return (
                  <g key={n.id} data-id={n.id} className="topo-node" transform={`translate(${pos.x[i]},${pos.y[i]})`}
                    opacity={dim ? (on ? 0.2 : 0.06) : 1} onPointerEnter={() => setHover(n.id)} onPointerLeave={() => setHover(null)}>
                    <circle r={(r + 6) / Math.sqrt(view.k)} fill="transparent" />
                    {n.kind === 'asset' && n.exposure >= 80 && <circle r={r + 4} className="topo-ring" />}
                    <circle r={r} fill={fill} stroke={selected === n.id ? 'var(--text)' : 'var(--panel)'} strokeWidth={selected === n.id ? 2 : 1.5} />
                    {n.kind === 'asset' && (view.k > 1.6 || labelled.has(n.id) || lit?.has(n.id)) && !dim && (
                      <text y={r + 12} textAnchor="middle" className="topo-label" style={{ fontSize: 11 / view.k }}>{n.label}</text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>
        )}
        {hover && byId.get(hover) && !sel && <HoverTip node={byId.get(hover)} />}
        {sel && (
          <NodePanel node={sel} neighbors={[...(neighbors.get(sel.id) || [])].map((id) => byId.get(id)).filter(Boolean)}
            onClose={() => setSelected(null)} onPick={centerOn} navigate={navigate} />
        )}
        {g && g.nodes.length > 0 && (
          <div className="topo-legend">
            <span><span className="swatch round" style={{ background: 'var(--series-1)' }} /> Asset</span>
            <span><span className="swatch round" style={{ background: 'var(--vip)' }} /> VIP asset</span>
            <span><span className="swatch round" style={{ background: 'var(--sev-critical)' }} /> Critical leak</span>
            <span><span className="swatch round" style={{ background: 'var(--sev-high)' }} /> High</span>
            <span><span className="swatch round" style={{ background: 'var(--sev-medium)' }} /> Medium</span>
            <span><span className="swatch round" style={{ background: 'var(--sev-low)' }} /> Low</span>
            <span><span className="swatch round ring" /> Exposure ≥ 80</span>
          </div>
        )}
        {g && pos && g.nodes.length > 0 && w > 0 && <Minimap graph={g} pos={pos} view={view} w={w} h={h} setView={setView} visible={visible} />}
      </section>
      {g?.truncated && <p className="fineprint">Showing the 300 most severe matching leaks in this window.</p>}
    </div>
  );
}

function HoverTip({ node }) {
  return (
    <div className="topo-hover">
      {node.kind === 'asset' ? (
        <><b>{node.label}</b> <span className="faint">{node.type}{node.vip ? ' · VIP' : ''} · {node.hits} hits · exposure {node.exposure}</span></>
      ) : (
        <><b>{node.label}</b> <span className="faint">{node.source} · severity {node.severity}</span></>
      )}
    </div>
  );
}

function NodePanel({ node, neighbors, onClose, onPick, navigate }) {
  const leaks = neighbors.filter((n) => n.kind === 'leak').sort((a, b) => b.severity - a.severity);
  const assets = neighbors.filter((n) => n.kind === 'asset');
  return (
    <aside className="topo-panel" onPointerDown={(e) => e.stopPropagation()}>
      <header>
        <div className="topo-panel-title">{node.label}</div>
        <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={16} /></button>
      </header>
      {node.kind === 'asset' ? (
        <>
          <div className="tags">
            <Pill>{node.type}</Pill>
            {node.vip && <Pill tone="vip">VIP</Pill>}
            <Pill tone={node.exposure >= 80 ? 'critical' : 'default'}>exposure {node.exposure}</Pill>
          </div>
          <div className="faint small mt">{node.hits} matching leak{node.hits === 1 ? '' : 's'} in this window</div>
          <ul className="topo-list">
            {leaks.slice(0, 8).map((l) => (
              <li key={l.id} onClick={() => onPick(l.id)}>
                <SeverityBadge value={l.severity} /> <span className="trunc-fill">{l.label}</span>
              </li>
            ))}
          </ul>
          <button className="btn btn-sm mt" onClick={() => navigate(`/leaks?q=${encodeURIComponent(node.label)}`)}>
            <ExternalLink size={13} /> Search leaks for this asset
          </button>
        </>
      ) : (
        <>
          <div className="tags"><SeverityBadge value={node.severity} /> <StatusPill status={node.status} /></div>
          <div className="faint small mt">{node.source} · {relTime(node.discovered_at)}</div>
          <h4 className="mt">Matched assets</h4>
          <ul className="topo-list">
            {assets.map((a) => (
              <li key={a.id} onClick={() => onPick(a.id)}>
                <span className="swatch round" style={{ background: a.vip ? 'var(--vip)' : 'var(--series-1)' }} /> <span className="trunc-fill">{a.label}</span>
              </li>
            ))}
          </ul>
          <button className="btn btn-sm btn-primary mt" onClick={() => navigate(`/leaks?id=${encodeURIComponent(node.id.slice(2))}`)}>
            <ExternalLink size={13} /> Open leak
          </button>
        </>
      )}
    </aside>
  );
}

function Minimap({ graph, pos, view, w, h, setView, visible }) {
  const MW = 180;
  const MH = 120;
  let x0 = Infinity; let y0 = Infinity; let x1 = -Infinity; let y1 = -Infinity;
  for (let i = 0; i < pos.x.length; i++) {
    x0 = Math.min(x0, pos.x[i]); x1 = Math.max(x1, pos.x[i]);
    y0 = Math.min(y0, pos.y[i]); y1 = Math.max(y1, pos.y[i]);
  }
  const pad = 20;
  const s = Math.min(MW / (x1 - x0 + pad * 2 || 1), MH / (y1 - y0 + pad * 2 || 1));
  const mx = (v) => (v - x0 + pad) * s;
  const my = (v) => (v - y0 + pad) * s;
  const vx = (-view.x / view.k);
  const vy = (-view.y / view.k);
  const click = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    const wx = (e.clientX - r.left) / s + x0 - pad;
    const wy = (e.clientY - r.top) / s + y0 - pad;
    setView((v) => ({ ...v, x: w / 2 - wx * v.k, y: h / 2 - wy * v.k }));
  };
  return (
    <div className="topo-minimap" onPointerDown={(e) => e.stopPropagation()}>
      <div className="topo-minimap-head"><span>Minimap</span><span>{graph.nodes.length}</span></div>
      <svg width={MW} height={MH} onClick={click}>
        {graph.nodes.map((n) => {
          const i = pos.idx.get(n.id);
          return <circle key={n.id} cx={mx(pos.x[i])} cy={my(pos.y[i])} r={n.kind === 'asset' ? 2.2 : 1.3}
            opacity={visible.has(n.id) ? 1 : 0.2}
            fill={n.kind === 'asset' ? (n.vip ? 'var(--vip)' : 'var(--series-1)') : SEV(n.severity)} />;
        })}
        <rect x={mx(vx)} y={my(vy)} width={(w / view.k) * s} height={(h / view.k) * s} className="topo-viewport" />
      </svg>
    </div>
  );
}
