import React, { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { CheckCheck, FileDown, FileText, Search, X } from 'lucide-react';
import { api } from '../api';
import useDebounced from '../useDebounced';
import { Highlight } from '../components/Highlight';
import LeakDrawer from '../components/LeakDrawer';
import {
  Empty, ErrorBox, Pill, SeverityBadge, Spinner, STATUSES, StatusPill, relTime, statusLabel, useAsync, useToast,
} from '../components/ui';

const PAGE = 25;
const SEVERITY_PRESETS = [
  { key: 'all', label: 'Any severity', min: null, max: null },
  { key: 'critical', label: 'Critical ≥80', min: 80, max: null },
  { key: 'high', label: 'High 60–79', min: 60, max: 79 },
  { key: 'medium', label: 'Medium 30–59', min: 30, max: 59 },
  { key: 'low', label: 'Low <30', min: 0, max: 29 },
];

function presetFromMin(min) {
  if (min == null) return 'all';
  return SEVERITY_PRESETS.find((p) => p.min === Number(min))?.key || 'all';
}

export default function Leaks({ onDossier }) {
  const [params, setParams] = useSearchParams();
  const toast = useToast();
  const [q, setQ] = useState(params.get('q') || '');
  const [sev, setSev] = useState(presetFromMin(params.get('min')));
  const [sources, setSources] = useState(params.get('source') ? [params.get('source')] : []);
  const [statuses, setStatuses] = useState([]);
  const [category, setCategory] = useState(params.get('category') || '');
  const [offset, setOffset] = useState(0);
  const debouncedQ = useDebounced(q.trim(), 300);
  const openId = params.get('id');

  // Deep links (?min=, ?source=, ?category=, ?q=) from the dashboard / palette.
  useEffect(() => {
    if (params.has('min')) setSev(presetFromMin(params.get('min')));
    if (params.has('source')) setSources([params.get('source')]);
    if (params.has('category')) setCategory(params.get('category'));
    if (params.has('q')) setQ(params.get('q'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.get('min'), params.get('source'), params.get('category'), params.get('q')]);

  useEffect(() => { setOffset(0); }, [debouncedQ, sev, sources, statuses, category]);

  const stats = useAsync(() => api.stats(), []);
  const preset = SEVERITY_PRESETS.find((p) => p.key === sev);
  const query = {
    q: debouncedQ || undefined,
    min_severity: preset.min,
    max_severity: preset.max,
    source: sources,
    status: statuses,
    category: category || undefined,
    limit: PAGE,
    offset,
  };
  // useAsync drops stale responses, so fast typing never shows an old page.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const res = useAsync(() => api.searchLeaks(query), [JSON.stringify(query)]);

  const sourceOptions = useMemo(() => {
    const fromFacets = res.data?.facets?.sources || {};
    const fromStats = stats.data?.by_source || {};
    return [...new Set([...Object.keys(fromStats), ...Object.keys(fromFacets), ...sources])].sort();
  }, [res.data, stats.data, sources]);
  const categoryOptions = useMemo(() => {
    const fromFacets = res.data?.facets?.categories || {};
    const fromStats = stats.data?.by_category || {};
    return [...new Set([...Object.keys(fromStats), ...Object.keys(fromFacets)])].filter(Boolean).sort();
  }, [res.data, stats.data]);

  const toggle = (list, setList, v) => setList(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const openLeak = (id) => {
    const next = new URLSearchParams(params);
    if (id) next.set('id', id);
    else next.delete('id');
    setParams(next, { replace: !id });
  };
  const clearFilters = () => {
    setQ('');
    setSev('all');
    setSources([]);
    setStatuses([]);
    setCategory('');
    setParams(openId ? { id: openId } : {});
  };

  const ackAll = async () => {
    if (!window.confirm('Acknowledge every unacknowledged leak with severity 80 or above?')) return;
    try {
      const r = await api.ackAll(80);
      toast(`Acknowledged ${r.acknowledged} critical leaks`, 'ok');
      res.reload();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const exportCsv = async () => {
    try {
      await api.exportCsv();
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const total = res.data?.total ?? 0;
  const items = res.data?.items || [];
  const hasFilters = q || sev !== 'all' || sources.length || statuses.length || category;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Leaks</h1>
          <p className="muted">Snippets are masked. Raw evidence is only available on request and every download is audited.</p>
        </div>
        <div className="btn-row">
          <button className="btn" onClick={ackAll}><CheckCheck size={14} /> Ack all critical</button>
          <button className="btn" onClick={exportCsv}><FileText size={14} /> Export CSV</button>
          <button className="btn btn-primary" onClick={onDossier}><FileDown size={14} /> Dossier</button>
        </div>
      </div>

      <div className="searchbar">
        <Search size={16} />
        <input className="input bare" placeholder="Search masked snippets, titles and URLs…" value={q}
          onChange={(e) => setQ(e.target.value)} maxLength={256} />
        {q && <button className="icon-btn" onClick={() => setQ('')} aria-label="Clear search"><X size={16} /></button>}
      </div>

      <div className="filters">
        <FilterRow label="Severity">
          {SEVERITY_PRESETS.map((p) => (
            <button key={p.key} className={`chip ${sev === p.key ? 'on' : ''} chip-${p.key}`} onClick={() => setSev(p.key)}>{p.label}</button>
          ))}
        </FilterRow>
        <FilterRow label="Status">
          {STATUSES.map((s) => (
            <button key={s} className={`chip ${statuses.includes(s) ? 'on' : ''}`} onClick={() => toggle(statuses, setStatuses, s)}>
              {statusLabel(s)}
            </button>
          ))}
        </FilterRow>
        {sourceOptions.length > 0 && (
          <FilterRow label="Source">
            {sourceOptions.map((s) => (
              <button key={s} className={`chip ${sources.includes(s) ? 'on' : ''}`} onClick={() => toggle(sources, setSources, s)}>
                {s}{res.data?.facets?.sources?.[s] != null && <span className="chip-count">{res.data.facets.sources[s]}</span>}
              </button>
            ))}
          </FilterRow>
        )}
        {categoryOptions.length > 0 && (
          <FilterRow label="Category">
            {categoryOptions.map((c) => (
              <button key={c} className={`chip ${category === c ? 'on' : ''}`} onClick={() => setCategory(category === c ? '' : c)}>{c}</button>
            ))}
          </FilterRow>
        )}
      </div>

      <div className="result-meta">
        <span>{res.loading ? 'Searching…' : `${total.toLocaleString()} result${total === 1 ? '' : 's'}`}</span>
        {res.data?.engine && (
          <Pill tone={res.data.engine === 'elasticsearch' ? 'ok' : 'default'}
            title={res.data.engine === 'sql' ? 'SQL fallback: no relevance ranking or highlights' : 'Full-text relevance with highlights'}>
            engine: {res.data.engine}
          </Pill>
        )}
        {hasFilters && <button className="link" onClick={clearFilters}>Clear filters</button>}
      </div>

      <ErrorBox error={res.error} onRetry={res.reload} />
      {res.loading && !res.data && <Spinner />}
      {res.data && items.length === 0 && (
        <Empty title="No leaks match">{hasFilters ? 'Try widening the filters.' : 'Nothing has matched your watchlist yet.'}</Empty>
      )}

      {items.length > 0 && (
        <div className={`table-wrap ${res.loading ? 'is-loading' : ''}`}>
          <table className="table leaks-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Source</th>
                <th className="w-50">Finding</th>
                <th>Matched watch items</th>
                <th>Status</th>
                <th>Seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((l) => (
                <tr key={l.id} className="clickable" onClick={() => openLeak(l.id)}>
                  <td><SeverityBadge value={l.severity} /></td>
                  <td><span className="mono">{l.source}</span>{l.category && <div className="sub">{l.category}</div>}</td>
                  <td>
                    <div className="cell-title">{l.title || <span className="muted">untitled</span>}</div>
                    {l.highlights?.length > 0 ? (
                      <div className="highlights">
                        {l.highlights.slice(0, 3).map((h, i) => <div key={i} className="hl-frag"><Highlight html={h} /></div>)}
                      </div>
                    ) : (
                      <div className="snippet">{l.snippet}</div>
                    )}
                    <div className="tags">
                      {l.yara_rules?.map((r) => <Pill key={r} tone="rule">{r}</Pill>)}
                      {l.credential_count > 0 && <Pill tone="critical">{l.credential_count} credentials</Pill>}
                      {l.email_count > 0 && <Pill>{l.email_count} emails</Pill>}
                      {l.has_evidence && <Pill tone="warn">raw evidence</Pill>}
                    </div>
                  </td>
                  <td>
                    <div className="tags">
                      {l.watch_matches?.length ? l.watch_matches.map((m) => (
                        <Pill key={m.id || m.value} tone={m.vip ? 'vip' : 'default'} title={m.type}>{m.vip && '★ '}{m.value}</Pill>
                      )) : <span className="muted">—</span>}
                    </div>
                  </td>
                  <td>
                    <StatusPill status={l.status} />
                    {!l.acknowledged_at && <div className="sub warn-text">unacked</div>}
                  </td>
                  <td className="nowrap">
                    {relTime(l.last_seen_at || l.discovered_at)}
                    {l.seen_count > 1 && <div className="sub">×{l.seen_count}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {total > PAGE && (
        <div className="pager">
          <button className="btn btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
          <span>{offset + 1}–{Math.min(offset + PAGE, total)} of {total.toLocaleString()}</span>
          <button className="btn btn-sm" disabled={offset + PAGE >= total || offset + PAGE > 10000}
            onClick={() => setOffset(offset + PAGE)}>Next</button>
        </div>
      )}

      {openId && (
        <LeakDrawer id={openId} onClose={() => openLeak(null)} onChanged={(summary) => {
          res.setData((d) => d && { ...d, items: d.items.map((x) => (x.id === summary.id ? { ...x, ...summary } : x)) });
        }} />
      )}
    </div>
  );
}

function FilterRow({ label, children }) {
  return (
    <div className="filter-row">
      <span className="filter-label">{label}</span>
      <div className="chips">{children}</div>
    </div>
  );
}

