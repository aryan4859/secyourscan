'use client';

import { Fragment, useDeferredValue, useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { motion } from 'motion/react';
import { EASE } from '../../components/motion';
import { PASSWORD_RISK, comma, fmtDate } from '../../lib/format';

const PAGE = 50;
const SORTS = {
  added: (a, b) => Date.parse(b.added || 0) - Date.parse(a.added || 0),
  breached: (a, b) => Date.parse(b.breached || 0) - Date.parse(a.breached || 0),
  size: (a, b) => b.records - a.records,
  name: (a, b) => a.id.localeCompare(b.id),
};
const HOT = /password|government|credit|bank|security question|health/i;

export default function Directory({ rows }) {
  const params = useSearchParams();
  const industries = useMemo(() => [...new Set(rows.map((b) => b.industry).filter(Boolean))].sort(), [rows]);
  const [q, setQ] = useState(params.get('q') || '');
  const [industry, setIndustry] = useState(industries.includes(params.get('industry')) ? params.get('industry') : '');
  const [sort, setSort] = useState('added');
  const [shown, setShown] = useState(PAGE);
  const [open, setOpen] = useState(null);
  const dq = useDeferredValue(q);

  const indexed = useMemo(() => rows.map((b) => ({ ...b, _s: [b.id, b.domain, b.industry, ...b.data].join(' ').toLowerCase() })), [rows]);
  const filtered = useMemo(() => {
    const words = dq.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return indexed.filter((b) => (!industry || b.industry === industry) && words.every((w) => b._s.includes(w))).sort(SORTS[sort]);
  }, [indexed, dq, industry, sort]);

  const reset = (fn) => (e) => { fn(e.target.value); setShown(PAGE); setOpen(null); };
  const visible = filtered.slice(0, shown);

  return (
    <>
      <div className="filters">
        <label className="sr-only" htmlFor="search">Search breaches</label>
        <input id="search" type="search" placeholder="Search by name, domain or data type" value={q} onChange={reset(setQ)} />
        <label className="sr-only" htmlFor="industry">Industry</label>
        <select id="industry" value={industry} onChange={reset(setIndustry)}>
          <option value="">All industries</option>
          {industries.map((i) => <option key={i} value={i}>{i}</option>)}
        </select>
        <label className="sr-only" htmlFor="sort">Sort</label>
        <select id="sort" value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="added">Recently added</option>
          <option value="breached">Breach date</option>
          <option value="size">Largest first</option>
          <option value="name">Name A–Z</option>
        </select>
        <span className="count-line" aria-live="polite">
          {filtered.length === rows.length ? `${comma(rows.length)} breaches` : `${comma(filtered.length)} of ${comma(rows.length)}`}
        </span>
      </div>

      {filtered.length === 0 ? (
        <motion.p className="muted" style={{ padding: '24px 0' }} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          No breach matches that. Try a shorter search.
        </motion.p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th>Breach</th><th>Industry</th><th className="num">Breached</th><th className="num">Records</th></tr>
            </thead>
            <tbody>
              {visible.map((b, i) => (
                  <Fragment key={b.id}>
                    <motion.tr className={`expandable ${open === b.id ? 'is-open' : ''}`} tabIndex={0}
                      aria-expanded={open === b.id}
                      initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.35, delay: Math.min(i, 12) * 0.015, ease: EASE }}
                      onClick={() => setOpen(open === b.id ? null : b.id)}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(open === b.id ? null : b.id); } }}>
                      <td><div className="row-name"><span className="caret" aria-hidden="true">›</span>{b.id}</div><div className="desc">{b.domain}</div></td>
                      <td>{b.industry || '—'}</td>
                      <td className="num">{fmtDate(b.breached, { month: 'short', year: 'numeric' })}</td>
                      <td className="num">{comma(b.records)}</td>
                    </motion.tr>
                    {open === b.id && (
                      <tr className="detail-row">
                        <td colSpan={4}>
                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                            transition={{ duration: 0.4, ease: EASE }} style={{ overflow: 'hidden' }}>
                            <Detail b={b} />
                          </motion.div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
            </tbody>
          </table>
        </div>
      )}
      {filtered.length > shown && (
        <p className="more"><button className="btn quiet" onClick={() => setShown((n) => n + PAGE)}>Show {Math.min(PAGE, filtered.length - shown)} more</button></p>
      )}
    </>
  );
}

function Detail({ b }) {
  const [pw] = PASSWORD_RISK[String(b.passwordRisk || 'unknown').toLowerCase()] || [b.passwordRisk];
  const flags = [b.verified ? 'verified' : 'unverified', b.sensitive && 'sensitive', b.type !== 'DataBreach' && b.type].filter(Boolean).join(' · ');
  let host = '';
  try { host = b.ref ? new URL(b.ref).hostname : ''; } catch { host = ''; }
  return (
    <div className="detail">
      <p>{b.description || 'No description.'}</p>
      <dl>
        <dt>What leaked</dt>
        <dd><div className="chips">{b.data.map((d) => <span key={d} className={`chip ${HOT.test(d) ? 'hot' : ''}`}>{d}</span>)}</div></dd>
        <dt>Passwords</dt><dd>{pw}</dd>
        <dt>Breached</dt><dd>{fmtDate(b.breached)}</dd>
        <dt>Added to index</dt><dd>{fmtDate(b.added)}</dd>
        <dt>Status</dt><dd>{flags}</dd>
        {host && <><dt>Source</dt><dd><a href={b.ref} target="_blank" rel="noopener noreferrer">{host}</a></dd></>}
      </dl>
    </div>
  );
}
