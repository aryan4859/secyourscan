import React from 'react';
import { CheckCircle2, MinusCircle, XCircle } from 'lucide-react';

/**
 * The real data sources behind a page and what each returned in the last
 * scan. ``counts`` maps source key → number found, "error", or undefined
 * (not run / not configured).
 */
export default function SourcesPanel({ title = 'Data sources', sources, counts = {}, unit = 'found' }) {
  return (
    <section className="card">
      <header className="card-head"><h2>{title}</h2><span className="faint small">from the last scan</span></header>
      <div className="card-body">
        <ul className="sources-list">
          {sources.map((s) => {
            const v = counts[s.key];
            const state = v === 'error' ? 'bad' : v === undefined || v === 'disabled' ? 'off' : 'ok';
            return (
              <li key={s.key} className={`src-${state}`}>
                {state === 'ok' ? <CheckCircle2 size={14} /> : state === 'bad' ? <XCircle size={14} /> : <MinusCircle size={14} />}
                <div className="src-text">
                  <div className="src-title">{s.href ? <a className="link" href={s.href} target="_blank" rel="noreferrer noopener">{s.label}</a> : s.label}</div>
                  <div className="sub">{s.desc}</div>
                </div>
                <span className="src-count">{state === 'ok' ? `${v} ${unit}` : state === 'bad' ? 'failed' : (v === 'disabled' ? (s.off || 'disabled') : 'not run yet')}</span>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
