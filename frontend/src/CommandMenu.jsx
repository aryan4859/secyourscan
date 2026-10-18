import React, { useEffect, useState } from 'react';
import { Command } from 'cmdk';
import { CheckCheck, FileDown, FileText, Plus, ShieldCheck, Siren } from 'lucide-react';
import { api } from './api';
import { NAV } from './nav';
import useDebounced from './useDebounced';
import { severityBand, useToast } from './components/ui';
import { decodeEntities } from './components/Highlight';

// Global Ctrl/⌘+K palette, modelled on naso's CommandMenu.jsx:
//  - cmdk does fuzzy filtering over each item's value + keywords;
//  - with no query, open critical leaks are listed first;
//  - a typed query (2+ chars) also hits /leaks/search, so leaks outside what
//    is on screen are reachable. Remote hits carry the query as a keyword so
//    cmdk's client-side filter never hides a server-side match.

const OPEN_STATUSES = ['new', 'reviewing', 'escalated'];

export default function CommandMenu({ navigate, onDossier }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [top, setTop] = useState([]);
  const [remote, setRemote] = useState({ items: [], loading: false, error: null });
  const debounced = useDebounced(query.trim(), 200);
  const toast = useToast();

  useEffect(() => {
    const down = (e) => {
      if (e.key && e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    const openHandler = () => setOpen(true);
    document.addEventListener('keydown', down);
    window.addEventListener('sys:open-command', openHandler);
    return () => {
      document.removeEventListener('keydown', down);
      window.removeEventListener('sys:open-command', openHandler);
    };
  }, []);

  // Top open critical leaks, refreshed each time the palette opens.
  useEffect(() => {
    if (!open) return undefined;
    let alive = true;
    api.searchLeaks({ min_severity: 80, status: OPEN_STATUSES, limit: 8 })
      .then((r) => alive && setTop(r.items || []))
      .catch(() => alive && setTop([]));
    return () => { alive = false; };
  }, [open]);

  // Live search.
  useEffect(() => {
    if (!open || debounced.length < 2) {
      setRemote({ items: [], loading: false, error: null });
      return undefined;
    }
    let alive = true;
    setRemote((r) => ({ ...r, loading: true, error: null }));
    api.searchLeaks({ q: debounced, limit: 10 })
      .then((r) => alive && setRemote({ items: r.items || [], loading: false, error: null, engine: r.engine, total: r.total }))
      .catch((e) => alive && setRemote({ items: [], loading: false, error: e.message }));
    return () => { alive = false; };
  }, [debounced, open]);

  const close = () => { setOpen(false); setQuery(''); };
  const run = (fn) => () => { close(); fn(); };

  const verifyChain = async () => {
    try {
      const r = await api.verifyAudit();
      if (r.valid) toast(`Audit chain intact (${r.checked} entries)`, 'ok');
      else toast(`Audit chain BROKEN at entry #${r.broken_at} (${r.reason})`, 'error');
      navigate('/audit');
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const ackAll = async () => {
    if (!window.confirm('Acknowledge every unacknowledged leak with severity 80 or above?')) return;
    try {
      const r = await api.ackAll(80);
      toast(`Acknowledged ${r.acknowledged} critical leaks`, 'ok');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  if (!open) return null;

  const showingRemote = debounced.length >= 2;
  const leaks = showingRemote ? remote.items : top;

  return (
    <div className="cmdk-overlay" onClick={close}>
      <div className="cmdk-panel" onClick={(e) => e.stopPropagation()}>
        <Command label="Global command menu"
          onKeyDown={(e) => { if (e.key === 'Escape') { e.preventDefault(); close(); } }}>
          <Command.Input autoFocus value={query} onValueChange={setQuery} placeholder="Search leaks, pages and actions…" />
          <Command.List>
            <Command.Empty>{remote.loading ? 'Searching…' : 'No results. Try another keyword.'}</Command.Empty>

            <Command.Group heading="Navigation">
              {NAV.map(({ to, label, icon: Icon, keywords }) => (
                <Command.Item key={to} value={`nav ${label}`} keywords={keywords} onSelect={run(() => navigate(to))}>
                  <Icon size={15} /> <span className="item-title">{label}</span>
                </Command.Item>
              ))}
            </Command.Group>

            <Command.Group heading="Quick actions">
              <Command.Item value="action verify audit chain" keywords={['audit', 'integrity', 'hash']} onSelect={run(verifyChain)}>
                <ShieldCheck size={15} /> Verify audit chain
              </Command.Item>
              <Command.Item value="action acknowledge all critical" keywords={['ack', 'critical', 'triage']} onSelect={run(ackAll)}>
                <CheckCheck size={15} /> Acknowledge all critical leaks
              </Command.Item>
              <Command.Item value="action export dossier" keywords={['pdf', 'report', 'signed', 'export']} onSelect={run(onDossier)}>
                <FileDown size={15} /> Export signed dossier
              </Command.Item>
              <Command.Item value="action export csv" keywords={['csv', 'spreadsheet', 'export']}
                onSelect={run(() => api.exportCsv().catch((e) => toast(e.message, 'error')))}>
                <FileText size={15} /> Export leaks CSV
              </Command.Item>
              <Command.Item value="action new watch item" keywords={['add', 'watchlist', 'domain', 'email', 'monitor']}
                onSelect={run(() => navigate('/watchlist?new=1'))}>
                <Plus size={15} /> New watch item
              </Command.Item>
              <Command.Item value="action show critical leaks" keywords={['critical', 'severity', 'filter']}
                onSelect={run(() => navigate('/leaks?min=80'))}>
                <Siren size={15} /> Show critical leaks
              </Command.Item>
              {showingRemote && (
                <Command.Item value={`action search leaks for ${debounced}`} keywords={[debounced]}
                  onSelect={run(() => navigate(`/leaks?q=${encodeURIComponent(debounced)}`))}>
                  Search all leaks for “{debounced}”
                </Command.Item>
              )}
            </Command.Group>

            {leaks.length > 0 && (
              <Command.Group heading={showingRemote ? `Leaks${remote.engine ? ` (${remote.engine}, ${remote.total} total)` : ''}` : 'Open critical leaks'}>
                {leaks.map((l) => {
                  const hl = l.highlights?.[0];
                  const sub = hl ? decodeEntities(hl.replace(/<\/?mark>/g, '')) : l.snippet;
                  return (
                    <Command.Item key={`l-${l.id}`} value={`leak-${l.id} ${l.title || ''}`}
                      keywords={[debounced, l.source, l.category || '', ...(l.watch_matches || []).map((m) => m.value)].filter(Boolean)}
                      onSelect={run(() => navigate(`/leaks?id=${encodeURIComponent(l.id)}`))}>
                      <span className={`sev sev-${severityBand(l.severity)}`}>{l.severity}</span>
                      <span className="item-main">
                        <span className="item-title">{l.title || (l.snippet || '').slice(0, 80) || l.id}</span>
                        <span className="item-sub">{l.source} · {(sub || '').slice(0, 120)}</span>
                      </span>
                      <span className="item-meta">{l.status}</span>
                    </Command.Item>
                  );
                })}
              </Command.Group>
            )}
            {remote.error && <div className="cmdk-error">Search failed: {remote.error}</div>}
          </Command.List>
          <div className="cmdk-footer">
            <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
            <span><kbd>↵</kbd> select</span>
            <span><kbd>esc</kbd> close</span>
          </div>
        </Command>
      </div>
    </div>
  );
}
