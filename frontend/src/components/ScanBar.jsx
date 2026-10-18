import React, { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, Loader2, Play, XCircle } from 'lucide-react';
import { api } from '../api';
import { relTime, useToast } from './ui';

/**
 * Last-scan status for one external-risk module plus a "Scan now" button.
 * Polls /intel/status every 3 s while the scan is queued or running and calls
 * onFinished once it completes, so the page can reload its data.
 */
export default function ScanBar({ module, label, onFinished, extraModule }) {
  const [st, setSt] = useState(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const timer = useRef(null);
  const wasActive = useRef(false);

  const load = useCallback(async () => {
    try {
      const all = await api.intelStatus();
      const s = all[module] || { status: 'never' };
      const extra = extraModule ? all[extraModule] : null;
      const active = ['queued', 'running'].includes(s.status) || (extra && ['queued', 'running'].includes(extra.status));
      setSt(s);
      if (wasActive.current && !active) onFinished?.(s);
      wasActive.current = active;
      clearTimeout(timer.current);
      if (active) timer.current = setTimeout(load, 3000);
    } catch {
      /* the page shows its own errors */
    }
  }, [module, extraModule, onFinished]);

  useEffect(() => {
    load();
    return () => clearTimeout(timer.current);
  }, [load]);

  const start = async () => {
    setBusy(true);
    try {
      await api.intelScan(module);
      toast(`${label} scan started`, 'ok');
      wasActive.current = true;
      await load();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const active = st && ['queued', 'running'].includes(st.status);
  return (
    <div className="scanbar">
      <span className="scanbar-status">
        {!st ? null : active ? (
          <span className="warn-text"><Loader2 size={13} className="spin" /> Scan {st.status}…</span>
        ) : st.status === 'ok' ? (
          <span className="chain-ok"><CheckCircle2 size={13} /> Last scan {relTime(st.finished_at)}</span>
        ) : st.status === 'error' ? (
          <span className="chain-bad" title={st.error}><XCircle size={13} /> Last scan failed</span>
        ) : (
          <span className="faint">Never scanned</span>
        )}
      </span>
      <button className="btn btn-primary" onClick={start} disabled={busy || active}>
        {active ? <Loader2 size={14} className="spin" /> : <Play size={14} />} Scan now
      </button>
    </div>
  );
}
