import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Check, ChevronDown, ChevronRight, Copy, Inbox, Loader2, X } from 'lucide-react';

// ── Formatting ───────────────────────────────────────────────────────────────

export function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') || /[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

export function relTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') || /[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`);
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (Number.isNaN(s)) return iso;
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function severityBand(sev) {
  if (sev == null) return 'info';
  if (sev >= 80) return 'critical';
  if (sev >= 60) return 'high';
  if (sev >= 30) return 'medium';
  return 'low';
}

export const STATUSES = ['new', 'reviewing', 'escalated', 'resolved', 'false_positive'];
export const statusLabel = (s) => (s || '').replace(/_/g, ' ');

// ── Small presentational pieces ─────────────────────────────────────────────

export function SeverityBadge({ value }) {
  const band = severityBand(value);
  return (
    <span className={`sev sev-${band}`} title={`Severity ${value ?? 'n/a'} (${band})`}>
      {value ?? '–'} <span className="sev-band">{band}</span>
    </span>
  );
}

export function StatusPill({ status }) {
  return <span className={`pill st-${status}`}>{statusLabel(status)}</span>;
}

export function Pill({ children, tone = 'default', title }) {
  return <span className={`pill tone-${tone}`} title={title}>{children}</span>;
}

export function Spinner({ label = 'Loading…', inline = false }) {
  return (
    <div className={inline ? 'spinner inline' : 'spinner'} role="status">
      <Loader2 size={16} className="spin" /> <span>{label}</span>
    </div>
  );
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null;
  const msg = typeof error === 'string' ? error : error.message || String(error);
  return (
    <div className="error-box" role="alert">
      <AlertTriangle size={16} />
      <span>{msg}</span>
      {onRetry && <button className="btn btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Empty({ title = 'Nothing here yet', children }) {
  return (
    <div className="empty">
      <Inbox size={22} />
      <div className="empty-title">{title}</div>
      {children && <div className="empty-sub">{children}</div>}
    </div>
  );
}

export function Card({ title, actions, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <h2>{title}</h2>
          <div className="card-actions">{actions}</div>
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Toggle({ checked, onChange, label, disabled }) {
  return (
    <label className={`toggle ${disabled ? 'disabled' : ''}`}>
      <input type="checkbox" checked={!!checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="toggle-track"><span className="toggle-thumb" /></span>
      {label && <span className="toggle-label">{label}</span>}
    </label>
  );
}

export function CopyButton({ text, label = 'Copy' }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    setDone(true);
    setTimeout(() => setDone(false), 1500);
  };
  return (
    <button type="button" className="btn btn-sm" onClick={copy}>
      {done ? <Check size={14} /> : <Copy size={14} />} {done ? 'Copied' : label}
    </button>
  );
}

/** Collapsible JSON viewer. Values are rendered as text, never as HTML. */
export function JsonView({ data, title, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  let text;
  try {
    text = JSON.stringify(data, null, 2);
  } catch {
    text = String(data);
  }
  if (!title) return <pre className="json">{text}</pre>;
  return (
    <div className="json-block">
      <button type="button" className="json-toggle" onClick={() => setOpen((v) => !v)}>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />} {title}
      </button>
      {open && <pre className="json">{text}</pre>}
    </div>
  );
}

export function KV({ rows }) {
  return (
    <dl className="kv">
      {rows.filter(Boolean).map(([k, v]) => (
        <React.Fragment key={k}>
          <dt>{k}</dt>
          <dd>{v ?? '—'}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

// ── Overlays ─────────────────────────────────────────────────────────────────

function useEscape(onClose) {
  useEffect(() => {
    const h = (e) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [onClose]);
}

export function Modal({ title, onClose, children, footer, wide = false }) {
  useEscape(onClose);
  return (
    <div className="overlay" onMouseDown={onClose}>
      <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}>
        <header className="modal-head">
          <h3>{title}</h3>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children, actions }) {
  useEscape(onClose);
  return (
    <div className="overlay drawer-overlay" onMouseDown={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title} onMouseDown={(e) => e.stopPropagation()}>
        <header className="drawer-head">
          <h3>{title}</h3>
          <div className="drawer-actions">
            {actions}
            <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={18} /></button>
          </div>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

/** Confirmation that requires typing an exact phrase. */
export function TypedConfirm({ title, phrase, message, confirmLabel = 'Delete', onConfirm, onClose }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const go = async () => {
    setBusy(true);
    setErr(null);
    try {
      await onConfirm();
      onClose();
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };
  return (
    <Modal title={title} onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-danger" disabled={typed !== phrase || busy} onClick={go}>
          {busy ? 'Working…' : confirmLabel}
        </button>
      </>
    }>
      <p>{message}</p>
      <p>Type <code>{phrase}</code> to confirm.</p>
      <input className="input" autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} />
      <ErrorBox error={err} />
    </Modal>
  );
}

// ── Toasts ───────────────────────────────────────────────────────────────────

const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const seq = useRef(0);
  const push = useCallback((message, tone = 'info') => {
    const id = ++seq.current;
    setToasts((t) => [...t, { id, message, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === 'error' ? 7000 : 4000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.tone}`}>{t.message}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

// ── Data hook ────────────────────────────────────────────────────────────────

/** useAsync(fn, deps) → { data, error, loading, reload, setData } */
export function useAsync(fn, deps = []) {
  const [state, setState] = useState({ data: undefined, error: null, loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    Promise.resolve()
      .then(fn)
      .then((data) => alive && setState({ data, error: null, loading: false }))
      .catch((error) => alive && error?.name !== 'AbortError' && setState((s) => ({ ...s, error, loading: false })));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  const setData = useCallback((updater) => setState((s) => ({ ...s, data: typeof updater === 'function' ? updater(s.data) : updater })), []);
  return { ...state, reload, setData };
}
