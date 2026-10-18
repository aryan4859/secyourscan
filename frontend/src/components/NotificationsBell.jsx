import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Check } from 'lucide-react';
import { api } from '../api';
import { relTime, useToast } from './ui';

const POLL_MS = 30_000;

export default function NotificationsBell() {
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState(null);
  const ref = useRef(null);
  const navigate = useNavigate();
  const toast = useToast();

  const load = useCallback(async () => {
    try {
      const rows = await api.notifications({ unacknowledged: true, limit: 50 });
      setItems(rows || []);
      setError(null);
    } catch (e) {
      setError(e);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') load();
    }, POLL_MS);
    const refresh = () => load();
    window.addEventListener('sys:notifications-changed', refresh);
    return () => {
      clearInterval(t);
      window.removeEventListener('sys:notifications-changed', refresh);
    };
  }, [load]);

  useEffect(() => {
    if (!open) return undefined;
    const h = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false);
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);

  const ack = async (n) => {
    try {
      await api.ackNotification(n.id);
      setItems((xs) => xs.filter((x) => x.id !== n.id));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div className="bell" ref={ref}>
      <button className="icon-btn" onClick={() => setOpen((v) => !v)} aria-label={`Notifications (${items.length} unacknowledged)`}>
        <Bell size={18} />
        {items.length > 0 && <span className="bell-count">{items.length > 99 ? '99+' : items.length}</span>}
      </button>
      {open && (
        <div className="bell-panel">
          <div className="bell-head">Unacknowledged alerts</div>
          {error && <div className="bell-empty error-text">{error.message}</div>}
          {!error && items.length === 0 && <div className="bell-empty">All caught up.</div>}
          <ul>
            {items.map((n) => (
              <li key={n.id} className={`bell-item lvl-${n.level}`}>
                <button className="bell-main" onClick={() => {
                  setOpen(false);
                  if (n.leak_id) navigate(`/leaks?id=${encodeURIComponent(n.leak_id)}`);
                }}>
                  <span className="bell-title">{n.title}</span>
                  {n.body && <span className="bell-body">{n.body}</span>}
                  <span className="bell-time">{n.level} · {relTime(n.created_at)}</span>
                </button>
                <button className="icon-btn" title="Acknowledge" onClick={() => ack(n)}><Check size={16} /></button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
