import React, { useCallback, useEffect, useState } from 'react';
import { HashRouter, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { ChevronRight, LogOut, Menu, Radar, Search, X } from 'lucide-react';
import { NAV, NAV_GROUPS } from './nav';
import { api, onUnauthorized } from './api';
import { SessionCtx, useSession } from './session';
import CommandMenu from './CommandMenu';
import DossierDialog from './components/DossierDialog';
import NotificationsBell from './components/NotificationsBell';
import { Spinner, ToastProvider } from './components/ui';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Leaks from './pages/Leaks';
import DarkWeb from './pages/DarkWeb';
import Watchlist from './pages/Watchlist';
import Sources from './pages/Sources';
import AiAnalyst from './pages/AiAnalyst';
import Topology from './pages/Topology';
import Assets from './pages/Assets';
import Recon from './pages/Recon';
import Domains from './pages/Domains';
import Report from './pages/Report';
import Surface from './pages/Surface';
import Vulns from './pages/Vulns';
import Brand from './pages/Brand';
import Ransomware from './pages/Ransomware';
import Rules from './pages/Rules';
import Audit from './pages/Audit';
import Settings from './pages/Settings';

export default function App() {
  const [user, setUser] = useState(undefined); // undefined = checking, null = signed out

  const restore = useCallback(async () => {
    try {
      setUser(await api.me());
    } catch {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    onUnauthorized(() => setUser(null));
    restore();
  }, [restore]);

  if (user === undefined) {
    return <div className="boot"><Spinner label="Restoring session…" /></div>;
  }

  return (
    <ToastProvider>
      {user === null ? (
        <Login onLoggedIn={restore} />
      ) : (
        <HashRouter>
          <SessionCtx.Provider value={{ user, setUser, refreshUser: restore }}>
            <Shell />
          </SessionCtx.Provider>
        </HashRouter>
      )}
    </ToastProvider>
  );
}

const NAV_KEY = 'sys:nav-open-groups';

function readOpenGroups() {
  try {
    return new Set(JSON.parse(localStorage.getItem(NAV_KEY) || '[]'));
  } catch {
    return new Set();
  }
}

function Shell() {
  const { user, setUser } = useSession();
  const [navOpen, setNavOpen] = useState(false);
  const [dossierOpen, setDossierOpen] = useState(false);
  const [openGroups, setOpenGroups] = useState(readOpenGroups);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => { setNavOpen(false); }, [location.pathname]);

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
    }
  };

  const page = NAV.find((n) => location.pathname.startsWith(n.to)) || NAV[0];
  const initials = (user.full_name || user.email || '?').trim()[0].toUpperCase();
  const toggleGroup = (g) => setOpenGroups((cur) => {
    const next = new Set(cur);
    if (next.has(g)) next.delete(g); else next.add(g);
    try { localStorage.setItem(NAV_KEY, JSON.stringify([...next])); } catch { /* private mode */ }
    return next;
  });
  const link = ({ to, label, icon: Icon }) => (
    <NavLink key={to} to={to} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
      <Icon size={16} /> <span>{label}</span>
    </NavLink>
  );

  return (
    <div className={`shell ${navOpen ? 'nav-open' : ''}`}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Radar size={16} /></span>
          <span className="brand-name">SecYourScan</span>
          <button className="icon-btn nav-close" onClick={() => setNavOpen(false)} aria-label="Close menu"><X size={18} /></button>
        </div>
        <nav>
          {NAV.filter((n) => !n.group).map(link)}
          {NAV_GROUPS.map((g) => {
            const items = NAV.filter((n) => n.group === g);
            const here = items.some((n) => location.pathname.startsWith(n.to));
            const open = here || openGroups.has(g);
            return (
              <div key={g} className="nav-section">
                <button className={`nav-group ${here ? 'here' : ''}`} onClick={() => toggleGroup(g)} aria-expanded={open}>
                  <ChevronRight size={13} className={`nav-chevron ${open ? 'open' : ''}`} /> {g}
                </button>
                {open && <div className="nav-items">{items.map(link)}</div>}
              </div>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <span className="avatar">{initials}</span>
          <div className="who">
            <div className="who-name">{user.full_name || user.email}</div>
            <div className="who-sub">{user.tenant_name}</div>
          </div>
          <button className="icon-btn" onClick={logout} aria-label="Sign out" title="Sign out"><LogOut size={15} /></button>
        </div>
      </aside>
      <div className="nav-scrim" onClick={() => setNavOpen(false)} />

      <div className="main">
        <header className="topbar">
          <button className="icon-btn nav-toggle" onClick={() => setNavOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
          <div className="topbar-title">
            {page.group && <span className="crumb">{page.group}</span>}
            <span>{page.label}</span>
          </div>
          <div className="topbar-right">
            <StatusDot />
            <button className="search-trigger" onClick={() => window.dispatchEvent(new Event('sys:open-command'))}>
              <Search size={14} /> <span>Search</span> <kbd>Ctrl K</kbd>
            </button>
            <NotificationsBell />
          </div>
        </header>
        <main className="content">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/darkweb" element={<DarkWeb />} />
            <Route path="/leaks" element={<Leaks onDossier={() => setDossierOpen(true)} />} />
            <Route path="/watchlist" element={<Watchlist />} />
            <Route path="/sources" element={<Sources />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/recon" element={<Recon />} />
            <Route path="/domains" element={<Domains />} />
            <Route path="/report" element={<Report />} />
            <Route path="/surface" element={<Surface />} />
            <Route path="/vulns" element={<Vulns />} />
            <Route path="/brand" element={<Brand />} />
            <Route path="/ransomware" element={<Ransomware />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="/ai" element={<AiAnalyst />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>

      <CommandMenu navigate={navigate} onDossier={() => setDossierOpen(true)} />
      {dossierOpen && <DossierDialog onClose={() => setDossierOpen(false)} />}
    </div>
  );
}

/** One dot for platform health; latency and state on hover. Polled every 30 s. */
function StatusDot() {
  const [st, setSt] = useState(null);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const t0 = performance.now();
      try {
        const r = await api.status();
        if (alive) setSt({ ok: r.status === 'operational', ms: Math.round(performance.now() - t0) });
      } catch {
        if (alive) setSt({ ok: false, ms: null });
      }
    };
    tick();
    const t = setInterval(() => document.visibilityState === 'visible' && tick(), 30_000);
    return () => { alive = false; clearInterval(t); };
  }, []);
  if (!st) return null;
  return (
    <span className={`status-dot ${st.ok ? 'ok' : 'bad'}`} title={st.ok ? `Operational · ${st.ms} ms` : 'Degraded: check System health'}>
      <span /> {st.ok ? 'Operational' : 'Degraded'}
    </span>
  );
}
