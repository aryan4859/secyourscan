import {
  BadgeCheck, Bot, Bug, Crosshair, FileBarChart, FileCode2, Fingerprint, Fish, Gauge, Globe, ListChecks, Moon, Network,
  Radar, ScrollText, Settings as SettingsIcon, ShieldAlert, Skull,
} from 'lucide-react';

// Grouped by the job you are doing, not by how the backend is built.
export const NAV = [
  { to: '/dashboard', label: 'Overview', group: null, icon: Gauge, keywords: ['home', 'dashboard', 'stats', 'insights'] },

  { to: '/darkweb', label: 'Dark Web', group: 'Dark Web', icon: Moon, keywords: ['darkweb', 'tor', 'onion', 'telegram', 'mentions', 'underground'] },
  { to: '/leaks', label: 'Leaks', group: 'Dark Web', icon: ShieldAlert, keywords: ['breach', 'paste', 'findings', 'search'] },
  { to: '/recon', label: 'Probes', group: 'Dark Web', icon: Crosshair, keywords: ['probe', 'dark recon', 'ahmia', 'telegram', 'shodan'] },
  { to: '/sources', label: 'Sources', group: 'Dark Web', icon: Radar, keywords: ['collectors', 'runs', 'schedule', 'feeds'] },

  { to: '/report', label: 'Exposure Report', group: 'Attack Surface', icon: FileBarChart, keywords: ['report', 'score', 'pdf', 'executive'] },
  { to: '/surface', label: 'Attack Surface', group: 'Attack Surface', icon: Globe, keywords: ['easm', 'subdomains', 'hosts', 'ports', 'tls', 'dns'] },
  { to: '/vulns', label: 'Vulnerabilities', group: 'Attack Surface', icon: Bug, keywords: ['cve', 'kev', 'epss', 'patch'] },

  { to: '/brand', label: 'Brand Protection', group: 'Brand & Threats', icon: Fish, keywords: ['lookalike', 'typosquat', 'phishing', 'takedown'] },
  { to: '/ransomware', label: 'Ransomware', group: 'Brand & Threats', icon: Skull, keywords: ['ransomware', 'leak site', 'extortion', 'groups'] },

  { to: '/watchlist', label: 'Watchlist', group: 'Assets', icon: ListChecks, keywords: ['assets', 'domains', 'emails', 'keywords', 'ip', 'wallet'] },
  { to: '/assets', label: 'Asset Exposure', group: 'Assets', icon: Fingerprint, keywords: ['identities', 'exposure', 'vip', 'score'] },
  { to: '/domains', label: 'Domains', group: 'Assets', icon: BadgeCheck, keywords: ['verify', 'verification', 'ownership', 'txt'] },

  { to: '/topology', label: 'Topology', group: 'Analysis', icon: Network, keywords: ['graph', 'network', 'map'] },
  { to: '/ai', label: 'AI Co-Analyst', group: 'Analysis', icon: Bot, keywords: ['chat', 'llm', 'assistant'] },
  { to: '/rules', label: 'Rules', group: 'Analysis', icon: FileCode2, keywords: ['yara', 'detection'] },

  { to: '/audit', label: 'Audit', group: 'Admin', icon: ScrollText, keywords: ['log', 'chain', 'history'] },
  { to: '/settings', label: 'Settings', group: 'Admin', icon: SettingsIcon, keywords: ['profile', 'password', 'users', 'api keys', 'licence'] },
];

export const NAV_GROUPS = [...new Set(NAV.map((n) => n.group).filter(Boolean))];
