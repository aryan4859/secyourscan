export function num(n) {
  const v = typeof n === 'string' ? Number(n.replace(/,/g, '')) : n;
  return Number.isFinite(v) ? v : 0;
}

/** 11717192990 → { value: 11.7, unit: 'billion' } */
export function bigParts(n) {
  const v = num(n);
  if (v >= 1e9) return { value: Math.round(v / 1e8) / 10, unit: 'billion' };
  if (v >= 1e6) return { value: Math.round(v / 1e5) / 10, unit: 'million' };
  return { value: v, unit: '' };
}

export function big(n) {
  const { value, unit } = bigParts(n);
  return unit ? `${value} ${unit}` : value.toLocaleString('en-US');
}

export const comma = (n) => num(n).toLocaleString('en-US');

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** ISO dates, "2024-Apr-13" and "01-Aug-2026". */
export function parseDate(s) {
  if (!s) return null;
  let m = /^(\d{4})-([A-Za-z]{3})-(\d{1,2})$/.exec(s);
  if (m) return new Date(Date.UTC(+m[1], MONTHS[m[2].toLowerCase()], +m[3]));
  m = /^(\d{1,2})-([A-Za-z]{3})-(\d{4})$/.exec(s);
  if (m) return new Date(Date.UTC(+m[3], MONTHS[m[2].toLowerCase()], +m[1]));
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function fmtDate(s, opts = { day: 'numeric', month: 'short', year: 'numeric' }) {
  const d = parseDate(s);
  return d ? d.toLocaleDateString('en-GB', { ...opts, timeZone: 'UTC' }) : '—';
}

export const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);
export const isDomain = (s) => /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(s);

export const SENSITIVE = /password|government|credit|bank|social security|passport|health|security question|maiden|biometric|private message/i;

export const PASSWORD_RISK = {
  plaintext: ['Plain text', true],
  easytocrack: ['Weak hash', true],
  hardtocrack: ['Strong hash', false],
  unknown: ['Unknown', false],
};

/** Breach-news summaries come with feed noise ("XposedOrNot += …", hashtags). */
export const tidySummary = (s) => String(s || '').replace(/\s+/g, ' ').replace(/^XposedOrNot \+=\s*/, '').replace(/#(\w)/g, '$1').trim();
