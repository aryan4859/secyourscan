import React from 'react';

// Elasticsearch highlight fragments arrive HTML-escaped (encoder: "html") with
// literal <mark>…</mark> tags around hits. The content comes from breach and
// paste material, so it is hostile by default. We never hand it to innerHTML:
// the fragment is split on the two exact tag strings, every text piece has its
// entities decoded back to plain text, and React renders that text escaped.
// Only <mark> survives as an element; anything else stays inert text.

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'", '#x27': "'", '#x2F': '/', '#47': '/' };

export function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, name) => {
    if (ENTITIES[name] !== undefined) return ENTITIES[name];
    if (/^#x/i.test(name)) return safeCodePoint(parseInt(name.slice(2), 16), m);
    if (name.startsWith('#')) return safeCodePoint(parseInt(name.slice(1), 10), m);
    return m;
  });
}

function safeCodePoint(cp, fallback) {
  try {
    return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : fallback;
  } catch {
    return fallback;
  }
}

export function Highlight({ html }) {
  if (!html) return null;
  const parts = String(html).split(/(<mark>|<\/mark>)/);
  const out = [];
  let marked = false;
  parts.forEach((p, i) => {
    if (p === '<mark>') marked = true;
    else if (p === '</mark>') marked = false;
    else if (p) {
      const text = decodeEntities(p);
      out.push(marked ? <mark key={i}>{text}</mark> : <React.Fragment key={i}>{text}</React.Fragment>);
    }
  });
  return <span className="hl">{out}</span>;
}
