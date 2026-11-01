import React from 'react';

// One corner bracket of the mark; the other three are the same path rotated.
const BRACKET = 'M0 18A18 18 0 0 1 18 0H43.2V19H28A9 9 0 0 0 19 28V43.2H0Z';

/** The SecYourScan mark: four brackets around a red target. Colours come from
 *  --logo-navy / --logo-blue / --logo-red (styles.css), tuned for the dark UI. */
export default function BrandMark({ size = 26, className = '' }) {
  return (
    <svg className={`brand-logo ${className}`} viewBox="0 0 100 100" width={size} height={size} aria-hidden="true">
      <path d={BRACKET} fill="var(--logo-navy)" />
      <path d={BRACKET} fill="var(--logo-blue)" transform="rotate(90 50 50)" />
      <path d={BRACKET} fill="var(--logo-navy)" transform="rotate(180 50 50)" />
      <path d={BRACKET} fill="var(--logo-blue)" transform="rotate(270 50 50)" />
      <path d="M50 11v17M50 72v17M11 50h17M72 50h17" stroke="var(--logo-navy)" strokeWidth="3" strokeLinecap="round" fill="none" />
      <rect x="43.5" y="43.5" width="13" height="13" rx="1.8" fill="var(--logo-red)" />
    </svg>
  );
}

/** "SecYour" in the text colour, "Scan" in brand blue, as in the artwork. */
export function Wordmark() {
  return <span className="brand-name">SecYour<span className="brand-accent">Scan</span></span>;
}
