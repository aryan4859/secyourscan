'use client';

import { motion, useReducedMotion } from 'motion/react';

const SIZE = 440;
const C = SIZE / 2;
const PERIOD = 9; // seconds per sweep
const PAD = 120; // room for labels either side

/** Stable pseudo-random number in [0, 1) from a string, so blips don't jump between renders. */
function hash(s, salt) {
  let h = 2166136261 ^ salt;
  for (let i = 0; i < s.length; i += 1) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return ((h >>> 0) % 10000) / 10000;
}

/**
 * A quiet radar: one sweep, a few blips. Each blip is one of the newest
 * breaches in the index and brightens as the sweep passes over it.
 */
export default function Radar({ items = [] }) {
  const reduce = useReducedMotion();
  const blips = items.slice(0, 7).map((name, i) => {
    const angle = (hash(name, 1) * 300 + i * 51) % 360; // degrees, clockwise from 12 o'clock
    const r = 70 + hash(name, 2) * 120;
    const rad = (angle * Math.PI) / 180;
    return { name, angle, x: C + r * Math.sin(rad), y: C - r * Math.cos(rad) };
  });

  return (
    <div className="radar" aria-hidden="true">
      {/* horizontal padding in the viewBox keeps blip labels inside the box, never over the copy */}
      <svg viewBox={`${-PAD} 0 ${SIZE + PAD * 2} ${SIZE}`}>
        <defs>
          <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="var(--accent)" stopOpacity="0" />
            <stop offset="1" stopColor="var(--accent)" stopOpacity="0.22" />
          </linearGradient>
        </defs>
        {[70, 130, 190].map((r) => <circle key={r} cx={C} cy={C} r={r} className="ring" />)}
        <line x1={C} y1={C - 205} x2={C} y2={C + 205} className="axis" />
        <line x1={C - 205} y1={C} x2={C + 205} y2={C} className="axis" />

        <motion.g style={{ originX: '50%', originY: '50%' }}
          animate={reduce ? undefined : { rotate: 360 }}
          transition={{ duration: PERIOD, ease: 'linear', repeat: Infinity }}>
          {/* invisible full circle: makes the group's box centred, so it rotates about the radar centre */}
          <circle cx={C} cy={C} r="190" fill="none" stroke="none" />
          {/* a 40° wedge trailing the leading edge, which points at 12 o'clock */}
          <path d={`M${C},${C} L${C - 190 * Math.sin(40 * Math.PI / 180)},${C - 190 * Math.cos(40 * Math.PI / 180)} A190,190 0 0,1 ${C},${C - 190} Z`}
            fill="url(#sweep)" />
          <line x1={C} y1={C} x2={C} y2={C - 190} className="beam" />
        </motion.g>

        {blips.map((b, i) => (
          <motion.g key={b.name}
            initial={{ opacity: 0 }}
            animate={reduce ? { opacity: 1 } : { opacity: [1, 0.18] }}
            transition={reduce ? { duration: 0.6, delay: 0.3 + i * 0.1 } : {
              duration: PERIOD, ease: [0.1, 0.6, 0.3, 1], repeat: Infinity, delay: (b.angle / 360) * PERIOD,
            }}>
            <circle cx={b.x} cy={b.y} r="3.5" className="blip" />
            <circle cx={b.x} cy={b.y} r="9" className="blip-halo" />
            <text x={b.x + (b.x > C ? 12 : -12)} y={b.y + 4} textAnchor={b.x > C ? 'start' : 'end'} className="blip-label">{b.name}</text>
          </motion.g>
        ))}
        <circle cx={C} cy={C} r="3" className="center" />
      </svg>
    </div>
  );
}
