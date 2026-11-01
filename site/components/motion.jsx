'use client';

// Small motion vocabulary used across the site. One easing curve, short
// durations, everything plays once. MotionConfig(reducedMotion="user") turns
// transforms off for visitors who ask for less motion.

import { Fragment, useEffect, useRef } from 'react';
import { MotionConfig, animate, motion, useInView, useReducedMotion } from 'motion/react';

export const EASE = [0.22, 1, 0.36, 1];

export function Providers({ children }) {
  return <MotionConfig reducedMotion="user" transition={{ ease: EASE }}>{children}</MotionConfig>;
}

/** Fade + rise into view, once. */
export function Reveal({ children, delay = 0, y = 14, as = 'div', className, style }) {
  const Tag = motion[as];
  return (
    <Tag className={className} style={style} initial={{ opacity: 0, y }} whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '0px 0px -8% 0px' }} transition={{ duration: 0.7, delay, ease: EASE }}>
      {children}
    </Tag>
  );
}

/** Headline that rises in word by word. */
export function WordsUp({ text, as = 'h1', className, delay = 0, onView = false }) {
  const Tag = motion[as];
  const words = text.split(' ');
  const play = onView ? { whileInView: 'show', viewport: { once: true, margin: '0px 0px -10% 0px' } } : { animate: 'show' };
  return (
    <Tag className={className} aria-label={text} initial="hidden" {...play}
      variants={{ show: { transition: { staggerChildren: 0.06, delayChildren: delay } } }}>
      {words.map((w, i) => (
        <Fragment key={i}>
          <span className="word-mask" aria-hidden="true">
            <motion.span className="word" variants={{ hidden: { y: '105%' }, show: { y: '0%', transition: { duration: 0.8, ease: EASE } } }}>
              {w}
            </motion.span>
          </span>
          {/* the space must sit outside the clipped inline-block, or it collapses */}
          {i < words.length - 1 ? ' ' : null}
        </Fragment>
      ))}
    </Tag>
  );
}

/** Counts from 0 to `value` when scrolled into view. Renders the final value on the server. */
export function CountUp({ value, decimals = 0, duration = 1.4, className }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: '0px 0px -5% 0px' });
  const reduce = useReducedMotion();
  const fmt = (v) => v.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });

  useEffect(() => {
    if (!inView || reduce || !ref.current) return undefined;
    const node = ref.current;
    const controls = animate(0, value, {
      duration, ease: EASE,
      onUpdate: (v) => { node.textContent = fmt(v); },
    });
    return () => controls.stop();
  }, [inView, reduce, value]); // eslint-disable-line react-hooks/exhaustive-deps

  return <span ref={ref} className={className}>{fmt(value)}</span>;
}

/** A bar that grows to `pct` (0–100) when it enters the view. */
export function GrowBar({ pct, delay = 0, className = 'fill', style, axis = 'x' }) {
  const prop = axis === 'x' ? 'width' : 'height';
  return (
    <motion.span className={className} style={style}
      initial={{ [prop]: '0%' }} whileInView={{ [prop]: `${pct}%` }}
      viewport={{ once: true }} transition={{ duration: 0.9, delay, ease: EASE }} />
  );
}
