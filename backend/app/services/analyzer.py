"""YARA engine: static rules from ``app/rules`` plus active rules from the
database, compiled together and recompiled only when the rule set changes."""

import logging
from pathlib import Path

try:
    import yara
except ImportError:  # pragma: no cover — the image always has it
    yara = None

logger = logging.getLogger("secyourscan.yara")

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_MAX_SCAN_BYTES = 8 * 1024 * 1024


def validate_rule(source: str) -> str | None:
    """Return an error message, or None if the rule compiles."""
    if yara is None:
        return "yara-python is not installed"
    try:
        yara.compile(source=source, includes=False)
    except yara.Error as exc:
        return str(exc)
    return None


class Analyzer:
    def __init__(self) -> None:
        self.static_sources = {
            f"static_{p.stem}": p.read_text(encoding="utf-8") for p in sorted(RULES_DIR.glob("*.yar"))
        }
        self.dynamic_sources: dict[str, str] = {}
        self.version = 0
        self._compiled = self._compile()

    def _compile(self):
        if yara is None:
            return None
        sources = {**self.static_sources, **self.dynamic_sources}
        try:
            return yara.compile(sources=sources, includes=False)
        except yara.Error as exc:
            # One broken custom rule must not disable the static set.
            logger.error("YARA compile failed (%s); falling back to static rules", exc)
            return yara.compile(sources=self.static_sources, includes=False)

    @staticmethod
    def namespace(tenant_id: str | None, name: str) -> str:
        safe = "".join(c if c.isalnum() else "_" for c in name)
        return f"dyn_{(tenant_id or 'global').replace('-', '')}_{safe}"

    def refresh(self, rules: list[tuple[str | None, str, str]]) -> None:
        """``rules`` is ``[(tenant_id, name, source), ...]``."""
        new = {self.namespace(t, n): src for t, n, src in rules}
        if new == self.dynamic_sources:
            return
        self.dynamic_sources = new
        self._compiled = self._compile()
        self.version += 1
        logger.info("YARA ruleset recompiled (v%s, %s custom rules)", self.version, len(new))

    def analyze(self, text: str, tenant_id: str | None = None) -> tuple[list[dict], int]:
        """Match static rules, global custom rules and this tenant's rules —
        never another tenant's."""
        if self._compiled is None:
            return [], 0
        data = text.encode("utf-8", "ignore")[:_MAX_SCAN_BYTES]
        try:
            matches = self._compiled.match(data=data, timeout=30)
        except yara.Error as exc:
            logger.warning("YARA match failed: %s", exc)
            return [], 0
        allowed = ("static_", "dyn_global_", f"dyn_{(tenant_id or 'global').replace('-', '')}_")
        results, score = [], 0
        for m in matches:
            if not m.namespace.startswith(allowed):
                continue
            meta = dict(m.meta)
            rule_score = int(meta.get("score", 10))
            score += rule_score
            results.append(
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "description": meta.get("description"),
                    "category": meta.get("category"),
                    "score": rule_score,
                }
            )
        return results, min(score, 100)


analyzer = Analyzer()
