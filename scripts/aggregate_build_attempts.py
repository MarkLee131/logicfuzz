#!/usr/bin/env python3
"""Aggregate per-trial build_attempts.json into per-error-class fix curves.

Purpose
-------
This script feeds the data needed to *calibrate* the per-class retry
budget in src/workflow/nodes/supervisor.py (currently set conservatively
to MAX_COMPILATION_RETRIES=2 across all classes — see the self-review
in conversation history). The right budget per class should be the
attempt-index at which the marginal fix-success drops below noise. This
script produces the cumulative CDF needed to read that off.

Input
-----
Walks --root looking for files named "build_attempts.json" (written by
run_single_fuzz._fuzzing_pipeline; one file per trial, see
src/workflow/state.py:build_attempts).

Each record has the shape (excerpt — see execution.py for the full set):
  {
    "attempt_idx": int,      # 0-based, monotonically increases per trial
    "phase": "compilation" | "optimization",
    "compile_success": bool,
    "binary_exists": bool,
    "primary_category": str | null,   # ErrorCategory.name on failure
    "categories": dict[str, int],
    "fixer_calls_before": int,
    "compilation_retry_count": int,
  }

Output
------
By default, prints a markdown table on stdout. With --json, dumps the
aggregated structure for further analysis.

The key derived metric is **success-by-attempt** per category: among
trials whose first failure was in category X, what fraction succeeded
on attempt 1, 2, …, k? The 95th-percentile attempt index is the
suggested retry budget for that class.

Usage
-----
  python3 scripts/aggregate_build_attempts.py results
  python3 scripts/aggregate_build_attempts.py results --json out.json
  python3 scripts/aggregate_build_attempts.py results --min-trials 5
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional


def _walk_attempts(root: Path) -> List[dict]:
    """Yield (file_path, parsed) for every build_attempts.json under root."""
    out = []
    for path in root.rglob('build_attempts.json'):
        try:
            with path.open() as f:
                data = json.load(f)
            out.append((path, data))
        except (json.JSONDecodeError, OSError) as exc:
            print(f'warn: failed to read {path}: {exc}', file=sys.stderr)
    return out


def _derive_first_failure_category(attempts: List[dict]) -> Optional[str]:
    """Return the primary_category of the FIRST failing attempt, or None
    if the trial never failed."""
    for a in attempts:
        if a.get('compile_success') is False:
            return a.get('primary_category')
    return None


def _trial_succeeded(attempts: List[dict]) -> bool:
    """A trial 'succeeded' iff any build attempt produced a binary."""
    return any(a.get('compile_success') for a in attempts)


def _attempts_until_success(attempts: List[dict]) -> Optional[int]:
    """Return the 1-indexed attempt at which the first success occurred,
    or None if the trial never succeeded.

    Note: attempt_idx is 0-based in the records; we report 1-based here
    so a "budget of 5" means "five attempts allowed" rather than "indices
    0..4".
    """
    for a in attempts:
        if a.get('compile_success'):
            return a.get('attempt_idx', 0) + 1
    return None


def aggregate(per_trial: List[dict]) -> dict:
    """Per-class CDF aggregation."""
    # category → list[attempt_count_to_success | None]
    by_first_failure: Dict[str, List[Optional[int]]] = defaultdict(list)
    overall = {
        'total_trials': 0,
        'total_attempts': 0,
        'compile_success_count': 0,
        'never_failed_trials': 0,
    }

    for trial in per_trial:
        attempts = trial.get('attempts', [])
        if not attempts:
            continue
        overall['total_trials'] += 1
        overall['total_attempts'] += len(attempts)
        first_fail_cat = _derive_first_failure_category(attempts)
        succeeded = _trial_succeeded(attempts)
        if succeeded:
            overall['compile_success_count'] += 1
        if first_fail_cat is None:
            overall['never_failed_trials'] += 1
            continue
        by_first_failure[first_fail_cat].append(_attempts_until_success(attempts))

    per_class = {}
    for cat, outcomes in sorted(by_first_failure.items()):
        n = len(outcomes)
        succ = [o for o in outcomes if o is not None]
        # CDF: at attempt k, what fraction of the n trials had succeeded?
        max_k = max(succ, default=0)
        cdf = []
        for k in range(1, max_k + 1):
            count = sum(1 for o in succ if o <= k)
            cdf.append({'attempt': k, 'fraction': count / n if n else 0.0})
        # Suggested budget: smallest k where ≥ 95% of *successful* outcomes
        # are reached, capped at the largest observed attempt. If no trials
        # ever succeed in this class, return None (signal: maybe genuine
        # FAKE / LANG mismatch — don't waste retries).
        suggested = None
        if succ:
            target = 0.95 * len(succ)
            running = 0
            for k in range(1, max_k + 1):
                running += sum(1 for o in succ if o == k)
                if running >= target:
                    suggested = k
                    break
            if suggested is None:
                suggested = max_k
        per_class[cat] = {
            'n_trials_first_failed_here': n,
            'n_eventually_succeeded': len(succ),
            'success_rate': (len(succ) / n) if n else 0.0,
            'cdf': cdf,
            'suggested_budget_p95': suggested,
        }

    return {'overall': overall, 'per_class': per_class}


def render_markdown(agg: dict, min_trials: int = 1) -> str:
    overall = agg['overall']
    lines = ['# Build Attempts Aggregation', '']
    lines.append(f"- Trials seen: **{overall['total_trials']}**, "
                 f"build attempts: {overall['total_attempts']}")
    if overall['total_trials']:
        rate = overall['compile_success_count'] / overall['total_trials']
        lines.append(f"- Trials reaching binary: "
                     f"**{overall['compile_success_count']}** "
                     f"({rate:.1%}); never-failed: "
                     f"{overall['never_failed_trials']}")
    lines.append('')
    lines.append('## Per-class success curve')
    lines.append('')
    lines.append('| Category | n (first-failed here) | succeeded | rate | '
                 'suggested budget (p95) |')
    lines.append('|---|---|---|---|---|')
    for cat, st in sorted(agg['per_class'].items(),
                          key=lambda kv: -kv[1]['n_trials_first_failed_here']):
        if st['n_trials_first_failed_here'] < min_trials:
            continue
        budget = st['suggested_budget_p95']
        budget_str = str(budget) if budget is not None else 'never_succeeded'
        lines.append(f"| {cat} | {st['n_trials_first_failed_here']} | "
                     f"{st['n_eventually_succeeded']} | "
                     f"{st['success_rate']:.1%} | {budget_str} |")
    lines.append('')
    lines.append('## CDF (fraction succeeded by attempt k, of trials that '
                 'first failed in this class)')
    lines.append('')
    for cat, st in sorted(agg['per_class'].items()):
        if st['n_trials_first_failed_here'] < min_trials:
            continue
        cdf_str = ' → '.join(
            f"k={p['attempt']}:{p['fraction']:.0%}" for p in st['cdf']) or '(no successes)'
        lines.append(f"- **{cat}**: {cdf_str}")
    return '\n'.join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('root', type=Path,
                   help='Directory to walk for build_attempts.json '
                        '(usually results/)')
    p.add_argument('--json', type=Path, default=None,
                   help='If given, dump the aggregation as JSON to this path '
                        '(in addition to the markdown summary on stdout).')
    p.add_argument('--min-trials', type=int, default=1,
                   help='Hide categories with fewer than this many trials in '
                        'the rendered table (default: 1, recommended: 3-5 '
                        'for stable budget calibration).')
    args = p.parse_args(argv)

    if not args.root.exists():
        print(f'error: {args.root} does not exist', file=sys.stderr)
        return 1

    found = _walk_attempts(args.root)
    if not found:
        print(f'no build_attempts.json found under {args.root}', file=sys.stderr)
        return 1

    print(f'# Found {len(found)} build_attempts.json file(s) under {args.root}',
          file=sys.stderr)

    per_trial = [data for _path, data in found]
    agg = aggregate(per_trial)

    if args.json:
        with args.json.open('w') as f:
            json.dump(agg, f, indent=2)
        print(f'wrote aggregated JSON: {args.json}', file=sys.stderr)

    print(render_markdown(agg, min_trials=args.min_trials))
    return 0


if __name__ == '__main__':
    sys.exit(main())
