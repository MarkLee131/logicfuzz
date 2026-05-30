"""Coverage-diff of our generated portfolio vs the human OSS-Fuzz suite.

Usage: python scripts/cov_diff.py <project> [YYYYMMDD]

Human baseline = union of the project's human fuzzer covreports from the public
oss-fuzz-coverage bucket. Ours = union of our per-driver covreports. Diff via
experiment/textcov.Textcov.subtract_covered_lines (same metric as oss-fuzz-gen):
  WE_NEW   = ours - human   (lines humans never tested)
  HUMAN_NEW= human - ours   (lines we miss)
  recall   = OVERLAP / human
"""
import json
import glob
import urllib.request
import copy
import os
import sys

sys.path.insert(0, os.getcwd())
from experiment import textcov  # noqa: E402


def our(proj):
    out = textcov.Textcov()
    n = 0
    for f in glob.glob(
            f'results/output-{proj}-project/code-coverage-reports/*/textcov/*.covreport'):
        with open(f, 'rb') as fh:
            out.merge(textcov.Textcov.from_file(fh))
        n += 1
    return out, n


def human(proj, date):
    items = json.loads(urllib.request.urlopen(
        'https://storage.googleapis.com/storage/v1/b/oss-fuzz-coverage/o'
        f'?prefix={proj}/textcov_reports/{date}/&maxResults=200').read()
    ).get('items', [])
    out = textcov.Textcov()
    for it in items:
        name = it['name']
        if not name.endswith('.covreport'):
            continue
        dst = f'/tmp/{proj}__{name.split("/")[-1]}'
        if not os.path.exists(dst):
            urllib.request.urlretrieve(
                f'https://storage.googleapis.com/oss-fuzz-coverage/{name}', dst)
        with open(dst, 'rb') as fh:
            out.merge(textcov.Textcov.from_file(fh))
    return out


def main():
    proj = sys.argv[1]
    date = sys.argv[2] if len(sys.argv) > 2 else '20260530'
    o, n = our(proj)
    h = human(proj, date)
    we_new = copy.deepcopy(o)
    we_new.subtract_covered_lines(h)
    h_new = copy.deepcopy(h)
    h_new.subtract_covered_lines(o)
    overlap = o.covered_lines - we_new.covered_lines
    recall = 100 * overlap / h.covered_lines if h.covered_lines else 0
    print(f"{proj}: drivers={n}  ours={o.covered_lines}  human={h.covered_lines}  "
          f"recall={recall:.0f}%  WE_NEW={we_new.covered_lines}  "
          f"HUMAN_NEW={h_new.covered_lines}  OVERLAP={overlap}")


if __name__ == '__main__':
    main()
