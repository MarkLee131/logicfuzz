"""coverage_diff of an arbitrary coverage-report dir vs the human OSS-Fuzz suite.

Usage: python scripts/cov_diff_dir.py <project> <coverage_dir> [YYYYMMDD]
<coverage_dir> contains */textcov/*.covreport (e.g. a snapshot of an A/B run).
"""
import json
import glob
import urllib.request
import copy
import os
import sys

sys.path.insert(0, os.getcwd())
from experiment import textcov  # noqa: E402


def ours(cov_dir):
    out = textcov.Textcov()
    n = 0
    for f in glob.glob(f'{cov_dir}/*/textcov/*.covreport'):
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
    proj, cov_dir = sys.argv[1], sys.argv[2]
    date = sys.argv[3] if len(sys.argv) > 3 else '20260530'
    o, n = ours(cov_dir)
    h = human(proj, date)
    we_new = copy.deepcopy(o)
    we_new.subtract_covered_lines(h)
    overlap = o.covered_lines - we_new.covered_lines
    recall = 100 * overlap / h.covered_lines if h.covered_lines else 0
    print(f"{proj} [{os.path.basename(cov_dir)}]: drivers={n}  ours={o.covered_lines}  "
          f"human={h.covered_lines}  recall={recall:.0f}%  WE_NEW={we_new.covered_lines}  "
          f"HUMAN_NEW={h.covered_lines - overlap}  OVERLAP={overlap}")


if __name__ == '__main__':
    main()
