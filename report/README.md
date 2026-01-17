# Reports

## Experiment Report

* Reports are generated locally from the raw experiment artifacts under
  `results/`.
* **Quick start** - Generate and serve HTML report:
  ```bash
  python -m report.web -r results -s
  ```
  Then open http://localhost:8012/ in your browser.

* Full options:
  - Generate static HTML report only:
    `python -m report.web -r results -b <benchmark_set> -m <model> -o results-report`
  - Generate and serve with web server:
    `python -m report.web -r results -s -b <benchmark_set> -m <model> -o results-report`

## Trends Report

Historical trends can be produced entirely offline by using the locally
generated data inside `results/` and `training_data/`.

# Updating the Code

* `report/web.py` renders the static site; update templates in
  `report/templates/` when adjusting the UI.

