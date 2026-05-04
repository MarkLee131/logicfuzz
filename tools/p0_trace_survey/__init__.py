"""P0 (project-adaptive automaton design — phase 0).

Standalone *measurement-only* module. Walks libclang AST over project consumer
paths (tests/, examples/, fuzz drivers) and emits per-function ordered API
call lists with intra-function value-flow bindings.

Goal: validate signal density before committing to the production refactor
described in ``docs/automaton.md`` (which has since shipped — this tool is
preserved for re-running the survey on a new project before adding it to
the benchmark suite). Outputs a JSON report; does not touch
``FuzzingContext`` or any production pipeline component.
"""
