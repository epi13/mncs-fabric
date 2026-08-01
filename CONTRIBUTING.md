# Contributing

MNCS Fabric is experimental and changes to execution, identity, evidence, or status semantics require careful review.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
```

## Required invariants

Contributions must preserve these rules:

- no shell-based job execution;
- no arbitrary controller command strings;
- no silent fallback when a required capability is absent;
- no rewriting `UNKNOWN` as `PASS`;
- `FAIL` dominates `UNKNOWN`, which dominates `PASS`;
- raw observations remain distinguishable from evaluator verdicts;
- operator-controlled machines never become independent merely by increasing their count;
- mutation and unfavorable results remain retained; and
- identity-affecting changes require fixtures and tests.

## Pull requests

Explain the authority boundary, threat-model effect, compatibility effect, and tests. Protocol or schema changes must be versioned; do not silently change the interpretation of an existing schema version.
