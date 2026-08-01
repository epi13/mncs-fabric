# Agent instructions

MNCS Fabric is an evidence-sensitive project. Before changing code, read `ARCHITECTURE.md`, `THREAT_MODEL.md`, and `CONTRIBUTING.md`.

Do not add remote shell execution, unauthenticated listeners, silent capability fallbacks, mutable evidence rewriting, or claims of independence. New network behavior requires an explicit threat-model update and adversarial tests. Existing schema versions are immutable in meaning; create a new version for incompatible changes.

Run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src
```
