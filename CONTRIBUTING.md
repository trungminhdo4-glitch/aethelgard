# Contributing to AethelGard

Thanks for helping improve AethelGard. The project is an alpha, local-first Python
prototype for human pre-review of security documentation. Contributions should keep
that scope and its privacy boundaries intact.

## Development setup

Use Python 3.11 or newer and install the development extras in an isolated environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[all]"
```

## Checks before opening a pull request

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m compileall -q src tests scripts
python -m ruff check .
python -m mypy
python -m pytest -q
python scripts/check_public_fixtures.py
python scripts/check_marketing_claims.py
```

The test suite must remain offline and deterministic. Do not run Docker, external
scanners, live network integrations, or paid APIs as part of a contribution unless the
maintainer has explicitly requested that validation.

## Pull requests

- Keep changes small and focused; explain the user-visible or safety-relevant effect.
- Add or update tests for behavior changes.
- Do not commit customer documents, secrets, `.env` files, databases, logs, cookies,
  private paths, or unlicensed third-party material.
- Preserve metadata-only and human-review boundaries. Do not turn suggestions into
  automatic compliance decisions.
- Update documentation when a command, output, limitation, or security boundary
  changes.
- Use the pull-request template and report skipped validation explicitly.

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md). Do not use a public issue for an undisclosed
vulnerability or attach private data to a report.
