## Summary

Describe the focused change and why it is needed.

## Safety and privacy

- [ ] No customer documents, credentials, `.env` files, databases, logs, cookies, or
      private paths were added.
- [ ] No live trading, external API, paid API, scraper, or long-running service was
      introduced.
- [ ] Metadata-only and human-review boundaries remain intact.

## Validation

- [ ] `python -m compileall -q src tests scripts`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy`
- [ ] `python -m pytest -q`
- [ ] Relevant fixture or safety gates were run.
- [ ] Skipped checks and known risks are explained below.

## Notes

<!-- Mention changed files, compatibility considerations, and follow-up work. -->
