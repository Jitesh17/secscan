## Summary

<!-- One or two sentences. What does this PR do, and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature / scanner
- [ ] Refactor (no behaviour change)
- [ ] Documentation
- [ ] Packaging / build
- [ ] Other:

## Linked issue

<!-- e.g. Closes #12. Delete this section if there isn't one. -->

## How was this tested?

<!-- Concrete commands you ran. Manual test against a real target, or pytest output. -->

```
secscan scan https://example.com --scans headers,tls
```

## Checklist

- [ ] One logical change per PR.
- [ ] `secscan --help` and `secscan list-scanners` still work.
- [ ] If a new scanner: registered in `secscan/scanners/__init__.py` and shows up in `list-scanners`.
- [ ] If packaging changed: `python -m build` produces a wheel that installs cleanly in a fresh venv.
- [ ] README updated if user-facing behaviour changed.
- [ ] No new dependencies, or the PR description explains why one is needed.

## Notes for the reviewer

<!-- Anything tricky, anything to look at first, anything you're unsure about. -->
