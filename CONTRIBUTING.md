# Contributing

Issues and pull requests are welcome. [ROADMAP.md](ROADMAP.md) lists what may come next.

- Keep the module self-contained: the functions use only the Python standard library and
  boto3, and the module only the `aws` and `archive` providers.
- Keep decisions pure. Path rules belong in `paths.py`, verdicts in `classify.py`, alerting in
  `diff.py`, tripwire judgments in `tripwire.py`; AWS calls belong in `inventory.py` and
  `aws.py`.
- Keep the member role read-only and its actions named: no `Describe*` or `Get*` wildcards.
- Run the tests and `terraform fmt` / `validate` / `test` before opening a pull request; see
  [docs/development.md](docs/development.md).
- Behaviour changes need a test, and a line in [CHANGELOG.md](CHANGELOG.md).
