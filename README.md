# KYBER Secret Sentinel

Offline local secret-pattern review with redacted findings and shareable HTML reports.

**Status: v0.1 portfolio implementation.** Created by Farouk Khaled for the KYBER portfolio. This is new work created in November 2026, not a historical client deployment.

## Features

- Pattern detection for private-key blocks, selected token formats and credential assignments.
- Never emits matched values: path, line, rule and fingerprint only.
- Skips symlinks, binary files, oversized files and common generated folders.

## Technology

Python 3.9+. No third-party runtime dependencies.

## Run

```sh
python sentinel.py PATH_TO_DIRECTORY --json report.json --html report.html
```

## Verify

```sh
python -m unittest -v
```

See [VALIDATION.md](VALIDATION.md) for the checks actually run in the authoring environment.

## Scope and limitations

- Pattern coverage is deliberately limited; false positives and false negatives are expected.
- Does not scan Git history, archives, binary files or remote systems.
- File paths and fingerprints can still be sensitive. Exit 0 clean, 1 findings, 2 incomplete/error.

## Repository layout

Source, configuration, synthetic sample data and tests are kept in this repository. Runtime databases and generated reports are ignored. Never commit client data, credentials or unredacted reports.

## Roadmap

- Broaden test fixtures and error recovery coverage.
- Gather real usability feedback using synthetic data.
- Version the data format before adding import/migration features.

## Security

Report concerns privately through the contact options on [the maintainer profile](https://github.com/faroukkhaled). Do not include secrets in public issues. See [SECURITY.md](SECURITY.md).

## License

No license has been granted yet. Contact the author before reuse or redistribution.
