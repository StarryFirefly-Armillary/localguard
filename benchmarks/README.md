# Detection benchmarks

## VulnShop (`vulnshop-ground-truth.json`)

Ground truth for the 16 intentionally vulnerable cases in
[laugiov/code-safety](https://github.com/laugiov/code-safety), MIT licensed
(Copyright 2025 Taint Analysis Masterclass Contributors).

Used by `scripts/bench_detection.py` to measure LocalGuard's recall against a
fixed, known set of vulnerabilities. The benchmark application itself is **not**
bundled here; clone it to `./repos/code-safety` or pass `--target`:

```bash
git clone https://github.com/laugiov/code-safety.git repos/code-safety
python scripts/bench_detection.py --config localguard.local.json
```

The script writes `benchmarks/last-run.json` with the latest metrics.

Matching is file-level by default (an issue in the same file as a documented
vulnerability counts as a detection). Use `--strict-line` to require the issue
line to fall within the documented range. File-level matching is the default
because rules often flag a different line of the same vulnerable construct.
