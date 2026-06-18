# CI gating

One line, exits non-zero on a fixable vulnerability:

```bash
./pkgremedy-run.sh --base "$SPARK_BASE_IMAGE" -- scan --fail-on fixable
# or:  make scan BASE="$SPARK_BASE_IMAGE"
```

- `github-actions.yml` — drop-in workflow.
- `Jenkinsfile.snippet` — a stage to paste into your pipeline.

To auto-remediate instead of just gating, swap `scan --fail-on fixable` for
`envfix` and have the job open a PR with the emitted `environment.fixed.yml`.
