# Argus agent red-team scan

This action runs [Argus](https://github.com/gy15901580825/Argus) red-team probes against your AI agent from inside your CI job. It installs the `argus-probe` CLI, runs `argus-probe run --local` against the target you describe in a JSON file, and writes a report. With the default SARIF format it uploads the report to GitHub code scanning, so findings show up in the Security tab and on pull requests. The job fails when a probe fails at or above the `fail-on` severity. The SARIF upload happens before the job fails, so you still see the findings. The action also writes verdict counts and the top failing probes to the workflow run summary.

The job summary, count outputs, `baseline`, `sarif-category` and `upload-report` are available from v2.15.0.

## Usage

```yaml
name: agent-red-team
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  argus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: gy15901580825/argus-probe-action@v2
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          target: .argus/target.json
          fail-on: high
```

A minimal `.argus/target.json` for an OpenAI-compatible endpoint:

```json
{
  "kind": "openai_compat",
  "endpoint_url": "https://my-agent.example.com/v1/chat/completions",
  "model": "my-agent",
  "api_key": "${MY_AGENT_KEY}"
}
```

`${VAR}` references are read from the environment at run time, so put the secret in the step's `env:` and keep it out of the file. The [target spec cookbook](https://github.com/gy15901580825/Argus/blob/main/docs/onboarding/target-spec-cookbook.md) covers the other target kinds.

## Inputs

| Input | Default | Description |
|---|---|---|
| `target` | (required) | Path to the target spec JSON file. |
| `probes` | `owasp_01_prompt_injection_basic,owasp_07_system_prompt_leakage` | Comma-separated probe ids, or `all`. |
| `format` | `sarif` | Report format: `sarif`, `html`, `junit` or `json`. |
| `output` | `argus.sarif` | Path of the report file. Give it the extension that matches `format`: `.sarif`, `.html`, `.xml` for `junit`, or `.json` for `json`. When they differ, the action still writes the file at this path and shows a warning on the run page. |
| `fail-on` | `critical` | Fail the job when a probe fails with this severity or higher (`info`, `low`, `medium`, `high`, `critical`). Set it to `''` to turn the gate off. |
| `per-run-cap` | `0.50` | Maximum LLM spend in USD for one scan. The CLI refuses to start a scan whose estimate is above the cap, and stops a scan whose real spend reaches it. |
| `skip-judged` | `false` | Without a judge key, run only the probes decided by deterministic checks and report the judged ones as `skipped`. Without it, a scan that selects judged probes and has no key exits 1. |
| `upload-sarif` | `true` | Upload the report to code scanning. Ignored unless `format` is `sarif`. |
| `baseline` | `''` | Earlier run.json for the same target and mode. Passes `--baseline` to the CLI so `fail-on` gates only on new failing probe ids. From 1.19.0, a missing local file is treated as an empty baseline and prints a note, so you can use the same path on the first run. An invalid file exits 2. |
| `sarif-category` | `argus-probe` | Code scanning category. Give every matrix target a different value. Also used as the suffix of the report artifact name, so use simple names without slashes or other artifact filename characters. |
| `upload-report` | `false` | Upload the requested report with `actions/upload-artifact`, even when the gate trips. The artifact is named `argus-report-<sarif-category>`. A missing file produces a warning. |
| `argus-version` | `1.19.1` | Version of `argus-probe` to install from PyPI. |
| `install-spec` | `''` | Space-separated pip specs to install instead of `argus-probe[local]==<argus-version>`, for example a git URL or a wheel path. |
| `python-version` | `3.11` | Python version passed to `actions/setup-python`. |

## Outputs

| Output | Description |
|---|---|
| `exit-code` | Exit code of `argus-probe run`. 0 means no gated failure. 1 means an error, including a run where any probe ended in `error` (for example the target answered 401, 429 or 5xx) or that stopped early. 2 is a usage error, such as an unknown probe id. 3 means the `fail-on` gate tripped. 4 means the cost cap: the estimate was above `per-run-cap`, or real spend reached it during the scan. |
| `report` | Path of the requested report file, including when it was not written. Check `exit-code` and the summary. |
| `passed` | Number of `pass` verdicts. |
| `failed` | Number of `fail` verdicts, including failures already in the baseline. |
| `warned` | Number of `warn` verdicts. |
| `errored` | Number of `error` verdicts. |
| `skipped` | Number of `skipped` verdicts. |
| `blocked-by-target` | Number of `blocked_by_target` verdicts. |
| `aborted-cost` | Number of `aborted_cost` verdicts. |
| `total` | Number of findings across all verdicts. Repeated probe trials count separately. |

Count outputs are empty when no readable report is available. An empty count does not mean zero. The summary says what is missing and shows the scan exit code. Counts describe all findings; use `exit-code` to decide whether the CLI's severity and baseline gate tripped.

With `format: json`, the action reads the run.json directly. CLI 1.19.0 and later write only one format per scan, so the action reads SARIF, HTML or JUnit when those are requested and states that run.json is missing. Verdict counts are available from each of these formats in CLI 1.19.0 and later. If a report cannot provide counts, the outputs stay empty and the summary says so. Use `format: json` to save a baseline and show its comparison in the summary. The action runs one scan and `upload-report` uploads the requested report.

Later steps can read the outputs even when the gate trips:

```yaml
- uses: gy15901580825/argus-probe-action@v2.15.0
  id: argus
  with:
    target: .argus/target.json
- name: Read scan counts
  if: always()
  env:
    FAILED: ${{ steps.argus.outputs.failed }}
    EXIT_CODE: ${{ steps.argus.outputs.exit-code }}
  run: echo "Argus exit code $EXIT_CODE; failed findings $FAILED"
```

## Gate on new failures

Save a JSON report from the default branch with `format: json`, `output: run.json`, `upload-sarif: 'false'` and `upload-report: 'true'`. Set `fail-on: ''` on that baseline-building scan if you want to save existing findings without failing the default-branch job. Restore that report before the PR scan, then set `baseline` to its path and `fail-on` to the severity you want to block.

CLI 1.19.0 and later validate the baseline before scanning. A missing local baseline file is treated as an empty baseline and prints a note. You can set `baseline` to the intended path on the first run; the usual severity gate applies until a baseline exists. An invalid baseline is still a usage error (exit 2). The baseline must describe the same target and mode. A probe that already failed in the baseline does not trip the gate, even if its severity rises. Errors and incomplete scans still fail the action.

This PR example downloads the last successful baseline workflow run on `main`. It needs `actions: read` as well as `contents: read`. Keep the baseline-building workflow name and artifact category consistent with the download command. Use the default branch name for your repository.

```yaml
- name: Restore default-branch baseline
  id: baseline
  env:
    GH_TOKEN: ${{ github.token }}
  shell: bash
  run: |
    baseline_run=$(gh run list --workflow agent-red-team.yml --branch main --event push \
      --status success --limit 1 --json databaseId --jq '.[0].databaseId // empty')
    if [ -n "$baseline_run" ]; then
      gh run download "$baseline_run" --name argus-report-argus-probe --dir .argus/baseline
      echo "path=.argus/baseline/run.json" >> "$GITHUB_OUTPUT"
    fi
- uses: gy15901580825/argus-probe-action@v2.15.0
  with:
    target: .argus/target.json
    baseline: ${{ steps.baseline.outputs.path }}
    fail-on: high
    format: json
    output: run.json
    upload-sarif: 'false'
```

An expired or unavailable artifact makes the restore step fail so the workflow does not accidentally substitute a different baseline. If no baseline run exists yet, the empty output omits `--baseline`. JSON is the one-scan baseline recipe for the default CLI version. A SARIF or HTML scan can compare against an existing JSON baseline, but CLI 1.19.0 and later cannot also write a new run.json from that scan.

## Scan several targets

Use a unique `sarif-category` and report path for every target. GitHub distinguishes scans of the same commit by category; reusing the category can overwrite findings or reject an upload. Distinct categories also give report artifacts distinct names.

```yaml
jobs:
  argus:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        target: [support, assistant]
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: gy15901580825/argus-probe-action@v2.15.0
        with:
          target: .argus/${{ matrix.target }}.json
          sarif-category: argus-${{ matrix.target }}
          output: argus-${{ matrix.target }}.sarif
          upload-report: 'true'
```

Each matrix job writes its own summary and exposes its own step outputs. For baseline gating, save and restore a separate run.json for each target and set that job's `baseline` path. Review the key and fork guidance below when using judged probes.

## Versions

`@v2` installs argus-probe 1.19.1 by default. Set `argus-version` to install a different version.

`@v1` installs argus-probe 0.4.0. With `@v2`, a scan in which any probe errored exits 1. HTTP 401, 404, and 429 from the target count as errors. A scan without a judge key that selects judged probes exits 1 unless you set `skip-judged: true`. `@v1` stays on 0.4.0. See the [0.7.0 release notes](https://github.com/gy15901580825/Argus/releases/tag/v0.7.0).

## Notes

- The judge needs an API key. Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` (used automatically when it is the only key). For Azure OpenAI or a litellm model such as Ollama, set `REDTEAM_MODEL_PROVIDER` as described in the [Argus README](https://github.com/gy15901580825/Argus#readme). Without a key, a scan that selects judged probes exits 1; set `skip-judged: true` to run only the probes that need no judge. MCP-agent probes need no key.
- Pull requests from forks and from Dependabot get no repository secrets. The judge key is empty there, so the job fails. Skip the job for those events, for example with `if: github.event_name != 'pull_request' || (github.event.pull_request.head.repo.full_name == github.repository && github.actor != 'dependabot[bot]')`.
- `browser_use` targets need an agent that can open the trap page the scan serves on the runner. The page listens on `127.0.0.1` by default, so the agent has to run on the same runner unless the target spec sets `trap_host`, `trap_port` and `trap_public_url`; see the [browser_use section of the cookbook](https://github.com/gy15901580825/Argus/blob/main/docs/onboarding/target-spec-cookbook.md#browser_use).
- Every scan costs money on your judge key. The default cap is $0.50 per scan. `probes: all` selects only the probes your target can run; against a chat target with the default Anthropic judge it estimates about $5.32, so raise `per-run-cap` for it.
- For `mcp_agent` and `payment_agent` targets, set `"testbed_url": "local"` in the target spec and the scan starts the bundled testbed on the runner. The agent under test has to reach `127.0.0.1` on the runner.
- The action fails the job on any nonzero exit code, not only on 3. The error message says whether the gate tripped or the scan itself failed.
- Uploading SARIF needs `security-events: write`. On private repositories code scanning also needs GitHub Advanced Security.

## License

Apache-2.0. See [LICENSE](LICENSE).
