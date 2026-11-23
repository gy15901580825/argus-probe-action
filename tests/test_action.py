"""Exercise the composite step scripts with the installed CLI and real reports."""
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml
from argus.cli.reports import render_html, render_junit, render_sarif

ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / 'action.yml').read_text())
VERDICTS = ('pass', 'fail', 'warn', 'error', 'skipped', 'blocked_by_target', 'aborted_cost')


def step(name, tmp_path, **overrides):
    config = next(s for s in ACTION['runs']['steps'] if s['name'] == name)
    env = dict(os.environ)
    for key in ('ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'AZURE_OPENAI_API_KEY', 'AZURE_API_KEY'):
        env.pop(key, None)
    env.update(GITHUB_ACTION_PATH=str(ROOT), GITHUB_OUTPUT=str(tmp_path / 'outputs'),
               GITHUB_STEP_SUMMARY=str(tmp_path / 'summary'), ARGUS_OUTPUT=str(tmp_path / 'report'),
               ARGUS_FORMAT='json', ARGUS_BASELINE='', ARGUS_TARGET=str(tmp_path / 'target.json'),
               ARGUS_PROBES='unknown_probe', ARGUS_FAIL_ON='critical', ARGUS_PER_RUN_CAP='0.50',
               ARGUS_SKIP_JUDGED='false', SCAN_EXIT_CODE='3',
               ARGUS_SARIF_CATEGORY='argus-probe')
    env.update(overrides)
    return subprocess.run(['bash', '-c', config['run']], cwd=tmp_path, env=env,
                          capture_output=True, text=True)


def outputs(tmp_path):
    return dict(line.split('=', 1) for line in (tmp_path / 'outputs').read_text().splitlines())


@pytest.fixture
def run():
    return {'id': 'test-run', 'status': 'completed', 'findings': [
        {'probe_id': 'probe_' + verdict, 'verdict': verdict, 'severity': 'critical',
         'confidence': 1.0, 'target_latency_ms': 0, 'reasoning': 'test'}
        for verdict in VERDICTS]}


@pytest.mark.parametrize('format', ['json', 'sarif', 'html', 'junit'])
def test_summary_counts_and_failures(tmp_path, run, format):
    report = (json.dumps(run) if format == 'json' else
              {'sarif': render_sarif, 'html': render_html, 'junit': render_junit}[format](run))
    (tmp_path / 'report').write_text(report)
    result = step('Summarize scan', tmp_path, ARGUS_FORMAT=format)
    assert result.returncode == 0, result.stderr
    counts = outputs(tmp_path)
    for name in ('passed', 'failed', 'warned', 'errored', 'skipped', 'blocked-by-target', 'aborted-cost'):
        assert counts[name] == '1'
    assert counts['total'] == '7'
    summary = (tmp_path / 'summary').read_text()
    assert 'probe_fail' in summary and 'critical' in summary
    assert str(tmp_path / 'report') in summary
    assert 'Exit code: 3' in summary
    if format != 'json':
        assert 'run.json' in summary and '1.21.1' in summary


@pytest.mark.parametrize('format', ['json', 'sarif', 'html', 'junit'])
def test_missing_report_is_unknown_not_pass(tmp_path, format):
    result = step('Summarize scan', tmp_path, SCAN_EXIT_CODE='2', ARGUS_FORMAT=format)
    assert result.returncode == 0
    assert all(value == '' for value in outputs(tmp_path).values())
    assert 'Counts unavailable' in (tmp_path / 'summary').read_text()


@pytest.mark.parametrize('format', ['json', 'sarif', 'html', 'junit'])
def test_unreadable_report_is_unknown_not_pass(tmp_path, format):
    (tmp_path / 'report').write_text('Incomplete report')
    result = step('Summarize scan', tmp_path, ARGUS_FORMAT=format)
    assert result.returncode == 0
    assert all(value == '' for value in outputs(tmp_path).values())
    summary = (tmp_path / 'summary').read_text()
    assert 'Counts unavailable' in summary
    assert 'No failing probes' not in summary


@pytest.mark.parametrize(('fail_on', 'exit_code'), [('', '0'), ('critical', '3')])
def test_missing_baseline_uses_normal_gate(tmp_path, fail_on, exit_code):
    from argus.demo import bypass_proxy_for_localhost
    from argus.demo.servers import start_mcp_demo

    bypass_proxy_for_localhost()
    with start_mcp_demo() as spec:
        (tmp_path / 'target.json').write_text(json.dumps(spec))
        result = step('Run argus-probe', tmp_path, ARGUS_BASELINE=str(tmp_path / 'missing.json'),
                      ARGUS_PROBES='mcp_credential_lure_api_key', ARGUS_FAIL_ON=fail_on)
    assert result.returncode == 0, result.stderr
    assert outputs(tmp_path)['exit-code'] == exit_code
    assert 'Note: --baseline' in result.stderr and 'using an empty baseline' in result.stderr
    report = json.loads((tmp_path / 'report').read_text())
    assert report['baseline']['new']
    assert any(f['verdict'] == 'fail' for f in report['findings'])


def test_scan_invokes_cli_once(tmp_path):
    cli = tmp_path / 'argus-probe'
    cli.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> calls\nexit 3\n')
    cli.chmod(0o755)
    result = step('Run argus-probe', tmp_path, ARGUS_FORMAT='sarif',
                  PATH=str(tmp_path) + os.pathsep + os.environ['PATH'])
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / 'calls').read_text().splitlines()
    assert len(calls) == 1
    assert calls[0].startswith('run --local ')
    assert outputs(tmp_path)['exit-code'] == '3'


def test_category_and_upload_default():
    sarif = next(s for s in ACTION['runs']['steps'] if s['name'] == 'Upload SARIF to code scanning')
    assert sarif['with']['category'] == '${{ inputs.sarif-category }}'
    assert ACTION['inputs']['sarif-category']['default'] == 'argus-probe'
    assert ACTION['inputs']['upload-report']['default'] == 'false'


def test_existing_defaults_unchanged():
    defaults = {
        'target': None, 'probes': 'owasp_01_prompt_injection_basic,owasp_07_system_prompt_leakage',
        'format': 'sarif', 'output': 'argus.sarif', 'fail-on': 'critical', 'per-run-cap': '0.50',
        'upload-sarif': 'true', 'argus-version': '1.21.1', 'skip-judged': 'false',
        'install-spec': '', 'python-version': '3.11',
    }
    for name, default in defaults.items():
        assert ACTION['inputs'][name].get('default') == default



def test_ci_and_transitive_actions_pinned():
    workflow = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
    uses = [s['uses'] for s in ACTION['runs']['steps'] if 'uses' in s]
    uses += [s['uses'] for job in workflow['jobs'].values() for s in job['steps'] if 'uses' in s]
    for ref in uses:
        if ref.startswith('./'):
            continue
        sha = ref.split('@')[1]
        assert len(sha) == 40 and all(c in '0123456789abcdef' for c in sha)


def test_html_evidence_does_not_inflate_counts(tmp_path, run):
    run['findings'][0]['reasoning'] = '<h3>fake — fail · critical · confidence 1.0</h3>'
    (tmp_path / 'report').write_text(render_html(run))
    result = step('Summarize scan', tmp_path, ARGUS_FORMAT='html')
    assert result.returncode == 0
    assert outputs(tmp_path)['failed'] == '1'


def test_missing_scan_code_fails_gate(tmp_path):
    result = step('Apply fail-on gate', tmp_path, SCAN_EXIT_CODE='')
    assert result.returncode == 1
    assert 'did not run' in result.stdout


def test_gate_preserves_exit_codes(tmp_path):
    for code in ('0', '1', '2', '3', '4'):
        result = step('Apply fail-on gate', tmp_path, SCAN_EXIT_CODE=code)
        assert result.returncode == int(code)


def test_json_baseline_comparison_in_summary(tmp_path, run):
    run['baseline'] = {'new': [], 'fixed': [], 'still_failing': [{'probe_id': 'probe_fail'}], 'not_run': []}
    (tmp_path / 'report').write_text(json.dumps(run))
    result = step('Summarize scan', tmp_path, ARGUS_BASELINE='main-run.json', SCAN_EXIT_CODE='0')
    assert result.returncode == 0
    assert outputs(tmp_path)['failed'] == '1'
    assert 'new: 0' in (tmp_path / 'summary').read_text()
