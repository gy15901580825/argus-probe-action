"""Write action outputs and a job summary without rerunning any probes."""
from collections import Counter
from html import escape
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET

VERDICTS = {'pass': 'passed', 'fail': 'failed', 'warn': 'warned', 'error': 'errored',
            'skipped': 'skipped', 'blocked_by_target': 'blocked-by-target', 'aborted_cost': 'aborted-cost'}
SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']


class FindingHeaders(HTMLParser):
    """Only read finding headings, never nested evidence or attacker content."""
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.finding_depth = None
        self.heading = False
        self.text = []
        self.findings = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'div':
            self.depth += 1
            if attrs.get('class') == 'finding':
                self.finding_depth = self.depth
        if tag == 'h3' and self.finding_depth == self.depth:
            self.heading = True
            self.text = []

    def handle_data(self, data):
        if self.heading:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag == 'h3' and self.heading:
            match = re.fullmatch(r'(.+?)\s+—\s+(\w+)\s+·\s+(\w+)\s+·\s+confidence\s+\S+', ''.join(self.text).strip())
            if not match:
                raise ValueError('HTML finding heading is not supported')
            probe, verdict, severity = match.groups()
            self.findings.append({'probe_id': probe, 'verdict': verdict, 'severity': severity})
            self.heading = False
        if tag == 'div':
            if self.finding_depth == self.depth:
                self.finding_depth = None
            self.depth -= 1


def read_report(path, format):
    text = path.read_text(encoding='utf-8')
    if format == 'json':
        return json.loads(text)['findings']
    if format == 'sarif':
        return [{'probe_id': f['ruleId'], **f['properties']}
                for run in json.loads(text)['runs'] for f in run.get('results', [])]
    if format == 'html':
        parser = FindingHeaders()
        parser.feed(text)
        if 'Findings (0)' not in text and not parser.findings:
            raise ValueError('HTML finding headings are missing')
        return parser.findings
    if format == 'junit':
        findings = []
        for case in ET.fromstring(text).iter('testcase'):
            verdict, severity = 'pass', 'info'
            for tag, value in [('failure', 'fail'), ('error', 'error'), ('skipped', 'skipped')]:
                child = case.find(tag)
                if child is not None:
                    verdict = child.get('type', value) if tag == 'error' else value
                    severity = child.get('type', 'info') if tag == 'failure' else 'info'
                    break
            else:
                output = case.findtext('system-out', '')
                if re.search(r'(?m)^warn \(', output):
                    verdict = 'warn'
                elif re.search(r'(?m)^blocked_by_target:', output):
                    verdict = 'blocked_by_target'
            findings.append({'probe_id': case.get('name', 'unknown'), 'verdict': verdict, 'severity': severity})
        return findings
    raise ValueError(f'Unsupported format: {format}')


def safe(value):
    return escape(str(value)).replace('|', '&#124;').replace('`', '&#96;').replace('\n', ' ').replace('\r', ' ')


def main():
    report = Path(os.environ['ARGUS_OUTPUT'])
    format = os.environ['ARGUS_FORMAT'].lower()
    code = os.environ.get('SCAN_EXIT_CODE') or 'unavailable (scan did not run)'
    lines = ['## Argus scan', '', f"Target: <code>{safe(os.environ['ARGUS_TARGET'])}</code>", '',
             f'Exit code: {safe(code)}', '', f'Report path: <code>{safe(report)}</code>', '']
    baseline = os.environ.get('ARGUS_BASELINE', '')
    if baseline:
        lines += [f'Baseline: <code>{safe(baseline)}</code>. The severity gate applies only to new failures.', '']
    values = {output: '' for output in VERDICTS.values()}
    values['total'] = ''
    try:
        findings = read_report(report, format)
        if format == 'json':
            record = json.loads(report.read_text(encoding='utf-8'))
            if record.get('incomplete_reason'):
                lines += [f"Incomplete run: {safe(record['incomplete_reason'])}", '']
            comparison = record.get('baseline')
            if comparison:
                lines += ['Baseline comparison: ' + ', '.join(
                    f'{key.replace("_", " ")}: {len(comparison.get(key, []))}'
                    for key in ('new', 'fixed', 'still_failing', 'not_run')), '']
        counts = Counter(f['verdict'] for f in findings)
        if counts.keys() - VERDICTS.keys():
            raise ValueError('Report contains verdicts this action does not recognize')
        values.update({output: str(counts[verdict]) for verdict, output in VERDICTS.items()})
        values['total'] = str(len(findings))
        lines += ['| Verdict | Count |', '|---|---:|']
        lines += [f'| {verdict} | {counts[verdict]} |' for verdict in VERDICTS]
        lines += [f'| total | {len(findings)} |', '', '### Top failing probes', '']
        failing = sorted((f for f in findings if f['verdict'] == 'fail'),
                         key=lambda f: SEVERITIES.index(f['severity']) if f.get('severity') in SEVERITIES else 99)
        if failing:
            lines += ['| Probe | Severity |', '|---|---|']
            lines += [f"| {safe(f['probe_id'])} | {safe(f.get('severity', 'unknown'))} |" for f in failing[:10]]
        else:
            lines += ['No failing probes were recorded.']
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
        lines += [f'Counts unavailable: {safe(exc)}. Check the scan log and report path.']
        print('::warning::Argus counts unavailable; check the job summary and scan log.')
    if format != 'json':
        lines += ['', 'run.json is unavailable. The installed CLI (1.20.0 by default) writes one format per scan. '
                  'Counts above come from the requested report; a full run record and JSON baseline comparison '
                  'are missing. Use format: json to save a baseline without another scan.']
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key, value in values.items():
            output.write(f'{key}={value}\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
        summary.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
