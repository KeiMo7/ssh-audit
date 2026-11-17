import json
import os
import sys
import threading
import tracemalloc
import urllib.request

import pytest

from ssh_audit import exitcodes
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.sarif import (
    MAX_ARTIFACT_URI_LENGTH,
    SEVERITY_MAP,
    SarifValidationError,
    SarifWriter,
    artifact_uri,
    find_repository_root,
    stable_rule_id,
    validate_result,
)


OFFICIAL_SCHEMA_URL = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json'


@pytest.fixture(scope='session')
def official_sarif_schema():
    jsonschema = pytest.importorskip('jsonschema')
    try:
        with urllib.request.urlopen(OFFICIAL_SCHEMA_URL, timeout=20) as response:
            schema = json.load(response)
    except Exception as err:  # pragma: no cover - only unavailable in offline CI.
        pytest.skip('official SARIF schema unavailable: %s' % err)
    jsonschema.Draft4Validator.check_schema(schema)
    return schema


def _validate_official(schema, path):
    jsonschema = pytest.importorskip('jsonschema')
    with open(path, 'r', encoding='utf-8') as handle:
        document = json.load(handle)
    errors = sorted(jsonschema.Draft4Validator(schema).iter_errors(document), key=lambda error: list(error.absolute_path))
    assert errors == []
    return document


def _location(tmp_path, line=1, start_column=1, end_column=12):
    return {
        'artifact_uri': artifact_uri(str(tmp_path / 'targets.txt'), str(tmp_path)),
        'start_line': line,
        'start_column': start_column,
        'end_line': line,
        'end_column': end_column,
    }


def _writer(tmp_path, name='results.sarif', baseline_path=None):
    return SarifWriter(str(tmp_path / name), repo_root=str(tmp_path), baseline_path=baseline_path, tool_version='v3.9.1-dev')


def test_sarif_multiple_rules_and_repeated_locations(tmp_path, official_sarif_schema):
    output = str(tmp_path / 'results.sarif')
    writer = _writer(tmp_path)
    invocation = writer.begin_invocation('ssh-audit', 'localhost:22')
    line_one = _location(tmp_path, line=1)
    line_two = _location(tmp_path, line=2)

    writer.add_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1', line_one, 'localhost:22')
    writer.add_finding('cipher', '3des-cbc', 'warn', 'cipher: broken 3DES', line_one, 'localhost:22')
    writer.add_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1', line_two, 'localhost:22')
    writer.finish_invocation(invocation, True, exitcodes.FAILURE)
    writer.finalize(True)

    document = _validate_official(official_sarif_schema, output)
    results = document['runs'][0]['results']
    assert len(results) == 3
    assert [result['level'] for result in results] == ['error', 'warning', 'error']
    assert results[0]['ruleId'] == results[2]['ruleId']
    assert results[0]['locations'][0]['physicalLocation']['region']['startLine'] == 1
    assert results[2]['locations'][0]['physicalLocation']['region']['startLine'] == 2
    assert all(result['message']['text'] for result in results)


def test_sarif_zero_hits_is_valid(tmp_path, official_sarif_schema):
    output = str(tmp_path / 'empty.sarif')
    writer = _writer(tmp_path, 'empty.sarif')
    invocation = writer.begin_invocation('ssh-audit', 'localhost:22')
    writer.finish_invocation(invocation, True, exitcodes.GOOD)
    writer.finalize(True)

    document = _validate_official(official_sarif_schema, output)
    assert document['runs'][0]['results'] == []
    assert document['runs'][0]['invocations'][0]['executionSuccessful'] is True


def test_sarif_scan_failure_marks_invocation_failed(tmp_path, official_sarif_schema):
    output = str(tmp_path / 'failed.sarif')
    writer = _writer(tmp_path, 'failed.sarif')
    invocation = writer.begin_invocation('ssh-audit', 'localhost:22')
    writer.add_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1', _location(tmp_path), 'localhost:22')
    writer.finish_invocation(invocation, False, exitcodes.CONNECTION_ERROR, 'connection reset')
    writer.finalize(True)

    document = _validate_official(official_sarif_schema, output)
    invocation_record = document['runs'][0]['invocations'][0]
    assert invocation_record['executionSuccessful'] is False
    assert invocation_record['toolExecutionNotifications'][0]['message']['text'] == 'connection reset'
    assert len(document['runs'][0]['results']) == 1


def test_sarif_abnormal_exit_leaves_no_partial_output_and_cleans_temps(tmp_path):
    output = str(tmp_path / 'aborted.sarif')
    writer = _writer(tmp_path, 'aborted.sarif')
    writer.begin_invocation('ssh-audit', 'localhost:22')
    writer.add_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1', _location(tmp_path), 'localhost:22')
    writer.cleanup()

    assert not os.path.exists(output)
    assert [name for name in os.listdir(tmp_path) if name.startswith('.ssh-audit-sarif-')] == []


def test_sarif_baseline_marks_new_and_unchanged(tmp_path, official_sarif_schema):
    output = str(tmp_path / 'baseline.sarif')
    location = _location(tmp_path)

    first = _writer(tmp_path, 'baseline.sarif')
    invocation = first.begin_invocation('ssh-audit', 'localhost:22')
    first.add_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1', location, 'localhost:22')
    first.finish_invocation(invocation, True, exitcodes.FAILURE)
    first.finalize(True)

    second = _writer(tmp_path, 'baseline.sarif')
    invocation = second.begin_invocation('ssh-audit', 'localhost:22')
    second.add_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1', location, 'localhost:22')
    second.add_finding('cipher', '3des-cbc', 'warn', 'cipher: broken 3DES', location, 'localhost:22')
    second.finish_invocation(invocation, True, exitcodes.FAILURE)
    second.finalize(True)

    document = _validate_official(official_sarif_schema, output)
    results = document['runs'][0]['results']
    assert results[0]['baselineState'] == 'unchanged'
    assert results[1]['baselineState'] == 'new'


def test_sarif_rule_ids_and_severity_are_stable():
    assert SEVERITY_MAP == {'fail': 'error', 'warn': 'warning', 'info': 'note'}
    first = stable_rule_id('kex', 'diffie-hellman-group1-sha1')
    second = stable_rule_id('kex', 'diffie-hellman-group1-sha1')
    assert first == second
    assert first.startswith('SSH-AUDIT-KEX-')
    assert '/' not in first and '\\' not in first
    assert '2026' not in first


def test_sarif_artifact_uri_is_relative_and_escaped(tmp_path):
    root = str(tmp_path)
    regular = artifact_uri(str(tmp_path / 'subdir' / 'targets.txt'), root)
    assert regular == 'subdir/targets.txt'
    assert not regular.startswith('/')

    non_utf8 = artifact_uri(str(tmp_path / 'bad-\udcff.txt'), root)
    assert non_utf8.encode('ascii')
    assert non_utf8.startswith('bad-')

    long_name = 'a' * (MAX_ARTIFACT_URI_LENGTH + 100) + '.txt'
    too_long = artifact_uri(long_name, root)
    assert too_long.startswith('external/')
    assert len(too_long) <= MAX_ARTIFACT_URI_LENGTH

    symlink = tmp_path / 'targets-link.txt'
    symlink.symlink_to(tmp_path / 'targets.txt')
    assert artifact_uri(str(symlink), root) == 'targets-link.txt'

    outside = artifact_uri('/home/feedback/outside/targets.txt', root)
    assert outside.startswith('external/')
    assert '/home' not in outside


def test_sarif_target_and_messages_do_not_leak_absolute_paths(tmp_path, official_sarif_schema):
    output = str(tmp_path / 'unix.sarif')
    writer = _writer(tmp_path, 'unix.sarif')
    invocation = writer.begin_invocation('ssh-audit', 'unix:///home/feedback/socket')
    writer.add_finding('kex', 'test', 'warn', 'failed at /home/feedback/secret', _location(tmp_path), 'unix:///home/feedback/socket')
    writer.finish_invocation(invocation, True, exitcodes.WARNING)
    writer.finalize(True)

    document = _validate_official(official_sarif_schema, output)
    result = document['runs'][0]['results'][0]
    assert '/home' not in result['message']['text']
    assert '/home' not in result['properties']['target']
    assert '/home' not in document['runs'][0]['invocations'][0]['properties']['target']


def test_sarif_self_check_reports_json_pointer():
    bad_result = {
        'ruleId': 'SSH-AUDIT-KEX-TEST',
        'level': 'error',
        'message': {'text': 'test'},
        'locations': [{
            'physicalLocation': {
                'artifactLocation': {'uri': '/home/feedback/absolute.txt'},
                'region': {'startLine': 1, 'startColumn': 1, 'endLine': 1, 'endColumn': 2},
            },
        }],
    }
    with pytest.raises(SarifValidationError) as excinfo:
        validate_result(bad_result, '/runs/0/results/7')
    assert excinfo.value.path == '/runs/0/results/7/locations/0/physicalLocation/artifactLocation/uri'


def test_sarif_large_result_set_is_spooled_and_temps_are_cleaned(tmp_path):
    output = str(tmp_path / 'large.sarif')
    location = _location(tmp_path)
    tracemalloc.start()
    writer = _writer(tmp_path, 'large.sarif')
    invocation = writer.begin_invocation('ssh-audit', 'localhost:22')
    samples = []
    for index in range(12000):
        writer.add_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1', location, 'localhost:22')
        if index % 1000 == 0:
            samples.append(tracemalloc.get_traced_memory()[0])
    writer.finish_invocation(invocation, True, exitcodes.FAILURE)
    writer.finalize(True)
    current, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert current - samples[0] < 2 * 1024 * 1024
    assert os.path.getsize(output) > 1024 * 1024
    assert [name for name in os.listdir(tmp_path) if name.startswith('.ssh-audit-sarif-')] == []
    with open(output, 'r', encoding='utf-8') as handle:
        document = json.load(handle)
    assert len(document['runs'][0]['results']) == 12000


def test_sarif_concurrent_writes_are_serialized(tmp_path, official_sarif_schema):
    output = str(tmp_path / 'concurrent.sarif')
    writer = _writer(tmp_path, 'concurrent.sarif')
    location = _location(tmp_path)
    writer.begin_invocation('ssh-audit', 'multiple')

    def worker(worker_id):
        for index in range(100):
            writer.add_finding('kex', 'algorithm-%d' % worker_id, 'warn', 'finding %d' % index, location, 'host-%d' % worker_id)

    threads = [threading.Thread(target=worker, args=(worker_id,)) for worker_id in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    writer.finalize(True)

    document = _validate_official(official_sarif_schema, output)
    assert len(document['runs'][0]['results']) == 800
    assert len({result['fingerprints']['ssh-audit/v1'] for result in document['runs'][0]['results']}) > 1


def test_outputbuffer_recording_does_not_change_text_output():
    out = OutputBuffer()
    out.info('before')
    out.record_finding('kex', 'algorithm', 'warn', 'message')
    out.info('after')
    assert out.get_buffer() == 'before\nafter'


def test_sarif_cli_main_logs_and_writes_valid_output(tmp_path, monkeypatch, capsys, official_sarif_schema, ssh_audit):
    output = str(tmp_path / 'cli.sarif')

    def fake_audit(out, aconf, print_target=False, sarif_writer=None, sarif_location=None, sarif_target=''):
        assert sarif_writer is not None
        out.record_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1')
        return exitcodes.FAILURE

    monkeypatch.setattr(ssh_audit, 'audit', fake_audit)
    monkeypatch.setattr(sys, 'argv', ['ssh-audit', '--sarif', output, '--skip-rate-test', 'localhost'])

    assert ssh_audit.main() == exitcodes.FAILURE
    captured = capsys.readouterr().out
    assert '(sarif) enter:' in captured
    assert '(sarif) exit:' in captured
    document = _validate_official(official_sarif_schema, output)
    assert len(document['runs'][0]['results']) == 1


def test_sarif_cli_mid_scan_exception_produces_failed_invocation(tmp_path, monkeypatch, capsys, official_sarif_schema, ssh_audit):
    output = str(tmp_path / 'cli-failed.sarif')

    def failing_audit(out, aconf, print_target=False, sarif_writer=None, sarif_location=None, sarif_target=''):
        out.record_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1')
        raise RuntimeError('simulated scan failure')

    monkeypatch.setattr(ssh_audit, 'audit', failing_audit)
    monkeypatch.setattr(sys, 'argv', ['ssh-audit', '--sarif', output, '--skip-rate-test', 'localhost'])

    with pytest.raises(RuntimeError, match='simulated scan failure'):
        ssh_audit.main()
    captured = capsys.readouterr().out
    assert '(sarif) failure:' in captured
    document = _validate_official(official_sarif_schema, output)
    assert document['runs'][0]['invocations'][0]['executionSuccessful'] is False


def test_sarif_cli_zero_hits_keeps_success_exit_code(tmp_path, monkeypatch, capsys, official_sarif_schema, ssh_audit):
    output = str(tmp_path / 'cli-empty.sarif')

    def fake_audit(out, aconf, print_target=False, sarif_writer=None, sarif_location=None, sarif_target=''):
        return exitcodes.GOOD

    monkeypatch.setattr(ssh_audit, 'audit', fake_audit)
    monkeypatch.setattr(sys, 'argv', ['ssh-audit', '--sarif', output, '--skip-rate-test', 'localhost'])

    assert ssh_audit.main() == exitcodes.GOOD
    document = _validate_official(official_sarif_schema, output)
    assert document['runs'][0]['results'] == []


def test_sarif_cli_targets_file_locations(tmp_path, monkeypatch, capsys, official_sarif_schema, ssh_audit):
    targets = tmp_path / 'targets.txt'
    targets.write_text('localhost:22\n\nlocalhost:22\n', encoding='utf-8')
    output = str(tmp_path / 'targets.sarif')

    def fake_audit(out, aconf, print_target=False, sarif_writer=None, sarif_location=None, sarif_target=''):
        out.record_finding('kex', 'diffie-hellman-group1-sha1', 'fail', 'kex: weak SHA-1')
        return exitcodes.FAILURE

    monkeypatch.setattr(ssh_audit, 'audit', fake_audit)
    monkeypatch.setattr(ssh_audit, 'find_repository_root', lambda start=None: str(tmp_path))
    monkeypatch.setattr(sys, 'argv', ['ssh-audit', '--sarif', output, '-T', str(targets), '--threads', '1', '--skip-rate-test'])

    assert ssh_audit.main() == exitcodes.FAILURE
    document = _validate_official(official_sarif_schema, output)
    results = document['runs'][0]['results']
    assert len(results) == 2
    assert sorted(result['locations'][0]['physicalLocation']['region']['startLine'] for result in results) == [1, 3]
    assert {result['locations'][0]['physicalLocation']['artifactLocation']['uri'] for result in results} == {'targets.txt'}
    assert all(result['ruleId'] == results[0]['ruleId'] for result in results)


def test_sarif_target_file_locations_preserve_line_numbers(tmp_path, monkeypatch, ssh_audit):
    targets = tmp_path / 'targets.txt'
    targets.write_text('\n  localhost:22\n\n  localhost:2222\n', encoding='utf-8')

    conf = ssh_audit.process_commandline(OutputBuffer(), ['-T', str(targets)])
    assert conf.target_list == ['localhost:22', 'localhost:2222']
    assert conf.target_locations == [(2, 3, 15), (4, 3, 17)]
    assert find_repository_root(str(tmp_path)) == str(tmp_path)
