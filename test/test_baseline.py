"""
   The MIT License (MIT)

   Copyright (C) 2026 Joe Testa (jtesta@positronsecurity.com)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
import json
import os

from datetime import datetime, timezone

import pytest

from ssh_audit import baseline as b
from ssh_audit import exitcodes
from ssh_audit.baseline import Baseline, BaselineError, ExceptionRegistry


TARGET = 'example.com:22'


def _entry(algorithm: str, notes=None, keysize=None, casize=None):
    e = {'algorithm': algorithm, 'notes': notes if notes is not None else {}}
    if keysize is not None:
        e['keysize'] = keysize
    if casize is not None:
        e['casize'] = casize
    return e


def _scan(kex=None, key=None, enc=None, mac=None, banner='SSH-2.0-OpenSSH_9.6', fingerprints=None):
    # The ordering here also covers the compression field every complete document has.
    return {
        'target': TARGET,
        'banner': {'raw': banner, 'protocol': '2.0', 'software': banner.replace('SSH-2.0-', ''), 'comments': None},
        'compression': ['none'],
        'kex': [_entry(a) for a in (kex if kex is not None else [])],
        'key': [_entry(a, keysize=s) for a, s in (key if key is not None else [])],
        'enc': [_entry(a) for a in (enc if enc is not None else [])],
        'mac': [_entry(a) for a in (mac if mac is not None else [])],
        'fingerprints': fingerprints if fingerprints is not None else [],
        'cves': [],
        'recommendations': {},
        'additional_notes': [],
    }


def _write(tmp_path, name, obj):
    path = os.path.join(str(tmp_path), name)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, sort_keys=True)
    return path


# Algorithms used below, with their knowledge-base ratings:
#   diffie-hellman-group1-sha1   -> fail (weak)
#   diffie-hellman-group14-sha1  -> fail + warn
#   curve25519-sha256            -> warn only
#   diffie-hellman-group16-sha512 -> warn only
#   ssh-ed25519, aes256-gcm@openssh.com, chacha20-poly1305@openssh.com,
#   hmac-sha2-512-etm@openssh.com -> strong (no fail/warn)
#   3des-cbc                     -> fail (weak)
#   aes128-cbc                   -> warn only
#   hmac-sha1                    -> fail (weak)


class TestBaselineCore:

    def test_four_diff_categories_strict(self):
        '''New weak algorithm, removed strong algorithm, reordering and shortened keys each produce their own regression type.'''

        old = _scan(
            kex=['diffie-hellman-group16-sha512', 'curve25519-sha256', 'ssh-ed25519-kex-placeholder'],
            key=[('ssh-ed25519', 256), ('rsa-sha2-512', 4096)],
            enc=['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
            mac=['hmac-sha2-512-etm@openssh.com'])
        # Make the third kex name a real, strong algorithm instead of a placeholder.
        old['kex'] = [_entry('diffie-hellman-group16-sha512'), _entry('curve25519-sha256'), _entry('diffie-hellman-group18-sha512')]

        new = _scan(
            # 1) weak algorithm added; 3) order of the common strong kex algorithms changed.
            kex=['diffie-hellman-group1-sha1', 'diffie-hellman-group18-sha512', 'diffie-hellman-group16-sha512', 'curve25519-sha256'],
            # 2) rsa-sha2-512 (strong) removed; 4) ed25519 key size cannot shrink, so use an RSA key to model a shortened key.
            key=[('ssh-ed25519', 256), ('ssh-rsa', 2048)],
            enc=['chacha20-poly1305@openssh.com'],  # aes256-gcm (strong) removed here too
            mac=['hmac-sha2-512-etm@openssh.com'])
        # Put the shortened-key case on rsa-sha2-512, present in both scans.
        old['key'] = [_entry('ssh-ed25519', keysize=256), _entry('rsa-sha2-512', keysize=4096)]
        new['key'] = [_entry('ssh-ed25519', keysize=256), _entry('rsa-sha2-512', keysize=2048)]

        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        types = {d['type'] for d in result['diffs']}
        assert b.DIFF_WEAK_ALG_ADDED in types
        assert b.DIFF_STRONG_ALG_REMOVED in types
        assert b.DIFF_REORDER in types
        assert b.DIFF_KEY_SIZE_DECREASED in types

        # All four are regressions in strict mode.
        assert result['regression_count'] >= 4
        assert all(d['is_regression'] for d in result['diffs'] if d['type'] in (b.DIFF_WEAK_ALG_ADDED, b.DIFF_STRONG_ALG_REMOVED, b.DIFF_REORDER, b.DIFF_KEY_SIZE_DECREASED))
        assert b.resolve_exit_code(result) == exitcodes.REGRESSION

        # The shortened-key entry carries the actual sizes.
        key_diff = next(d for d in result['diffs'] if d['type'] == b.DIFF_KEY_SIZE_DECREASED)
        assert key_diff['old_size'] == 4096 and key_diff['new_size'] == 2048

    def test_hardening_is_not_regression(self):
        '''Removing weak algorithms and growing keys must never be reported as a regression.'''

        old = _scan(
            kex=['diffie-hellman-group1-sha1', 'curve25519-sha256'],
            key=[('rsa-sha2-512', 2048)],
            enc=['3des-cbc', 'aes256-gcm@openssh.com'],
            mac=['hmac-sha1', 'hmac-sha2-512-etm@openssh.com'])
        new = _scan(
            # mlkem768x25519-sha256 has no fail/warn ratings, so adding it is pure hardening.
            kex=['curve25519-sha256', 'mlkem768x25519-sha256'],
            key=[('rsa-sha2-512', 4096)],
            enc=['aes256-gcm@openssh.com'],
            mac=['hmac-sha2-512-etm@openssh.com'])

        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert result['regression_count'] == 0
        types = {d['type'] for d in result['diffs']}
        assert b.DIFF_WEAK_ALG_REMOVED in types
        assert b.DIFF_KEY_SIZE_INCREASED in types
        assert all(not d['is_regression'] for d in result['diffs'])
        assert b.resolve_exit_code(result) == exitcodes.GOOD

    def test_lenient_mode_ignores_reorder_and_warnings(self):
        '''Strict/lenient decoupling: reordering and warning-level changes are diffs in both modes, but regressions only in strict mode.'''

        old = _scan(kex=['curve25519-sha256', 'diffie-hellman-group16-sha512'], enc=['aes128-cbc', 'aes256-gcm@openssh.com'])
        # Reorder the common kex list, and add a warning-level cipher (aes128-cbc already exists, so add a warn-only kex instead).
        new = _scan(kex=['diffie-hellman-group16-sha512', 'curve25519-sha256', 'diffie-hellman-group14-sha256'], enc=['aes128-cbc', 'aes256-gcm@openssh.com'])

        strict = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        lenient = b.compare_scans(old, new, mode=b.MODE_LENIENT, target=TARGET)

        # The same set of differences is produced regardless of mode.
        assert {(d['type'], d['algorithm']) for d in strict['diffs']} == {(d['type'], d['algorithm']) for d in lenient['diffs']}
        assert strict['regression_count'] > 0
        assert lenient['regression_count'] == 0
        assert b.resolve_exit_code(lenient) == exitcodes.GOOD
        # diffie-hellman-group14-sha256 carries only a warning (2048-bit modulus).
        assert any(d['type'] == b.DIFF_WARN_ALG_ADDED and d['algorithm'] == 'diffie-hellman-group14-sha256' for d in lenient['diffs'])

    def test_subset_semantics_match_policy(self):
        '''A pure subset (no new names, no reordering of the remainder) is not a regression of ordering; removing the last members is classified by strength.'''

        old = _scan(kex=['curve25519-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group1-sha1'])
        new = _scan(kex=['curve25519-sha256', 'diffie-hellman-group16-sha512'])  # weak member dropped, order preserved.
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert b.DIFF_REORDER not in {d['type'] for d in result['diffs']}
        assert result['regression_count'] == 0

    def test_reorder_counted_once_in_strict(self):
        '''A strict-mode reordering produces exactly one regression and cannot be suppressed by an algorithm-scoped exception.'''

        old = _scan(kex=['mlkem768x25519-sha256', 'sntrup761x25519-sha512'])
        new = _scan(kex=['sntrup761x25519-sha512', 'mlkem768x25519-sha256'])
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert result['regression_count'] == 1
        assert result['regressions'][0]['type'] == b.DIFF_REORDER

        # Even with a registry covering both algorithms, the ordering regression stands.
        registry = ExceptionRegistry([
            {'target': TARGET, 'type': 'kex', 'algorithm': 'mlkem768x25519-sha256', 'reason': 'x', 'expires': '2030-01-01T00:00:00+00:00'},
            {'target': TARGET, 'type': 'kex', 'algorithm': 'sntrup761x25519-sha512', 'reason': 'x', 'expires': '2030-01-01T00:00:00+00:00'},
        ])
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, exceptions=registry, target=TARGET)
        assert result['regression_count'] == 1
        assert result['exceptions_applied'] == []

    def test_software_identity_change_is_incomparable(self):
        '''A different software product makes the baseline incomparable rather than producing hard diffs.'''

        old = _scan(banner='SSH-2.0-OpenSSH_9.6')
        new = _scan(banner='SSH-2.0-Dropbear_2022.82')
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert result['status'] == b.STATUS_INCOMPARABLE
        assert result['comparable'] is False
        assert result['diffs'] == []
        assert b.resolve_exit_code(result) == exitcodes.INCOMPARABLE

    def test_version_change_same_product_is_comparable(self):
        '''A version bump within the same product remains comparable, with the banner change noted.'''

        old = _scan(banner='SSH-2.0-OpenSSH_9.0', kex=['curve25519-sha256'])
        new = _scan(banner='SSH-2.0-OpenSSH_9.6', kex=['curve25519-sha256'])
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert result['status'] == b.STATUS_COMPARED
        assert any(d['type'] == b.DIFF_BANNER_CHANGED for d in result['diffs'])
        assert result['regression_count'] == 0

    def test_fingerprint_change_makes_size_inconclusive(self):
        '''A replaced host key is reported explicitly and must not be turned into a key-size regression.'''

        old = _scan(key=[('ssh-ed25519', 256)], fingerprints=[{'hostkey': 'ssh-ed25519', 'hash_alg': 'SHA256', 'hash': 'AAA'}])
        new = _scan(key=[('ssh-ed25519', 256)], fingerprints=[{'hostkey': 'ssh-ed25519', 'hash_alg': 'SHA256', 'hash': 'BBB'}])
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert any(d['type'] == b.DIFF_FINGERPRINT_CHANGED for d in result['diffs'])
        assert all(d['type'] != b.DIFF_KEY_SIZE_DECREASED for d in result['diffs'])
        assert result['regression_count'] == 0

    def test_incomplete_scan_never_treated_as_removal(self):
        '''A partial current scan is incomparable, so missing sections are not counted as removed strong algorithms.'''

        old = _scan(kex=['curve25519-sha256'], enc=['aes256-gcm@openssh.com'])
        new = _scan(kex=['curve25519-sha256'], enc=['aes256-gcm@openssh.com'])
        del new['mac']
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert result['status'] == b.STATUS_INCOMPARABLE
        assert result['incomplete'] is True
        assert b.resolve_exit_code(result) == exitcodes.INCOMPARABLE

    def test_missing_size_field_does_not_crash(self):
        '''If only the baseline recorded a keysize, the size comparison is skipped rather than raising.'''

        old = _scan(key=[('rsa-sha2-512', 4096)])
        new = _scan()
        new['key'] = [_entry('rsa-sha2-512')]  # Present in both scans, but without a keysize.
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET)
        assert result['status'] == b.STATUS_COMPARED
        assert all(d['type'] != b.DIFF_KEY_SIZE_DECREASED for d in result['diffs'])


class TestExceptions:

    def _registry(self, tmp_path, entries):
        return ExceptionRegistry.load(_write(tmp_path, 'exceptions.json', {'exceptions': entries}))

    def test_exception_hit_suppresses_regression(self, tmp_path):
        old = _scan(kex=['curve25519-sha256'])
        new = _scan(kex=['curve25519-sha256', 'diffie-hellman-group1-sha1'])
        registry = self._registry(tmp_path, [{
            'target': TARGET, 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1',
            'reason': 'legacy device, ticket OPS-123', 'expires': '2030-01-01T00:00:00+00:00'}])

        result = b.compare_scans(old, new, mode=b.MODE_STRICT, exceptions=registry, target=TARGET)
        assert result['regression_count'] == 0
        assert len(result['exceptions_applied']) == 1
        assert result['exceptions_applied'][0]['reason'] == 'legacy device, ticket OPS-123'
        # The suppressed diff remains visible in the output.
        weak_diff = next(d for d in result['diffs'] if d['algorithm'] == 'diffie-hellman-group1-sha1')
        assert weak_diff['is_regression'] is False
        assert weak_diff['exception']['expires'] == '2030-01-01T00:00:00+00:00'
        assert b.resolve_exit_code(result) == exitcodes.EXCEPTION_ONLY

    def test_expired_exception_reopens_regression(self, tmp_path):
        old = _scan(kex=['curve25519-sha256'])
        new = _scan(kex=['curve25519-sha256', 'diffie-hellman-group1-sha1'])
        registry = self._registry(tmp_path, [{
            'target': TARGET, 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1',
            'reason': 'legacy device', 'expires': '2020-01-01T00:00:00+00:00'}])

        result = b.compare_scans(old, new, mode=b.MODE_STRICT, exceptions=registry, target=TARGET, now=datetime(2026, 11, 20, tzinfo=timezone.utc))
        assert result['regression_count'] == 1
        assert len(result['exceptions_applied']) == 0
        assert len(result['expired_exceptions']) == 1
        assert b.resolve_exit_code(result) == exitcodes.REGRESSION

    def test_timezone_boundary_uses_registered_timezone(self, tmp_path):
        '''An expiry expressed in a non-UTC timezone is evaluated at its own instant.'''
        old = _scan(kex=['curve25519-sha256'])
        new = _scan(kex=['curve25519-sha256', 'diffie-hellman-group1-sha1'])
        # 2026-11-20 01:00+02:00 == 2025-11-19 23:00 UTC: still active at 22:30 UTC.
        registry = self._registry(tmp_path, [{
            'target': TARGET, 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1',
            'reason': 'boundary test', 'expires': '2026-11-20T01:00:00+02:00'}])
        now = datetime(2026, 11, 19, 22, 30, tzinfo=timezone.utc)
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, exceptions=registry, target=TARGET, now=now)
        assert result['regression_count'] == 0
        assert len(result['exceptions_applied']) == 1

    def test_naive_expiry_rejected(self, tmp_path):
        with pytest.raises(BaselineError, match='timezone'):
            self._registry(tmp_path, [{
                'target': TARGET, 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1',
                'reason': 'bad entry', 'expires': '2030-01-01T00:00:00'}])

    def test_global_permanent_exemption_rejected(self, tmp_path):
        with pytest.raises(BaselineError, match='target'):
            self._registry(tmp_path, [{
                'target': '', 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1',
                'reason': 'no scope', 'expires': '2030-01-01T00:00:00+00:00'}])

    def test_duplicate_exceptions_deterministic_merge(self, tmp_path):
        registry = ExceptionRegistry.load(_write(tmp_path, 'exceptions.json', {'exceptions': [
            {'target': TARGET, 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1', 'reason': 'first', 'expires': '2030-01-01T00:00:00+00:00'},
            {'target': TARGET, 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1', 'reason': 'second', 'expires': '2031-01-01T00:00:00+00:00'},
        ]}))
        # Exactly one entry survives, and it is the one with the later expiry.
        assert len(registry.entries) == 1
        assert registry.entries[0]['expires'] == '2031-01-01T00:00:00+00:00'
        assert len(registry.conflicts) == 1
        assert registry.conflicts[0]['discarded']['reason'] == 'first'

    def test_three_way_exception_conflict(self, tmp_path):
        '''With three duplicates, the latest-expiry entry ultimately wins and every discarded entry is reported distinctly.'''
        registry = ExceptionRegistry([
            {'target': TARGET, 'type': 'kex', 'algorithm': 'x', 'reason': 'a', 'expires': '2030-01-01T00:00:00+00:00'},
            {'target': TARGET, 'type': 'kex', 'algorithm': 'x', 'reason': 'b', 'expires': '2032-01-01T00:00:00+00:00'},
            {'target': TARGET, 'type': 'kex', 'algorithm': 'x', 'reason': 'c', 'expires': '2031-01-01T00:00:00+00:00'},
        ])
        assert len(registry.entries) == 1
        assert registry.entries[0]['reason'] == 'b'
        discarded_reasons = {c['discarded']['reason'] for c in registry.conflicts}
        assert discarded_reasons == {'a', 'c'}
        assert all(c['kept']['reason'] == 'b' for c in registry.conflicts)

    def test_exception_scoped_to_target(self, tmp_path):
        old = _scan(kex=['curve25519-sha256'])
        new = _scan(kex=['curve25519-sha256', 'diffie-hellman-group1-sha1'])
        registry = self._registry(tmp_path, [{
            'target': 'other-host:22', 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1',
            'reason': 'wrong target', 'expires': '2030-01-01T00:00:00+00:00'}])
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, exceptions=registry, target=TARGET)
        assert result['regression_count'] == 1

    def test_bare_host_exception_matches_host_port_target(self, tmp_path):
        '''A registration scoped to a bare host also applies to that host's host:port scan targets.'''
        old = _scan(kex=['curve25519-sha256'])
        new = _scan(kex=['curve25519-sha256', 'diffie-hellman-group1-sha1'])
        registry = self._registry(tmp_path, [{
            'target': 'example.com', 'type': 'kex', 'algorithm': 'diffie-hellman-group1-sha1',
            'reason': 'bare host scope', 'expires': '2030-01-01T00:00:00+00:00'}])
        result = b.compare_scans(old, new, mode=b.MODE_STRICT, exceptions=registry, target=TARGET)
        assert result['regression_count'] == 0
        assert len(result['exceptions_applied']) == 1


class TestRatingSemantics:

    def test_gss_name_normalization(self):
        # GSS kex names carry a variable base64 suffix and must normalize to the wildcard DB entry, matching output_algorithm().
        fail, warn = b.get_alg_rating('kex', 'gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg==')
        assert fail is True

    def test_unknown_algorithm_is_failure(self):
        fail, warn = b.get_alg_rating('enc', 'totally-made-up-cipher-9000')
        assert fail is True and warn is False

    def test_stored_notes_fallback(self):
        fail, warn = b.get_alg_rating('enc', 'legacy-custom-cipher', {'fail': [], 'warn': ['custom warn']})
        assert fail is False and warn is True


class TestBaselineLoading:
    def test_cold_start(self):
        result = b.no_baseline_result(b.MODE_STRICT)
        assert result['status'] == b.STATUS_NO_BASELINE
        assert b.resolve_exit_code(result) == exitcodes.GOOD

    def test_missing_baseline_is_cold_start(self, tmp_path):
        with pytest.raises(BaselineError) as exc:
            Baseline.load(os.path.join(str(tmp_path), 'absent.json'))
        assert isinstance(exc.value.__cause__, FileNotFoundError)

    def test_corrupt_baseline_refused(self, tmp_path):
        path = os.path.join(str(tmp_path), 'corrupt.json')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{not valid json')
        with pytest.raises(BaselineError, match='not valid JSON'):
            Baseline.load(path)

    def test_unknown_format_version_refused(self, tmp_path):
        scan = _scan(kex=['curve25519-sha256'])
        scan['scan_meta'] = {'baseline_format_version': 999, 'generated_at': '2026-01-01T00:00:00+00:00'}
        path = _write(tmp_path, 'future.json', scan)
        with pytest.raises(BaselineError, match='unsupported baseline format version'):
            Baseline.load(path)

    def test_legacy_scan_without_meta_accepted(self, tmp_path):
        path = _write(tmp_path, 'legacy.json', _scan(kex=['curve25519-sha256']))
        baseline = Baseline.load(path)
        assert baseline.generated_at is None
        assert baseline.scan['kex'][0]['algorithm'] == 'curve25519-sha256'

    def test_incomplete_baseline_refused(self, tmp_path):
        scan = _scan(kex=['curve25519-sha256'])
        del scan['enc']
        path = _write(tmp_path, 'incomplete.json', scan)
        with pytest.raises(BaselineError, match='missing required algorithm section'):
            Baseline.load(path)

    def test_array_document_refused(self, tmp_path):
        path = _write(tmp_path, 'array.json', [_scan()])
        with pytest.raises(BaselineError, match='JSON array'):
            Baseline.load(path)


class TestDeterminismAndBootstrap:

    def test_output_repeatable_for_same_input(self):
        old = _scan(kex=['curve25519-sha256', 'diffie-hellman-group16-sha512'])
        new = _scan(kex=['diffie-hellman-group16-sha512', 'curve25519-sha256', 'diffie-hellman-group1-sha1'])
        now = datetime(2026, 11, 20, tzinfo=timezone.utc)
        first = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET, now=now)
        second = b.compare_scans(old, new, mode=b.MODE_STRICT, target=TARGET, now=now)
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_self_bootstrap_roundtrip(self, tmp_path):
        '''A scan document carrying scan_meta can be reloaded as a baseline and comparing it against itself yields no regressions.'''

        current = _scan(kex=['curve25519-sha256'], key=[('ssh-ed25519', 256)], enc=['aes256-gcm@openssh.com'], mac=['hmac-sha2-512-etm@openssh.com'])
        current['scan_meta'] = b.build_scan_meta(TARGET, b.is_complete_scan(current))
        path = _write(tmp_path, 'baseline.json', current)

        baseline = Baseline.load(path)
        result = b.compare_scans(baseline.scan, current, mode=b.MODE_STRICT, target=TARGET, baseline=baseline)
        assert result['status'] == b.STATUS_COMPARED
        assert result['regression_count'] == 0
        assert result['diffs'] == []
        assert baseline.meta['baseline_format_version'] == b.BASELINE_FORMAT_VERSION

    def test_generated_scan_meta_has_timezone(self):
        meta = b.build_scan_meta(TARGET, True)
        assert meta['complete'] is True
        # fromisoformat must parse it, and it must be timezone-aware.
        parsed = datetime.fromisoformat(meta['generated_at'])
        assert parsed.tzinfo is not None
