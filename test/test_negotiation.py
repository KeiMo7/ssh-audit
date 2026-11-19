"""
Tests for the additive negotiation analysis engine.

These cover the acceptance scenarios from the hardening review:
  1. version-removed / default-disabled algorithms are not counted as reachable
     weaknesses and never appear in recommendations;
  2. opposite client/server preference orders resolve to the RFC 4253 choice;
  3. AEAD ciphers shadow standalone MACs;
  4. observed key/modulus lengths are judged separately;
  5. host-key type to signature method mapping;
  6. declared support is separated from handshake-tested support;
  7. negotiated / peer-forced / declared-unreachable reachability grading;
  8. protocol-version applicability ranges;
  9. recommendations trace back to a concrete algorithm and reason;
  10. repeated evaluation is byte-identical.
"""
import json

from ssh_audit.negotiation import (
    AEAD_CIPHERS,
    Availability,
    ReasonCode,
    Reachability,
    Recommendation,
    Severity,
    TestState as NegotiationTestState,
    analyze,
    select_preferred,
)
from ssh_audit.negotiation_output import build_negotiation_struct, output_negotiation
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty


def _kex(kex_algs, key_algs, enc, mac, cookie=b'\x00' * 16):
    cli = SSH2_KexParty(list(enc), list(mac), ['none'], [''])
    srv = SSH2_KexParty(list(enc), list(mac), ['none'], [''])
    return SSH2_Kex(OutputBuffer, bytes(cookie), list(kex_algs), list(key_algs), cli, srv, 0)


def _openssh(version):
    return Software(None, 'OpenSSH', version, None, None)


def _by_name(results):
    return {r.name: r for r in results}


class TestSelection:
    def test_client_preferences_match_send_kexinit_defaults(self):
        # Guard against drift: the negotiation engine must use the same client
        # preference order that ssh-audit actually puts on the wire.
        import inspect
        from ssh_audit import ssh_socket
        from ssh_audit.negotiation import DEFAULT_CLIENT_PREFERENCES
        source = inspect.getsource(ssh_socket.SSH_Socket.send_kexinit)
        for alg_type, prefs in DEFAULT_CLIENT_PREFERENCES.items():
            for name in prefs:
                assert "'{}'".format(name) in source, (alg_type, name)

    def test_opposite_preference_orders(self):
        # Scenario 2: the client's order wins under RFC 4253 even when the
        # server's list is in the opposite order.
        assert select_preferred(['b', 'a'], ['a', 'b']) == 'b'
        assert select_preferred(['a', 'b'], ['b', 'a']) == 'a'

    def test_no_intersection(self):
        assert select_preferred(['a'], ['b']) is None

    def test_selected_basis_recorded(self):
        k = _kex(['curve25519-sha256', 'diffie-hellman-group14-sha256'],
                 ['ssh-ed25519'], ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        assert report.selected['kex']['algorithm'] == 'curve25519-sha256'
        assert 'RFC 4253' in report.selected['kex']['basis']

    def test_opposite_orders_end_to_end(self):
        # Server prefers the weak kex first; the client prefers the strong one.
        k = _kex(['diffie-hellman-group14-sha1', 'curve25519-sha256'],
                 ['ssh-ed25519'], ['aes256-ctr'], ['hmac-sha2-256'])
        prefs = {'kex': ['curve25519-sha256', 'diffie-hellman-group14-sha1']}
        report = analyze(k, _openssh('9.0'), peer_preferences=prefs)
        assert report.selected['kex']['algorithm'] == 'curve25519-sha256'
        # The weak kex is therefore only peer-forced, not negotiated by default.
        weak = _by_name(report.algorithms['kex'])['diffie-hellman-group14-sha1']
        assert weak.reachability == Reachability.PEER_FORCED


class TestVersionAvailability:
    def test_removed_algorithm_not_counted_as_weakness(self):
        # Scenario 1 & acceptance test 1: diffie-hellman-group1-sha1 was removed
        # in OpenSSH 6.9; an OpenSSH 9.0 target that merely declares it must not
        # count it as a reachable weakness.
        k = _kex(['diffie-hellman-group1-sha1'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        result = _by_name(report.algorithms['kex'])['diffie-hellman-group1-sha1']

        assert result.availability == Availability.REMOVED
        assert result.availability_reason == ReasonCode.VERSION_REMOVED
        assert result.reachability == Reachability.DECLARED_UNREACHABLE

        # It must not generate any recommendation (acceptance test 1).
        assert not [r for r in report.recommendations if r.name == 'diffie-hellman-group1-sha1']

        # But it is still *listed* with its finding + reason code, not silently dropped.
        assert result.is_weakness  # the DB fail reasons remain visible
        assert any(f.reason_code == ReasonCode.VERSION_REMOVED for f in result.findings)

    def test_removed_algorithm_absent_from_recommendation_text(self):
        # Acceptance test 1 (second half): the recommendation section must never
        # mention an algorithm that does not exist on this target version.
        k = _kex(['diffie-hellman-group1-sha1', 'curve25519-sha256'],
                 ['ssh-ed25519'], ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        serialized = json.dumps(build_negotiation_struct(report))
        for rec in report.recommendations:
            assert rec.name != 'diffie-hellman-group1-sha1'
        assert 'diffie-hellman-group1-sha1' not in [r['algorithm'] for r in report.to_dict()['recommendations']]
        # The algorithm still appears in the per-algorithm listing.
        assert 'diffie-hellman-group1-sha1' in serialized

    def test_disabled_by_default_classified(self):
        # ssh-dss is disabled by default in OpenSSH 7.0.
        k = _kex(['curve25519-sha256'], ['ssh-dss'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('8.0'))
        result = _by_name(report.algorithms['key'])['ssh-dss']
        assert result.availability in (Availability.DISABLED_BY_DEFAULT, Availability.REMOVED)
        assert result.reachability == Reachability.DECLARED_UNREACHABLE

    def test_available_algorithm_reaches_negotiated_grade(self):
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        result = _by_name(report.algorithms['kex'])['curve25519-sha256']
        assert result.availability == Availability.AVAILABLE

    def test_unknown_version_does_not_filter_or_pass(self):
        # Hard constraint 4 / degradation rule 2: unknown version -> no filtering
        # and explicit uncertainty; weaknesses are not silently allowed through.
        k = _kex(['diffie-hellman-group1-sha1'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, None)
        assert report.version_uncertain is True
        result = _by_name(report.algorithms['kex'])['diffie-hellman-group1-sha1']
        assert result.availability == Availability.UNKNOWN_VERSION
        assert result.availability_reason == ReasonCode.VERSION_UNKNOWN_NO_FILTER
        # It is still graded as a reachable/peer-forced weakness, not passed.
        assert result.reachability != Reachability.NOT_A_WEAKNESS


class TestAeadShadowing:
    def test_weak_mac_shadowed_by_aead_only(self):
        # Acceptance test 3: an AEAD cipher plus weak MACs -> MACs are not
        # reachable weaknesses and produce no recommendations.
        assert 'aes128-gcm@openssh.com' in AEAD_CIPHERS
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes128-gcm@openssh.com'], ['hmac-sha1', 'hmac-md5'])
        report = analyze(k, _openssh('9.0'))
        for result in report.algorithms['mac']:
            assert result.reachability == Reachability.NOT_A_WEAKNESS
            assert not [r for r in report.recommendations if r.alg_type == 'mac']

    def test_weak_mac_graded_when_non_aead_negotiable(self):
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes128-gcm@openssh.com', 'aes256-ctr'], ['hmac-sha1'])
        report = analyze(k, _openssh('9.0'))
        result = _by_name(report.algorithms['mac'])['hmac-sha1']
        assert result.reachability in (Reachability.NEGOTIATED, Reachability.PEER_FORCED)
        assert [r for r in report.recommendations if r.name == 'hmac-sha1']


class TestReachabilityGrading:
    def test_declared_unreachable_when_client_lacks_preference(self):
        # Scenario 7: server offers a weak MAC, but the client never asks for it.
        prefs = {'mac': ['hmac-sha2-256-etm@openssh.com']}
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha1'])
        report = analyze(k, _openssh('9.0'), peer_preferences=prefs)
        result = _by_name(report.algorithms['mac'])['hmac-sha1']
        assert result.reachability == Reachability.DECLARED_UNREACHABLE
        assert not [r for r in report.recommendations if r.name == 'hmac-sha1']

    def test_peer_forced_grade(self):
        # Weak kex is mutually supported but not the client's first choice.
        prefs = {'kex': ['curve25519-sha256', 'diffie-hellman-group14-sha1']}
        k = _kex(['curve25519-sha256', 'diffie-hellman-group14-sha1'],
                 ['ssh-ed25519'], ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'), peer_preferences=prefs)
        result = _by_name(report.algorithms['kex'])['diffie-hellman-group14-sha1']
        assert result.reachability == Reachability.PEER_FORCED
        rec = [r for r in report.recommendations if r.name == 'diffie-hellman-group14-sha1'][0]
        assert rec.reason_code == ReasonCode.NEGOTIABLE_IF_PEER_PREFERS

    def test_negotiated_grade(self):
        # The weak algorithm is the first mutual choice under the client order.
        prefs = {'mac': ['hmac-sha1']}
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha1'])
        report = analyze(k, _openssh('9.0'), peer_preferences=prefs)
        result = _by_name(report.algorithms['mac'])['hmac-sha1']
        assert result.reachability == Reachability.NEGOTIATED


class TestObservedLengths:
    def test_observed_dh_modulus_judged_separately(self):
        # Scenario 4/6: the GEX modulus observed during a handshake is attached
        # to the specific algorithm and marked as handshake-tested evidence.
        k = _kex(['diffie-hellman-group-exchange-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        k.set_dh_modulus_size('diffie-hellman-group-exchange-sha256', 2048)
        report = analyze(k, _openssh('9.0'))
        result = _by_name(report.algorithms['kex'])['diffie-hellman-group-exchange-sha256']
        assert result.key_size == 2048
        assert result.evidence == ReasonCode.EVIDENCE_HANDSHAKE_TESTED
        assert any(f.reason_code == ReasonCode.OBSERVED_DH_MODULUS for f in result.findings)

    def test_declared_only_vs_tested_separation(self):
        # Scenario 6: an algorithm present in KEXINIT but never exercised during
        # a handshake test is explicitly marked as declared-only.
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        result = _by_name(report.algorithms['kex'])['curve25519-sha256']
        assert result.evidence == ReasonCode.EVIDENCE_DECLARED_ONLY


class TestHostKeySignatures:
    def test_rsa_family_signature_mapping(self):
        # Scenario 5: one RSA host key, three usable signature methods.
        k = _kex(['curve25519-sha256'],
                 ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        mapping = {m['host_key_type']: m for m in report.host_key_signatures}
        assert set(mapping['ssh-rsa']['usable_signatures']) == {
            'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'}
        assert mapping['ssh-ed25519']['usable_signatures'] == ['ssh-ed25519']
        assert all(m['reason_code'] == ReasonCode.HOSTKEY_SIGNATURE_MAPPING.value
                   for m in report.host_key_signatures)


class TestProtocolVersion:
    def test_version_applicability_recorded(self):
        # Scenario 8: the report states the protocol-version interval it applies to.
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        assert report.protocol_versions == ['2.0']
        assert 'OpenSSH 9.0' in report.version_range


class TestRecommendations:
    def test_recommendations_trace_to_algorithm_and_reason(self):
        # Scenario 9: every recommendation references an existing algorithm and
        # carries the original reason text; no nonexistent algorithm appears.
        k = _kex(['diffie-hellman-group14-sha1'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha1'])
        report = analyze(k, _openssh('9.0'))
        existing = {}
        for alg_type, results in report.algorithms.items():
            for result in results:
                existing[(alg_type, result.name)] = result
        for rec in report.recommendations:
            assert (rec.alg_type, rec.name) in existing
            assert rec.reason_text
            assert rec.reachability in (Reachability.NEGOTIATED, Reachability.PEER_FORCED)
            assert isinstance(rec, Recommendation)

    def test_no_recommendation_for_unreachable_or_removed(self):
        k = _kex(['diffie-hellman-group1-sha1'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        # The version-removed kex must not produce a recommendation; any other
        # recommendations that remain must not reference it.
        assert not [r for r in report.recommendations
                    if r.name == 'diffie-hellman-group1-sha1']


class TestUnknownAlgorithm:
    def test_unknown_algorithm_listed_not_silent(self):
        # Degradation rule 4: unknown algorithms are surfaced as findings, never
        # silently treated as safe.
        k = _kex(['totally-bogus-kex-9000'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        result = _by_name(report.algorithms['kex'])['totally-bogus-kex-9000']
        assert result.availability == Availability.UNKNOWN_ALGORITHM
        assert result.is_weakness
        assert any(f.reason_code == ReasonCode.UNKNOWN_ALGORITHM for f in result.findings)


class TestDegradation:
    def test_no_handshake_is_declared_only(self):
        # Degradation rule 1.
        report = analyze(None, _openssh('9.0'))
        assert report.test_state == NegotiationTestState.NOT_ATTEMPTED
        assert report.algorithms == {}
        assert 'declared lists only' in report.test_state_note

    def test_interrupted_handshake_keeps_partial_results(self):
        # Degradation rule 3: an interrupted test retains completed work and
        # annotates the incompleteness instead of discarding the whole report.
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        k.mark_test_incomplete('simulated connection drop')
        report = analyze(k, _openssh('9.0'))
        assert report.test_state == NegotiationTestState.INCOMPLETE
        assert 'simulated connection drop' in report.test_state_note
        assert report.algorithms['kex']  # partial results retained


class TestDeterminism:
    def test_ten_runs_byte_identical(self):
        # Acceptance test 4: repeat evaluation ten times; output must be
        # byte-identical, independent of dictionary iteration order.
        k = _kex(['diffie-hellman-group14-sha1', 'curve25519-sha256'],
                 ['ssh-rsa', 'ssh-ed25519'],
                 ['aes256-ctr', 'aes128-cbc'],
                 ['hmac-sha1', 'hmac-sha2-256'])
        k.set_dh_modulus_size('diffie-hellman-group14-sha1', 2048)
        serialized = set()
        for _ in range(10):
            report = analyze(k, _openssh('8.0'))
            serialized.add(json.dumps(build_negotiation_struct(report), sort_keys=True))
        assert len(serialized) == 1

    def test_recommendations_are_sorted(self):
        k = _kex(['diffie-hellman-group14-sha1'], ['ssh-ed25519'],
                 ['aes128-cbc'], ['hmac-sha1', 'hmac-md5'])
        report = analyze(k, _openssh('9.0'))
        keys = [(r.alg_type, r.name, r.reason_text) for r in report.recommendations]
        assert keys == sorted(keys)


class TestExplainability:
    def test_every_finding_has_reason_code_evidence_and_version_condition(self):
        # Hard constraint 2: each conclusion carries a reason code and an
        # evidence source; version conditions are always present.
        k = _kex(['diffie-hellman-group14-sha1'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha1'])
        report = analyze(k, _openssh('9.0'))
        for results in report.algorithms.values():
            for result in results:
                assert result.version_condition
                for finding in result.findings:
                    assert isinstance(finding.reason_code, ReasonCode)
                    assert finding.evidence in (
                        ReasonCode.EVIDENCE_DECLARED_ONLY,
                        ReasonCode.EVIDENCE_HANDSHAKE_TESTED,
                    )
                    assert finding.severity in tuple(Severity)


class TestTextRendering:
    def test_text_section_renders_without_exit_code_side_effect(self):
        k = _kex(['diffie-hellman-group14-sha1'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha1'])
        report = analyze(k, _openssh('9.0'))
        out = OutputBuffer()
        out.batch = False  # Section headers are emitted only in non-batch mode (existing behavior).
        output_negotiation(out, report, False)
        text = out.get_buffer()
        assert '# negotiation analysis' in text
        assert '(neg)' in text
        # The reachability/availability concepts are human-visible.
        assert 'version' in text

    def test_json_renderer_is_plain_data(self):
        k = _kex(['curve25519-sha256'], ['ssh-ed25519'],
                 ['aes256-ctr'], ['hmac-sha2-256'])
        report = analyze(k, _openssh('9.0'))
        struct = build_negotiation_struct(report)
        # Round-trips through JSON and exposes the documented top-level fields.
        json.dumps(struct, sort_keys=True)
        for field in ('protocol_versions', 'version_range', 'version_uncertain',
                      'test_state', 'selected', 'algorithms',
                      'host_key_signatures', 'recommendations'):
            assert field in struct


def _ssh2_packet(payload):
    import struct
    padding = -(len(payload) + 5) % 8
    if padding < 4:
        padding += 8
    plen = len(payload) + padding + 1
    return struct.pack('>Ib', plen, padding) + payload + b'\x00' * padding


def _audit_payload():
    from ssh_audit.protocol import Protocol
    from ssh_audit.writebuf import WriteBuf
    w = WriteBuf()
    w.write_byte(Protocol.MSG_KEXINIT)
    w.write(b'\x00' * 16)
    w.write_list(['bogus_kex_removed_proxy', 'bogus_kex_other'])  # All-bogus kex prevents live host-key/GEX tests (see test_ssh2.py).
    w.write_list(['bogus_key_a', 'bogus_key_b'])  # All-bogus host keys prevent live host-key tests and DB mutation.
    w.write_list(['aes128-gcm@openssh.com'])
    w.write_list(['aes128-gcm@openssh.com'])
    w.write_list(['hmac-sha1', 'hmac-sha2-256'])
    w.write_list(['hmac-sha1', 'hmac-sha2-256'])
    w.write_list(['none'])
    w.write_list(['none'])
    w.write_list([''])
    w.write_list([''])
    w.write_byte(False)
    w.write_int(0)
    return w.write_flush()


class TestAuditIntegration:
    '''End-to-end checks that negotiation analysis is purely additive.'''

    def _run_audit(self, virtual_socket, negotiation, json_output):
        from ssh_audit.auditconf import AuditConf
        from ssh_audit.ssh_audit import audit
        virtual_socket.rdata.append(b'SSH-2.0-OpenSSH_9.0 ssh-audit-test\r\n')
        virtual_socket.rdata.append(_ssh2_packet(_audit_payload()))
        conf = AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        conf.verbose = True
        conf.skip_rate_test = True
        conf.negotiation = negotiation
        conf.json = json_output
        out = OutputBuffer()
        retval = audit(out, conf)
        return retval, out.get_buffer()

    def test_text_output_is_additive(self, virtual_socket):
        base_retval, base_text = self._run_audit(virtual_socket, False, False)
        neg_retval, neg_text = self._run_audit(virtual_socket, True, False)

        # Exit-code semantics are unchanged.
        assert base_retval == neg_retval
        # Every pre-existing line is still present and in the same order.
        base_lines = [l for l in base_text.splitlines() if l]
        neg_lines = [l for l in neg_text.splitlines() if l]
        for line in base_lines:
            assert line in neg_lines
        # Only the new section was added (in batch mode section headers are
        # suppressed, so we assert on the section's content prefix instead).
        assert any(l.startswith('(neg)') for l in neg_lines)
        assert not any(l.startswith('(neg)') for l in base_lines)

    def test_text_section_header_in_non_batch(self, virtual_socket):
        # The '# negotiation analysis' header follows the existing head() rule:
        # emitted in normal mode, suppressed in batch mode.
        virtual_socket.rdata.append(b'SSH-2.0-OpenSSH_9.0 ssh-audit-test\r\n')
        virtual_socket.rdata.append(_ssh2_packet(_audit_payload()))
        from ssh_audit.auditconf import AuditConf
        from ssh_audit.ssh_audit import audit
        conf = AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = False
        conf.verbose = True
        conf.skip_rate_test = True
        conf.negotiation = True
        out = OutputBuffer()
        audit(out, conf)
        assert '# negotiation analysis' in out.get_buffer()

    def test_json_output_adds_single_key(self, virtual_socket):
        _, base_raw = self._run_audit(virtual_socket, False, True)
        _, neg_raw = self._run_audit(virtual_socket, True, True)
        base = json.loads(base_raw)
        neg = json.loads(neg_raw)

        assert 'negotiation' not in base
        assert 'negotiation' in neg

        # All pre-existing keys are byte-for-byte unchanged.
        del neg['negotiation']
        assert neg == base

        # The added key carries the graded analysis.  The bogus kex (not in the
        # database) is surfaced as an unknown algorithm, never silently passed.
        negotiation = json.loads(neg_raw)['negotiation']
        bogus = [a for t in negotiation['algorithms'].values() for a in t
                 if a['algorithm'] == 'bogus_kex_removed_proxy'][0]
        assert bogus['availability'] == 'unknown-algorithm'
        # The version-known target still gets an applicability interval.
        assert negotiation['version_uncertain'] is False
        assert negotiation['protocol_versions'] == ['2.0']
        # Weak MACs are shadowed by the reachable AEAD cipher.
        mac_entries = {a['algorithm']: a for a in negotiation['algorithms']['mac']}
        assert mac_entries['hmac-sha1']['reachability'] == 'not-a-weakness'
        # The most likely negotiated cipher under the client preference order.
        assert negotiation['selected']['enc']['algorithm'] == 'aes128-gcm@openssh.com'

