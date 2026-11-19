import json
import os
import re
import struct

import pytest

from ssh_audit import exitcodes
from ssh_audit.banner import Banner
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.protocol import Protocol
from ssh_audit.readbuf import ReadBuf
from ssh_audit.remediation import Remediation, RemediationError
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.ssh_audit import audit, process_commandline
from ssh_audit.writebuf import WriteBuf


# pylint: disable=attribute-defined-outside-init,line-too-long
class TestRemediation:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.AuditConf = ssh_audit.AuditConf
        self.OutputBuffer = OutputBuffer
        self.audit = audit
        self.process_commandline = process_commandline
        self.banner = Banner.parse('SSH-2.0-OpenSSH_9.6')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_kex(kex_algs, key_algs, ciphers, macs, compressions, host_keys=None, dh_sizes=None):
        cli = SSH2_KexParty(list(ciphers), list(macs), list(compressions), [''])
        srv = SSH2_KexParty(list(ciphers), list(macs), list(compressions), [''])
        kex = SSH2_Kex(OutputBuffer(), os.urandom(16), list(kex_algs), list(key_algs), cli, srv, False, 0)
        for host_key_type, raw, size in (host_keys or []):
            kex.set_host_key(host_key_type, raw, size, '', 0)
        for dh_type, size in (dh_sizes or []):
            kex.set_dh_modulus_size(dh_type, size)
        return kex

    @staticmethod
    def _policy(data):
        return Policy(policy_data=data)

    @staticmethod
    def _plan(policy, kex, banner=None):
        findings = policy.evaluate_findings(banner, kex)
        return Remediation(policy, findings, policy.is_server_policy(), 'localhost', 22, banner, kex).build()

    def _failing_setup(self):
        kex = self._make_kex(
            ['curve25519-sha256', 'diffie-hellman-group14-sha1'],
            ['ssh-ed25519', 'ssh-rsa'],
            ['aes128-ctr', 'aes128-cbc'],
            ['hmac-sha2-256', 'hmac-sha1'],
            ['none', 'zlib'],
            host_keys=[('ssh-ed25519', b'ed25519-key', 256), ('ssh-rsa', b'rsa-key', 1024)],
            dh_sizes=[('diffie-hellman-group-exchange-sha256', 2048)],
        )
        policy = self._policy('''name = "Remediation Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = none
host keys = ssh-ed25519
key exchanges = curve25519-sha256, kex-strict-s-v00@openssh.com
ciphers = aes128-ctr, aes256-ctr
macs = hmac-sha2-256
host_key_sizes = {"ssh-ed25519": {"hostkey_size": 256}, "ssh-rsa": {"hostkey_size": 3072}}
dh_modulus_sizes = {"diffie-hellman-group-exchange-sha256": 3072}
''')
        return policy, kex

    def _passing_setup(self):
        kex = self._make_kex(
            ['curve25519-sha256', 'kex-strict-s-v00@openssh.com'],
            ['ssh-ed25519'],
            ['aes128-ctr', 'aes256-ctr'],
            ['hmac-sha2-256'],
            ['none'],
            host_keys=[('ssh-ed25519', b'ed25519-key', 256)],
        )
        policy = self._policy('''name = "Remediation Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = none
host keys = ssh-ed25519
key exchanges = curve25519-sha256, kex-strict-s-v00@openssh.com
ciphers = aes128-ctr, aes256-ctr
macs = hmac-sha2-256
host_key_sizes = {"ssh-ed25519": {"hostkey_size": 256}}
''')
        return policy, kex

    # ------------------------------------------------------------------
    # One-to-one correspondence between findings and remediation items
    # ------------------------------------------------------------------

    def test_passing_evaluation_produces_no_remediation(self):
        '''A configuration that passes must not yield any suggestion.'''

        policy, kex = self._passing_setup()
        passed, errors, _ = policy.evaluate(self.banner, kex)
        assert passed is True
        assert len(errors) == 0

        plan = self._plan(policy, kex, self.banner)
        assert plan['status'] == 'no_action_needed'
        assert plan['no_action_needed'] is True
        assert plan['entries'] == []
        assert plan['insufficient_basis'] == []

        # Text export says so explicitly rather than printing an empty list.
        text = Remediation.to_text(plan)
        assert Remediation.NO_ACTION_TEXT in text
        assert 'remediation items' not in text

    def test_findings_and_entries_correspond_one_to_one(self):
        '''Every failed check is covered by a suggestion, and passing checks never appear.'''

        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        finding_fields = [finding['field'] for finding in plan['findings']]
        covered = [field for entry in plan['entries'] for field in entry['checks']]
        for field in finding_fields:
            assert field in covered, 'finding %r has no remediation entry' % field

        # Checks that the policy does not even check cannot appear (i.e.: no invented "banner" remediation).
        assert 'Banner' not in finding_fields
        assert all(entry['category'] != 'banner' for entry in plan['entries'])

        # Conversely, a passing category gets no remediation.  The policy allows subsets, so only disallowed algorithms and the missing
        # strict marker need remediation; no "enable everything" entry is produced for passing algorithms.
        ciphers_entry = [entry for entry in plan['entries'] if entry['directive'] == 'Ciphers'][0]
        assert ciphers_entry['enable'] == []
        assert ciphers_entry['disable'] == ['aes128-cbc']
        assert 'aes256-ctr' not in ciphers_entry['disable']

    def test_entries_point_back_to_findings(self):
        '''Each suggestion must reference the finding(s) that triggered it.'''

        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        finding_ids = set(finding['id'] for finding in plan['findings'])
        for entry in plan['entries']:
            assert len(entry['finding_ids']) > 0
            for finding_id in entry['finding_ids']:
                assert finding_id in finding_ids

        # Spot-check a concrete mapping: the compression finding drives the compression entry.
        compression_finding = [finding for finding in plan['findings'] if finding['field'] == 'Compression'][0]
        compression_entry = [entry for entry in plan['entries'] if entry['category'] == 'compression'][0]
        assert compression_finding['id'] in compression_entry['finding_ids']

        text = Remediation.to_text(plan)
        assert 'Covers: %s (Compression)' % compression_finding['id'] in text

    def test_same_directive_is_merged(self):
        '''A single configuration item hit by several findings yields one entry that lists all covered findings.'''

        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        # The failing kex list produces two policy findings: a disallowed algorithm and a missing strict-kex marker.  KexAlgorithms must
        # appear exactly once, and that entry must reference both findings.
        kex_findings = [finding['id'] for finding in plan['findings'] if finding['field'] == 'Key exchanges']
        assert len(kex_findings) == 2
        kex_entries = [entry for entry in plan['entries'] if entry['directive'] == 'KexAlgorithms']
        assert len(kex_entries) == 1
        assert set(kex_entries[0]['finding_ids']) == set(kex_findings)
        assert kex_entries[0]['disable'] == ['diffie-hellman-group14-sha1']
        assert kex_entries[0]['enable'] == ['kex-strict-s-v00@openssh.com']

        # No configuration directive appears more than once.
        directives = [entry['directive'] for entry in plan['entries'] if entry['directive'] is not None]
        assert len(directives) == len(set(directives))

    # ------------------------------------------------------------------
    # Distinct suggestion shapes per failure category
    # ------------------------------------------------------------------

    def test_categories_have_distinct_shapes(self):
        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)
        by_category = {}
        for entry in plan['entries']:
            by_category.setdefault(entry['category'], []).append(entry)

        assert set(by_category) == {'algorithm_set', 'cipher_suite', 'compression', 'key_length', 'strict_kex'}

        # Algorithm sets: an explicit set to disable, with the policy directive named.
        algorithm_sets = {entry['directive']: entry for entry in by_category['algorithm_set']}
        assert set(algorithm_sets) == {'HostKeyAlgorithms', 'MACs'}
        assert algorithm_sets['MACs']['action'] == 'set_algorithms'
        assert algorithm_sets['MACs']['disable'] == ['hmac-sha1']

        # Cipher suites are separate from generic algorithm sets.
        assert by_category['cipher_suite'][0]['directive'] == 'Ciphers'
        assert by_category['cipher_suite'][0]['disable'] == ['aes128-cbc']

        # Key length is not an enable/disable list at all.
        assert by_category['key_length'][0]['action'] == 'increase_key_size'
        assert by_category['key_length'][0]['directive'] is None
        assert by_category['key_length'][0]['enable'] == [] and by_category['key_length'][0]['disable'] == []

        # Compression is a boolean-style directive.
        assert by_category['compression'][0]['action'] == 'disable_compression'
        assert by_category['compression'][0]['value'] == 'Compression no'

        # Strict key exchange is its own category with an explicit missing marker, merged into the KexAlgorithms entry.
        assert by_category['strict_kex'][0]['action'] == 'enable_strict_kex'
        assert by_category['strict_kex'][0]['directive'] == 'KexAlgorithms'
        assert by_category['strict_kex'][0]['enable'] == ['kex-strict-s-v00@openssh.com']
        assert by_category['strict_kex'][0]['strict_kex'] == {'required': ['kex-strict-s-v00@openssh.com'], 'missing': ['kex-strict-s-v00@openssh.com']}
        assert 'KexAlgorithms' not in algorithm_sets

    def test_banner_and_key_type_failures_have_their_own_shape(self):
        '''Banner and CA-signature-type failures are neither algorithm lists nor key sizes; they get dedicated entries.'''

        kex = self._make_kex(['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'], ['none'], host_keys=[('ssh-ed25519', b'key', 256, )])
        # A CA signature type cannot be observed without a certificate; use a required banner instead, which is fully observable.
        policy = self._policy('''name = "Banner Policy"
version = 1
banner = "SSH-2.0-Expected"
ciphers = aes128-ctr
''')
        plan = self._plan(policy, kex, self.banner)
        assert [entry['category'] for entry in plan['entries']] == ['banner']
        banner_entry = plan['entries'][0]
        assert banner_entry['action'] == 'set_banner'
        assert banner_entry['value'] == 'SSH-2.0-Expected'
        assert banner_entry['order_sensitive'] is False

        # The banner check is observable in this rescan, so an unchanged banner is "not converged".
        report = Remediation.verify(plan, 'localhost', 22, self.banner, kex)
        assert report['status'] == 'not_converged'

    def test_client_policy_uses_client_directives(self):
        '''Client policies produce the same directive shapes, without assuming a server role.'''

        kex = self._make_kex(['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr', 'aes128-cbc'], ['hmac-sha2-256'], ['none'])
        policy = self._policy('''name = "Client Policy"
version = 1
client policy = true
allow_algorithm_subset_and_reordering = true
ciphers = aes128-ctr
''')
        assert policy.is_server_policy() is False
        plan = self._plan(policy, kex, self.banner)
        cipher_entry = [entry for entry in plan['entries'] if entry['category'] == 'cipher_suite'][0]
        assert cipher_entry['directive'] == 'Ciphers'
        assert cipher_entry['disable'] == ['aes128-cbc']

    def test_order_requirement_is_reported(self):
        '''The suggestion states whether ordering matters, mirroring the policy's comparison mode.'''

        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)
        # This policy allows subsets/reordering for algorithms but compares compression exactly.
        cipher_entry = [entry for entry in plan['entries'] if entry['directive'] == 'Ciphers'][0]
        compression_entry = [entry for entry in plan['entries'] if entry['directive'] == 'Compression'][0]
        assert cipher_entry['order_sensitive'] is False
        assert compression_entry['order_sensitive'] is True

        exact_kex = self._make_kex(['curve25519-sha256', 'diffie-hellman-group14-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'], ['none'])
        exact_policy = self._policy('''name = "Exact"
version = 1
compressions = none
host keys = ssh-ed25519
key exchanges = curve25519-sha256, diffie-hellman-group16-sha512
ciphers = aes128-ctr
macs = hmac-sha2-256
''')
        exact_plan = self._plan(exact_policy, exact_kex, self.banner)
        kex_entry = [entry for entry in exact_plan['entries'] if entry['directive'] == 'KexAlgorithms'][0]
        assert kex_entry['order_sensitive'] is True
        assert kex_entry['value'] == 'KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512'

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def test_rescan_converges(self):
        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        fixed_kex = self._make_kex(
            ['curve25519-sha256', 'kex-strict-s-v00@openssh.com'],
            ['ssh-ed25519'],
            ['aes128-ctr', 'aes256-ctr'],
            ['hmac-sha2-256'],
            ['none'],
            host_keys=[('ssh-ed25519', b'ed25519-key', 256)],
        )
        report = Remediation.verify(plan, 'localhost', 22, self.banner, fixed_kex)
        assert report['fingerprint_match'] is True
        assert report['status'] == 'converged'
        assert all(entry['status'] == 'converged' for entry in report['entries'])

    def test_rescan_keeps_unremediated_items_with_diff(self):
        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        # Everything is fixed except the cipher list.
        partial_kex = self._make_kex(
            ['curve25519-sha256', 'kex-strict-s-v00@openssh.com'],
            ['ssh-ed25519'],
            ['aes128-ctr', 'aes128-cbc'],
            ['hmac-sha2-256'],
            ['none'],
            host_keys=[('ssh-ed25519', b'ed25519-key', 256)],
        )
        report = Remediation.verify(plan, 'localhost', 22, self.banner, partial_kex)
        assert report['status'] == 'not_converged'

        by_id = {entry['id']: entry for entry in report['entries']}
        cipher_entry = [entry for entry in report['entries'] if entry['directive'] == 'Ciphers'][0]
        assert by_id[cipher_entry['id']]['status'] == 'not_converged'
        diff = cipher_entry['checks'][0]['diff']
        assert diff['actual'] == ['aes128-ctr', 'aes128-cbc']
        assert 'aes128-ctr, aes256-ctr' in Remediation.verification_to_text(report)

    def test_unreachable_target_is_never_converged(self):
        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        report = Remediation.verify(plan, 'localhost', 22, None, None, scan_error='[exception] cannot connect')
        assert report['status'] == 'unable_to_confirm'
        assert all(entry['status'] == 'unable_to_confirm' for entry in report['entries'])
        assert 'CONVERGED' not in Remediation.verification_to_text(report).replace('NOT CONVERGED', '')

    def test_changed_target_refuses_to_judge_convergence(self):
        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        # Same data, different endpoint (port changed).
        report = Remediation.verify(plan, 'localhost', 2222, self.banner, kex)
        assert report['fingerprint_match'] is False
        assert report['status'] == 'fingerprint_mismatch'
        assert all(entry['status'] == 'unable_to_confirm' for entry in report['entries'])

        # Same endpoint, different banner (a different machine).
        other_banner = Banner.parse('SSH-2.0-OpenSSH_8.9')
        report = Remediation.verify(plan, 'localhost', 22, other_banner, kex)
        assert report['status'] == 'fingerprint_mismatch'

    def test_verification_uses_the_same_evaluation_rules(self):
        '''Convergence is determined by the same code path as the original evaluation.'''

        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        # A rescan that still fails produces exactly the same findings as a fresh evaluation of the same requirements.
        report = Remediation.verify(plan, 'localhost', 22, self.banner, kex)
        rebuilt = Policy.from_requirements(plan['policy']['requirements'])
        expected_fields = [finding['mismatched_field'] for finding in rebuilt.evaluate_findings(self.banner, kex)]
        reported_fields = [check['field'] for entry in report['entries'] for check in entry['checks']]
        # Every entry check points at a real check field, and each entry-level finding maps to the same failure the policy reports.
        for field in reported_fields:
            assert field in expected_fields
        assert set(reported_fields) == set(expected_fields)
        assert report['status'] == 'not_converged'

    # ------------------------------------------------------------------
    # Stability and export
    # ------------------------------------------------------------------

    def test_repeated_generation_is_byte_identical(self):
        policy, kex = self._failing_setup()
        first = self._plan(policy, kex, self.banner)
        second = self._plan(policy, kex, self.banner)

        assert Remediation.to_json(first) == Remediation.to_json(second)
        assert Remediation.to_text(first) == Remediation.to_text(second)

        report_first = Remediation.verify(first, 'localhost', 22, self.banner, kex)
        report_second = Remediation.verify(second, 'localhost', 22, self.banner, kex)
        assert Remediation.verification_to_json(report_first) == Remediation.verification_to_json(report_second)
        assert Remediation.verification_to_text(report_first) == Remediation.verification_to_text(report_second)

    def test_text_and_json_entries_correspond(self):
        policy, kex = self._failing_setup()
        plan = self._plan(policy, kex, self.banner)

        structured = json.loads(Remediation.to_json(plan))
        text = Remediation.to_text(plan)

        json_ids = [entry['id'] for entry in structured['entries']]
        text_ids = re.findall(r'^\[(R\d+)\]', text, re.MULTILINE)
        assert json_ids == text_ids
        assert len(json_ids) == len(structured['entries'])

        # Insufficient-basis items correspond as well.
        json_i_ids = [record['id'] for record in structured['insufficient_basis']]
        text_i_ids = re.findall(r'^\[(I\d+)\]', text, re.MULTILINE)
        assert json_i_ids == text_i_ids

    # ------------------------------------------------------------------
    # Insufficient basis and hard failure
    # ------------------------------------------------------------------

    def test_missing_negotiation_data_is_flagged_not_guessed(self):
        '''When a whole category of negotiation data is absent, say so instead of inventing a suggestion.'''

        policy, kex = self._failing_setup()
        findings = policy.evaluate_findings(self.banner, kex)

        # Simulate a scan whose cipher list was not obtained.
        plan = Remediation(policy, findings, True, 'localhost', 22, self.banner, kex).build()
        with_entries = len(plan['entries'])

        # With no key exchange data at all, every requirement that depends on it is "insufficient basis".
        empty_plan = Remediation(policy, findings, True, 'localhost', 22, self.banner, None).build()
        assert empty_plan['status'] == 'insufficient_basis'
        assert len(empty_plan['entries']) == 0
        assert len(empty_plan['insufficient_basis']) > 0
        reasons = [record['reason'] for record in empty_plan['insufficient_basis']]
        assert all('no remediation is guessed' in reason or 'cannot be evaluated' in reason for reason in reasons)
        assert with_entries > 0

    def test_partial_plan_is_never_emitted_on_error(self):
        policy, kex = self._failing_setup()
        findings = policy.evaluate_findings(self.banner, kex)
        findings[0]['mismatched_field'] = 'Some Future Policy Field'
        with pytest.raises(RemediationError):
            Remediation(policy, findings, True, 'localhost', 22, self.banner, kex).build()

    # ------------------------------------------------------------------
    # CLI-level behavior
    # ------------------------------------------------------------------

    @staticmethod
    def _payload(kex_algs, key_algs, ciphers, macs, compressions):
        w = WriteBuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(kex_algs)
        w.write_list(key_algs)
        w.write_list(ciphers)
        w.write_list(ciphers)
        w.write_list(macs)
        w.write_list(macs)
        w.write_list(compressions)
        w.write_list(compressions)
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return w.write_flush()

    @staticmethod
    def _packet(payload):
        padding = -(len(payload) + 5) % 8
        if padding < 4:
            padding += 8
        plen = len(payload) + padding + 1
        return struct.pack('>Ib', plen, padding) + payload + (b'\x00' * padding)

    def _feed(self, vsocket, kex_algs, key_algs, ciphers, macs, compressions, banner=b'SSH-2.0-OpenSSH_9.6 ssh-audit-test\r\n'):
        w = WriteBuf()
        w.write_byte(Protocol.MSG_KEXINIT)
        w.write(self._payload(kex_algs, key_algs, ciphers, macs, compressions))
        vsocket.rdata.append(banner)
        vsocket.rdata.append(self._packet(w.write_flush()))

    def _run_audit(self, out, aconf):
        return self.audit(out, aconf)

    def test_cli_generates_and_verifies_plan(self, tmp_path, virtual_socket):
        policy_data = '''name = "CLI Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = none
host keys = ssh-ed25519
key exchanges = curve25519-sha256
ciphers = aes128-ctr
macs = hmac-sha2-256
'''
        policy_path = tmp_path / 'policy.txt'
        policy_path.write_text(policy_data, encoding='utf-8')
        plan_path = tmp_path / 'plan.json'

        args = ['-P', str(policy_path), '--remediation', '--remediation-format', 'json', '--remediation-out', str(plan_path), 'localhost']
        out = OutputBuffer()
        aconf = self.process_commandline(out, args)
        aconf.skip_rate_test = True
        self._feed(virtual_socket, ['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr', 'aes128-cbc'], ['hmac-sha2-256'], ['none'])
        ret = self._run_audit(out, aconf)
        out.write()
        assert ret == exitcodes.FAILURE

        plan = json.loads(plan_path.read_text(encoding='utf-8'))
        assert plan['status'] == 'action_required'
        assert [entry['directive'] for entry in plan['entries']] == ['Ciphers']
        assert plan['entries'][0]['disable'] == ['aes128-cbc']

        # Rescan: the cipher list is now compliant.
        out = OutputBuffer()
        aconf = self.process_commandline(out, ['-P', str(policy_path), '--remediation-verify', str(plan_path), 'localhost'])
        aconf.skip_rate_test = True
        self._feed(virtual_socket, ['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'], ['none'])
        ret = self._run_audit(out, aconf)
        out.write()
        assert ret == exitcodes.GOOD

    def test_cli_unreachable_rescan_is_not_converged(self, tmp_path):
        from ssh_audit.policy import Policy as PolicyClass
        policy_data = 'name = "P"\nversion = 1\nciphers = aes128-ctr\n'
        policy_path = tmp_path / 'policy.txt'
        policy_path.write_text(policy_data, encoding='utf-8')

        # Build and store a plan without touching the network.
        kex = self._make_kex(['curve25519-sha256'], ['ssh-ed25519'], ['aes128-cbc'], ['hmac-sha2-256'], ['none'])
        plan = self._plan(PolicyClass(policy_data=policy_data), kex, self.banner)
        plan_path = tmp_path / 'plan.json'
        plan_path.write_text(Remediation.to_json(plan), encoding='utf-8')

        out = OutputBuffer()
        aconf = self.process_commandline(out, ['-P', str(policy_path), '--remediation-verify', str(plan_path), '--remediation-format', 'json', '--remediation-out', str(tmp_path / 'report.json'), 'localhost'])
        aconf.skip_rate_test = True
        # No rdata: the connection resolves and connects, but negotiation yields nothing.
        ret = self._run_audit(out, aconf)
        out.write()
        report = json.loads((tmp_path / 'report.json').read_text(encoding='utf-8'))
        assert report['status'] == 'unable_to_confirm'
        assert ret == exitcodes.CONNECTION_ERROR

    def test_cli_no_action_needed(self, tmp_path, virtual_socket):
        policy_data = '''name = "Already Compliant"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = none
host keys = ssh-ed25519
key exchanges = curve25519-sha256
ciphers = aes128-ctr
macs = hmac-sha2-256
'''
        policy_path = tmp_path / 'policy.txt'
        policy_path.write_text(policy_data, encoding='utf-8')

        out = OutputBuffer()
        aconf = self.process_commandline(out, ['-P', str(policy_path), '--remediation', 'localhost'])
        aconf.skip_rate_test = True
        self._feed(virtual_socket, ['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'], ['none'])
        ret = self._run_audit(out, aconf)
        rendered = out.get_buffer()
        assert ret == exitcodes.GOOD
        assert Remediation.NO_ACTION_TEXT in rendered

    def test_existing_policy_audit_output_is_unchanged(self, virtual_socket, tmp_path):
        '''Policy audits without the new flags behave exactly as before.'''

        policy_data = 'name = "Plain"\nversion = 1\nciphers = aes128-ctr\n'
        policy_path = tmp_path / 'policy.txt'
        policy_path.write_text(policy_data, encoding='utf-8')

        out = OutputBuffer()
        aconf = self.process_commandline(out, ['-P', str(policy_path), '-n', 'localhost'])
        aconf.skip_rate_test = True
        self._feed(virtual_socket, ['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'], ['none'])
        ret = self._run_audit(out, aconf)
        rendered = out.get_buffer()
        assert ret == exitcodes.GOOD
        # Strip any ANSI color sequences (process_commandline() re-derives color support).
        rendered = re.sub(r'\x1b\[\d+?m', '', rendered)
        assert 'Result: ✔ Passed' in rendered
        assert 'remediation' not in rendered.lower()

    def test_cli_requires_policy(self, tmp_path):
        '''--remediation without a policy is rejected instead of guessing at a baseline.'''

        out = OutputBuffer()
        with pytest.raises(SystemExit) as excinfo:
            self.process_commandline(out, ['--remediation', 'localhost'])
        assert excinfo.value.code == exitcodes.UNKNOWN_ERROR

    def test_cli_plan_round_trips_through_json(self, tmp_path, virtual_socket):
        '''A plan written to disk in JSON can be re-loaded and verified, proving the structured form is self-contained.'''

        policy_data = '''name = "Round Trip"
version = 1
allow_algorithm_subset_and_reordering = true
ciphers = aes128-ctr
'''
        policy_path = tmp_path / 'policy.txt'
        policy_path.write_text(policy_data, encoding='utf-8')
        plan_path = tmp_path / 'plan.json'

        out = OutputBuffer()
        aconf = self.process_commandline(out, ['-P', str(policy_path), '--remediation', '--remediation-format', 'json', '--remediation-out', str(plan_path), 'localhost'])
        aconf.skip_rate_test = True
        self._feed(virtual_socket, ['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'], ['none'])
        assert self._run_audit(out, aconf) == exitcodes.GOOD
        out.write()

        reloaded = json.loads(plan_path.read_text(encoding='utf-8'))
        assert reloaded['no_action_needed'] is True

        # Verify the same (compliant) target against the reloaded plan.  The banner must match the one in the plan.
        verify_banner = Banner.parse('SSH-2.0-OpenSSH_9.6 ssh-audit-test')
        report = Remediation.verify(reloaded, 'localhost', 22, verify_banner, self._make_kex(['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'], ['none']))
        assert report['status'] == 'no_action_needed'

    def test_cli_insufficient_basis_is_reported(self, tmp_path, virtual_socket):
        '''A scan that yields no negotiation data reports insufficient basis rather than a bogus pass or suggestion.'''

        policy_data = 'name = "P"\nversion = 1\nciphers = aes128-ctr\n'
        policy_path = tmp_path / 'policy.txt'
        policy_path.write_text(policy_data, encoding='utf-8')
        report_path = tmp_path / 'plan.json'

        out = OutputBuffer()
        aconf = self.process_commandline(out, ['-P', str(policy_path), '--remediation', '--remediation-format', 'json', '--remediation-out', str(report_path), 'localhost'])
        aconf.skip_rate_test = True
        # Banner only: never answers with a KEXINIT.
        virtual_socket.rdata.append(b'SSH-2.0-OpenSSH_9.6 test\r\n')
        ret = self._run_audit(out, aconf)
        out.write()

        plan = json.loads(report_path.read_text(encoding='utf-8'))
        assert plan['status'] == 'insufficient_basis'
        assert plan['entries'] == []
        assert len(plan['insufficient_basis']) > 0
        assert ret == exitcodes.CONNECTION_ERROR
