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
# pylint: disable=unused-import
import copy
import hashlib
import json

from typing import Dict, List, Optional, Set, Tuple, Any  # noqa: F401

from ssh_audit.banner import Banner
from ssh_audit.fingerprint import Fingerprint
from ssh_audit.policy import Policy
from ssh_audit.ssh2_kex import SSH2_Kex


class RemediationError(Exception):
    '''Raised when a remediation plan cannot be generated completely.  Callers must not emit a partial plan.'''


class Remediation:
    '''Derives an executable remediation plan from policy evaluation findings, and verifies whether applying it made the findings converge.

    Every expected value in a plan comes from the Policy object that produced the findings (via Policy.get_requirements()).  There is
    deliberately no second, hand-maintained list of "recommended" algorithms here: if the policy passes a check, no remediation is
    generated for it; if it fails, the remediation is computed from the same requirements the check used.
    '''

    VERSION = 1

    NO_ACTION_TEXT = 'No remediation needed.'

    # Algorithm families in the stable order in which plan entries are emitted.
    FAMILIES = ['key', 'kex', 'enc', 'mac', 'compression']

    # The config directive each algorithm family maps to.  In OpenSSH, both server and client use these same directive names.
    DIRECTIVES = {
        'key': 'HostKeyAlgorithms',
        'kex': 'KexAlgorithms',
        'enc': 'Ciphers',
        'mac': 'MACs',
        'compression': 'Compression',
    }

    # Maps a mismatched_field from Policy.evaluate_findings() to (category, family).
    _FIELD_MAP: List[Tuple[str, str, Optional[str]]] = [
        ('Banner', 'banner', None),
        ('Compression', 'compression', 'compression'),
        ('Host keys', 'algorithm_set', 'key'),
        ('Key exchanges', 'algorithm_set', 'kex'),
        ('Ciphers', 'cipher_suite', 'enc'),
        ('MACs', 'algorithm_set', 'mac'),
        ('Host key (', 'key_length', None),
        ('CA signature', 'key_length', None),
        ('Group exchange (', 'key_length', None),
    ]

    _FAMILY_FIELD = {'key': 'Host keys', 'kex': 'Key exchanges', 'enc': 'Ciphers', 'mac': 'MACs', 'compression': 'Compression'}
    _FAMILY_REQUIREMENT = {'key': 'host_keys', 'kex': 'kex', 'enc': 'ciphers', 'mac': 'macs', 'compression': 'compressions'}


    def __init__(self, policy: Policy, findings: List[Dict[str, Any]], server_policy: bool, host: str, port: int, banner: Optional[Banner], kex: Optional[SSH2_Kex]) -> None:
        self._policy = policy
        self._requirements = policy.get_requirements()
        # Keep the role so that client-specific directive names can be selected; the OpenSSH directives used today are shared by
        # both roles, but the planner must not silently assume a server policy.
        self._server_policy = server_policy
        self._host = host
        self._port = port
        self._banner = banner
        self._kex = kex

        # Normalize findings into stable, self-contained records.  Each record keeps the exact check it was generated from, so that
        # every remediation entry can point back to it during manual review.
        self._findings: List[Dict[str, Any]] = []
        for finding in findings:
            field = str(finding['mismatched_field'])
            category, family = self._classify_field(field)
            if category == 'unsupported':
                raise RemediationError('cannot derive remediation for policy field: %s' % field)
            self._findings.append({
                'id': 'F%02d' % (len(self._findings) + 1),
                'category': category,
                'field': field,
                'family': family,
                'expected_required': [str(x) for x in finding['expected_required']],
                'expected_optional': [str(x) for x in finding['expected_optional']],
                'actual': [str(x) for x in finding['actual']],
            })


    @staticmethod
    def _classify_field(field: str) -> Tuple[str, Optional[str]]:
        for prefix, category, family in Remediation._FIELD_MAP:
            if field == prefix or field.startswith(prefix):
                return category, family
        return 'unsupported', None


    # ------------------------------------------------------------------
    # Target fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def target_fingerprint(host: str, port: int, banner: Optional[Banner], kex: Optional[SSH2_Kex]) -> Dict[str, Any]:
        '''Computes a deterministic identity for the scanned target.  Host key fingerprints are used when they were obtained; otherwise the banner is the only observable identity.'''

        hostkey_fps: Dict[str, str] = {}
        if kex is not None:
            for host_key_type in sorted(kex.host_keys()):
                # Certificate host keys carry the same bytes as their certificate, so include each distinct key once under its
                # non-certificate name.  (The RSA family legitimately shares one key across three type names.)
                if '-cert-' in host_key_type:
                    continue
                raw = kex.host_keys()[host_key_type].get('raw_hostkey_bytes')
                if isinstance(raw, bytes) and len(raw) > 0:
                    hostkey_fps[host_key_type] = Fingerprint(raw).sha256

        payload = {
            'host': host,
            'port': port,
            'banner': str(banner) if banner is not None else '',
            'host_key_fingerprints': hostkey_fps,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()
        return {
            'sha256': digest,
            'host': host,
            'port': port,
            'banner': payload['banner'],
            'host_key_fingerprints': hostkey_fps,
        }


    # ------------------------------------------------------------------
    # Data availability
    # ------------------------------------------------------------------

    @staticmethod
    def _unique(values: List[str]) -> List[str]:
        ret: List[str] = []
        for value in values:
            if value not in ret and value != '':
                ret.append(value)
        return ret


    def _family_available(self, family: str) -> bool:
        if self._kex is None:
            return False
        if family == 'key':
            return len(self._kex.key_algorithms) > 0
        if family == 'kex':
            return len(self._kex.kex_algorithms) > 0
        if family == 'enc':
            return len(self._kex.server.encryption) > 0
        if family == 'mac':
            return len(self._kex.server.mac) > 0
        if family == 'compression':
            return len(self._kex.server.compression) > 0
        return False


    def _hostkey_size_available(self, hostkey_type: str) -> bool:
        if self._kex is None or hostkey_type not in self._kex.host_keys():
            return False
        size = self._kex.host_keys()[hostkey_type].get('hostkey_size', 0)
        return isinstance(size, int) and size > 0


    def _dh_size_available(self, dh_type: str) -> bool:
        if self._kex is None:
            return False
        sizes = self._kex.dh_modulus_sizes()
        return dh_type in sizes and int(sizes[dh_type]) > 0


    @staticmethod
    def _hostkey_type_from_field(field: str) -> Optional[str]:
        if field.startswith('Host key (') and field.endswith(') sizes'):
            return field[len('Host key ('):-len(') sizes')]
        return None


    @staticmethod
    def _dh_type_from_field(field: str) -> Optional[str]:
        if field.startswith('Group exchange (') and field.endswith(') modulus sizes'):
            return field[len('Group exchange ('):-len(') modulus sizes')]
        return None


    def _record_available(self, record: Dict[str, Any]) -> bool:
        family = record['family']
        if family is not None:
            return self._family_available(family)
        if record['category'] == 'banner':
            return self._banner is not None and str(self._banner) != ''
        if record['category'] == 'key_length':
            hostkey_type = self._hostkey_type_from_field(record['field'])
            if hostkey_type is not None:
                return self._hostkey_size_available(hostkey_type)
            dh_type = self._dh_type_from_field(record['field'])
            if dh_type is not None:
                return self._dh_size_available(dh_type)
            # CA signature checks are only emitted when a host key was measured.
            return self._kex is not None and len(self._kex.host_keys()) > 0
        return False


    # ------------------------------------------------------------------
    # Plan entries
    # ------------------------------------------------------------------

    def _order_sensitive(self, family: str) -> bool:
        # The policy compares compression lists exactly and in order regardless of the subset flag.
        if family == 'compression':
            return True
        if family == 'key':
            return not self._requirements['allow_hostkey_subset_and_reordering']
        return not self._requirements['allow_algorithm_subset_and_reordering']


    def _entry(self, category: str, action: str, directive: Optional[str], enable: List[str], disable: List[str], order_sensitive: bool, value: Optional[str], records: List[Dict[str, Any]], detail: str, requirements: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            'id': '',  # Assigned after all entries are collected, so IDs follow the stable output order.
            'category': category,
            'action': action,
            'directive': directive,
            'enable': list(enable),
            'disable': list(disable),
            'order_sensitive': order_sensitive,
            'value': value,
            'finding_ids': self._unique([record['id'] for record in records]),
            'checks': self._unique([record['field'] for record in records]),
            'detail': detail,
        }
        if requirements is not None:
            entry['requirements'] = requirements
        return entry


    def _algorithm_entries(self, family: str, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        '''Builds the remediation entries for one algorithm family.

        Exactly one entry is produced per configuration directive, even when several policy checks on that directive failed (e.g. a
        disallowed algorithm plus a missing strict key exchange marker): the single entry lists every finding it covers.'''

        if family == 'compression':
            return [self._compression_entry(records)]

        directive = self.DIRECTIVES[family]
        expected = [str(x) for x in (self._requirements[self._FAMILY_REQUIREMENT[family]] or [])]
        actual = self._unique([alg for record in records for alg in record['actual']])
        optional = set(str(x) for x in (self._requirements.get('optional_host_keys') or [])) if family == 'key' else set()

        strict_required: List[str] = []
        strict_missing: List[str] = []
        if family == 'kex':
            strict_required = [alg for alg in expected if alg.startswith('kex-strict-')]
            strict_missing = [alg for alg in strict_required if alg not in actual]

        if self._order_sensitive(family):
            # Exact match (including order): the suggested value fully describes the required state, marker included.
            entry = self._entry(
                category='cipher_suite' if family == 'enc' else 'algorithm_set',
                action='set_ciphers' if family == 'enc' else 'set_algorithms',
                directive=directive,
                enable=expected,
                disable=sorted([alg for alg in actual if alg not in expected]),
                order_sensitive=True,
                value=directive + ' ' + ','.join(expected),
                records=records,
                detail='the target must advertise exactly the policy algorithms, in the policy order',
            )
        else:
            # Subset and/or reordering allowed: anything the target advertises but the policy does not allow must be removed, and
            # any strictly-required marker that is absent must be enabled.
            disallowed = [alg for alg in actual if alg not in expected and alg not in optional]
            category = 'cipher_suite' if family == 'enc' else ('strict_kex' if len(strict_missing) > 0 else 'algorithm_set')
            if len(strict_missing) > 0:
                detail = 'the target does not advertise the strict key exchange marker(s) required as the Terrapin (CVE-2023-48795) countermeasure: %s' % ', '.join(strict_missing)
                if len(disallowed) > 0:
                    detail += '; it also advertises algorithms the policy does not allow'
            else:
                detail = 'the target advertises algorithms that the policy does not allow (subsets and reordering are otherwise permitted)'
            entry = self._entry(
                category=category,
                action='enable_strict_kex' if category == 'strict_kex' else ('set_ciphers' if family == 'enc' else 'set_algorithms'),
                directive=directive,
                enable=list(strict_missing),
                disable=sorted(disallowed),
                order_sensitive=False,
                value=None,
                records=records,
                detail=detail,
            )

        if len(strict_required) > 0:
            entry['strict_kex'] = {'required': strict_required, 'missing': strict_missing}

        return [entry]


    def _compression_entry(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        directive = self.DIRECTIVES['compression']
        expected = [str(x) for x in (self._requirements.get('compressions') or [])]
        actual = self._unique([alg for record in records for alg in record['actual']])
        expected_non_none = [alg for alg in expected if alg != 'none']

        if len(expected_non_none) == 0:
            return self._entry(
                category='compression',
                action='disable_compression',
                directive='Compression',
                enable=[],
                disable=sorted([alg for alg in actual if alg != 'none']),
                order_sensitive=True,
                value='Compression no',
                records=records,
                detail='compression must be disabled (the policy permits only "none")',
            )

        return self._entry(
            category='compression',
            action='set_compression',
            directive=directive,
            enable=list(expected_non_none),
            disable=sorted([alg for alg in actual if alg not in expected]),
            order_sensitive=True,
            value=None,
            records=records,
            detail='the policy permits only: %s' % ', '.join(expected),
        )


    def _key_length_entry(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        requirements: List[Dict[str, Any]] = []
        steps: List[str] = []
        for record in records:
            field = record['field']
            hostkey_type = self._hostkey_type_from_field(field)
            dh_type = self._dh_type_from_field(field)
            expected = int(record['expected_required'][0]) if record['expected_required'] and record['expected_required'][0].lstrip('-').isdigit() else 0
            actual = int(record['actual'][0]) if record['actual'] and record['actual'][0].lstrip('-').isdigit() else 0

            if hostkey_type is not None:
                requirements.append({'kind': 'host_key', 'name': hostkey_type, 'minimum_size': expected, 'actual_size': actual})
                steps.append('%s must be at least %d bits (target reported %d bits)' % (hostkey_type, expected, actual))
            elif dh_type is not None:
                requirements.append({'kind': 'dh_gex_minimum_modulus', 'name': dh_type, 'minimum_size': expected, 'actual_size': actual})
                steps.append('%s modulus must be at least %d bits (target reported %d bits)' % (dh_type, expected, actual))
            elif field.startswith('CA signature size'):
                ca_type = field[field.find('(') + 1:field.rfind(')')] if '(' in field else ''
                requirements.append({'kind': 'ca_key', 'name': ca_type, 'minimum_size': expected, 'actual_size': actual})
                steps.append('the CA signature must be at least %d bits (target reported %d bits)' % (expected, actual))
            elif field.startswith('CA signature type'):
                name = record['expected_required'][0] if record['expected_required'] else ''
                requirements.append({'kind': 'ca_key_type', 'name': name, 'minimum_size': 0, 'actual_size': 0})
                steps.append('the CA signature type must be %s' % name)

        return self._entry(
            category='key_length',
            action='increase_key_size',
            directive=None,
            enable=[],
            disable=[],
            order_sensitive=False,
            value=None,
            records=records,
            detail='; '.join(steps),
            requirements=requirements,
        )


    def _banner_entry(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        expected = self._requirements.get('banner')
        return self._entry(
            category='banner',
            action='set_banner',
            directive=None,
            enable=[],
            disable=[],
            order_sensitive=False,
            value=expected,
            records=records,
            detail='the target banner must be exactly %r' % expected,
        )


    def _insufficient(self, category: str, field: str, reason: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            'id': '',  # Assigned after all insufficient-basis records are collected.
            'category': category,
            'field': field,
            'reason': reason,
            'finding_ids': self._unique([record['id'] for record in records]),
        }


    # ------------------------------------------------------------------
    # Plan build
    # ------------------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        '''Builds the complete remediation plan.  Raises RemediationError on incomplete input rather than emitting a partial plan.'''

        entries: List[Dict[str, Any]] = []
        insufficient: List[Dict[str, Any]] = []

        groups: Dict[str, List[Dict[str, Any]]] = {}
        for record in self._findings:
            if record['category'] == 'key_length':
                group = 'key_length'
            elif record['category'] == 'banner':
                group = 'banner'
            else:
                group = str(record['family'])
            groups.setdefault(group, []).append(record)

        # Algorithm families, in stable order.
        for family in self.FAMILIES:
            records = groups.get(family, [])
            available = [record for record in records if self._record_available(record)]
            unavailable = [record for record in records if not self._record_available(record)]
            if len(unavailable) > 0:
                insufficient.append(self._insufficient(
                    'compression' if family == 'compression' else ('cipher_suite' if family == 'enc' else 'algorithm_set'),
                    self._FAMILY_FIELD[family],
                    'the target did not return negotiation data for this category; no remediation is guessed',
                    unavailable,
                ))
            if len(available) > 0:
                entries.extend(self._algorithm_entries(family, available))

        # Key length findings.
        key_length_records = groups.get('key_length', [])
        available = [record for record in key_length_records if self._record_available(record)]
        unavailable = [record for record in key_length_records if not self._record_available(record)]
        if len(unavailable) > 0:
            at_least_one = unavailable[0]
            insufficient.append(self._insufficient('key_length', at_least_one['field'], 'key size information was not obtained; no remediation is guessed', unavailable))
        if len(available) > 0:
            entries.append(self._key_length_entry(available))

        # Banner findings.
        banner_records = groups.get('banner', [])
        available_banner = [record for record in banner_records if self._record_available(record)]
        unavailable_banner = [record for record in banner_records if not self._record_available(record)]
        if len(unavailable_banner) > 0:
            insufficient.append(self._insufficient('banner', 'Banner', 'no banner was received; no remediation is guessed', unavailable_banner))
        if len(available_banner) > 0:
            entries.append(self._banner_entry(available_banner))

        # Any policy requirement whose evaluation was skipped for lack of data is reported as insufficient basis, not guessed at.
        insufficient.extend(self._global_insufficient(groups))

        for index, entry in enumerate(entries):
            entry['id'] = 'R%02d' % (index + 1)
        for index, record in enumerate(insufficient):
            record['id'] = 'I%02d' % (index + 1)

        fingerprint = self.target_fingerprint(self._host, self._port, self._banner, self._kex)
        no_action = len(entries) == 0 and len(insufficient) == 0

        return {
            'remediation_version': self.VERSION,
            'status': 'no_action_needed' if no_action else ('action_required' if len(entries) > 0 else 'insufficient_basis'),
            'no_action_needed': no_action,
            'target': fingerprint,
            'policy': {
                'name': self._requirements.get('name'),
                'version': self._requirements.get('version'),
                'name_and_version': self._policy.get_name_and_version(),
                'requirements': copy.deepcopy(self._requirements),
            },
            'findings': copy.deepcopy(self._findings),
            'entries': entries,
            'insufficient_basis': insufficient,
        }


    def _global_insufficient(self, groups: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        '''Returns insufficient-basis records for policy requirements whose checks could not be evaluated because the target did not
        supply the corresponding negotiation data.'''

        ret: List[Dict[str, Any]] = []

        for family in self.FAMILIES:
            requirement = self._requirements[self._FAMILY_REQUIREMENT[family]]
            if requirement is None or family in groups:
                continue
            if self._kex is None:
                reason = 'no key exchange packet was received; compliance cannot be evaluated'
            elif not self._family_available(family):
                reason = 'the target advertised no data for this algorithm category; compliance cannot be evaluated'
            else:
                continue
            ret.append(self._insufficient(
                'compression' if family == 'compression' else ('cipher_suite' if family == 'enc' else 'algorithm_set'),
                self._FAMILY_FIELD[family],
                reason,
                [],
            ))

        if self._kex is None:
            return ret

        # Host key sizes that the policy requires, and that the target advertised, but that could not be measured.
        hostkey_sizes = self._requirements.get('hostkey_sizes') or {}
        for hostkey_type in sorted(hostkey_sizes):
            if hostkey_type in self._kex.key_algorithms and not self._hostkey_size_available(hostkey_type):
                ret.append(self._insufficient('key_length', 'Host key (%s) sizes' % hostkey_type, 'the size of this host key was not measured; compliance cannot be evaluated', []))

        # Group exchange modulus sizes that the policy requires, and that the target offered, but that could not be measured.
        dh_sizes = self._requirements.get('dh_modulus_sizes') or {}
        for dh_type in sorted(dh_sizes):
            if dh_type in self._kex.kex_algorithms and not self._dh_size_available(dh_type):
                ret.append(self._insufficient('key_length', 'Group exchange (%s) modulus sizes' % dh_type, 'the group exchange modulus size was not measured; compliance cannot be evaluated', []))

        return ret


    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def to_json(plan: Dict[str, Any]) -> str:
        '''Returns a deterministic, structured representation of the plan.  Entries match to_text() one-to-one.'''
        return json.dumps(plan, indent=2, sort_keys=True)


    @staticmethod
    def to_text(plan: Dict[str, Any]) -> str:
        '''Returns a deterministic, human-readable representation of the plan.  Entries match to_json() one-to-one.'''

        target = plan.get('target', {})
        policy = plan.get('policy', {})
        entries = plan.get('entries', [])
        insufficient = plan.get('insufficient_basis', [])
        finding_fields = {finding['id']: finding['field'] for finding in plan.get('findings', [])}

        lines: List[str] = []
        lines.append('# SSH remediation plan')
        lines.append('Target: %s:%s' % (target.get('host', ''), target.get('port', '')))
        lines.append('Policy: %s' % policy.get('name_and_version', ''))
        lines.append('Target fingerprint: %s' % target.get('sha256', ''))

        if len(entries) == 0 and len(insufficient) == 0:
            lines.append('')
            lines.append(Remediation.NO_ACTION_TEXT)
            return '\n'.join(lines) + '\n'

        lines.append('')
        lines.append('# remediation items (%d)' % len(entries))
        for entry in entries:
            lines.append('')
            label = entry['checks'][0] if len(entry.get('checks', [])) > 0 else (entry.get('directive') or entry['category'])
            lines.append('[%s] %s' % (entry['id'], label))
            lines.append('  Category: %s' % entry['category'])
            lines.append('  Action: %s' % entry['action'])
            if entry.get('directive') is not None:
                lines.append('  Directive: %s' % entry['directive'])
            covers = ['%s (%s)' % (finding_id, finding_fields.get(finding_id, '?')) for finding_id in entry.get('finding_ids', [])]
            lines.append('  Covers: %s' % ', '.join(covers))
            if len(entry.get('enable', [])) > 0:
                lines.append('  Enable: %s' % ', '.join(entry['enable']))
            if len(entry.get('disable', [])) > 0:
                lines.append('  Disable: %s' % ', '.join(entry['disable']))
            # For exact-match checks the enabled list is the complete required value; restating it as "disabled" is meaningless.
            if len(entry.get('enable', [])) == 0 and len(entry.get('disable', [])) == 0:
                lines.append('  Algorithms: (none to enable or disable)')
            lines.append('  Order: %s' % ('exact order required' if entry.get('order_sensitive') else 'subset and/or reordering allowed'))
            if entry.get('value') is not None:
                lines.append('  Suggested setting: %s' % entry['value'])
            if 'strict_kex' in entry:
                missing = entry['strict_kex']['missing']
                lines.append('  Strict key exchange: required=%s missing=%s' % (', '.join(entry['strict_kex']['required']), ', '.join(missing) if len(missing) > 0 else 'none'))
            for requirement in entry.get('requirements', []):
                if requirement['minimum_size'] > 0:
                    lines.append('  Key size: %s >= %d bits' % (requirement['name'], requirement['minimum_size']))
                else:
                    lines.append('  Requirement: %s' % requirement['name'])
            lines.append('  Detail: %s' % entry['detail'])

        if len(insufficient) > 0:
            lines.append('')
            lines.append('# insufficient basis (%d)' % len(insufficient))
            for record in insufficient:
                lines.append('')
                lines.append('[%s] %s' % (record['id'], record['field']))
                lines.append('  Category: %s' % record['category'])
                lines.append('  Covers: %s' % (', '.join(record.get('finding_ids', [])) if len(record.get('finding_ids', [])) > 0 else 'none'))
                lines.append('  Reason: %s' % record['reason'])

        return '\n'.join(lines) + '\n'


    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    @staticmethod
    def _field_available(field: str, banner: Optional[Banner], kex: Optional[SSH2_Kex]) -> bool:
        '''Returns True when this policy check can be re-evaluated from the rescan data.  A check that cannot be evaluated must be
        reported as "unable to confirm", never as converged.'''

        if field == 'Banner':
            return banner is not None and str(banner) != ''
        if kex is None:
            return False
        if field == 'Compression':
            return len(kex.server.compression) > 0
        if field == 'Host keys':
            return len(kex.key_algorithms) > 0
        if field == 'Key exchanges':
            return len(kex.kex_algorithms) > 0
        if field == 'Ciphers':
            return len(kex.server.encryption) > 0
        if field == 'MACs':
            return len(kex.server.mac) > 0
        hostkey_type = Remediation._hostkey_type_from_field(field)
        if hostkey_type is not None:
            # If the target no longer advertises this host key type, the policy check no longer applies at all.
            if hostkey_type not in kex.key_algorithms:
                return True
            if hostkey_type not in kex.host_keys():
                return False
            size = kex.host_keys()[hostkey_type].get('hostkey_size', 0)
            return isinstance(size, int) and size > 0
        dh_type = Remediation._dh_type_from_field(field)
        if dh_type is not None:
            # If the target no longer offers this group exchange, the policy check no longer applies at all.
            if dh_type not in kex.kex_algorithms:
                return True
            sizes = kex.dh_modulus_sizes()
            return dh_type in sizes and int(sizes[dh_type]) > 0
        # CA signature checks are only meaningful when a host key was measured.
        return len(kex.host_keys()) > 0


    @staticmethod
    def _finding_diff(finding: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'expected_required': [str(x) for x in finding['expected_required']],
            'expected_optional': [str(x) for x in finding['expected_optional']],
            'actual': [str(x) for x in finding['actual']],
        }


    @staticmethod
    def verify(plan: Dict[str, Any], host: str, port: int, banner: Optional[Banner], kex: Optional[SSH2_Kex], scan_error: Optional[str] = None) -> Dict[str, Any]:
        '''Compares a rescan of the target against a previously generated plan.  Convergence is judged only from observable negotiation
        results, never from whether a local command was run.'''

        if 'policy' not in plan or not isinstance(plan['policy'], dict) or 'requirements' not in plan['policy']:
            raise RemediationError('the plan does not contain the policy requirements needed for verification')
        if 'target' not in plan or not isinstance(plan['target'], dict) or 'sha256' not in plan['target']:
            raise RemediationError('the plan does not contain a target fingerprint')

        current = Remediation.target_fingerprint(host, port, banner, kex)

        report: Dict[str, Any] = {
            'verification_version': Remediation.VERSION,
            'target': current,
            'plan_target': plan['target'],
            'fingerprint_match': False,
            'status': '',
            'reason': scan_error,
            'policy': plan['policy'].get('name_and_version'),
            'entries': [],
            'insufficient_basis': [],
            'unplanned': [],
        }

        # If the rescan could not negotiate at all, nothing can be confirmed; never report convergence on absent evidence.
        if kex is None or banner is None:
            if report['reason'] is None:
                report['reason'] = 'no banner or key exchange data was received from the target'
            report['status'] = 'unable_to_confirm'
            for entry in plan.get('entries', []):
                report['entries'].append({'id': entry['id'], 'category': entry['category'], 'action': entry.get('action'), 'directive': entry.get('directive'), 'status': 'unable_to_confirm', 'checks': [{'finding_id': finding_id, 'field': None, 'status': 'unable_to_confirm', 'diff': None} for finding_id in entry.get('finding_ids', [])]})
            for record in plan.get('insufficient_basis', []):
                report['insufficient_basis'].append({'id': record['id'], 'field': record['field'], 'category': record['category'], 'status': 'unable_to_confirm'})
            return report

        # Host key mismatches are tolerated when the plan itself calls for key regeneration (i.e.: a key-length remediation), since
        # replacing the key is exactly what such a remediation asks for.  Every other mismatch (host, port, banner, or keys) means the
        # target is not the one the plan was generated for.
        plan_regenerates_keys = any(entry.get('category') == 'key_length' for entry in plan.get('entries', []))
        plan_target = plan['target']
        endpoint_match = (current['host'] == plan_target.get('host') and current['port'] == plan_target.get('port'))
        banner_match = current['banner'] == plan_target.get('banner')
        keys_match = current['host_key_fingerprints'] == plan_target.get('host_key_fingerprints')
        fingerprint_match = endpoint_match and banner_match and (keys_match or plan_regenerates_keys)

        report['fingerprint_match'] = fingerprint_match

        if not fingerprint_match:
            # The target identity changed (different machine, different port, or different keys): refuse to judge convergence.
            report['status'] = 'fingerprint_mismatch'
            for entry in plan.get('entries', []):
                report['entries'].append({'id': entry['id'], 'category': entry['category'], 'action': entry.get('action'), 'directive': entry.get('directive'), 'status': 'unable_to_confirm', 'checks': [{'finding_id': finding_id, 'field': None, 'status': 'unable_to_confirm', 'diff': None} for finding_id in entry.get('finding_ids', [])]})
            for record in plan.get('insufficient_basis', []):
                report['insufficient_basis'].append({'id': record['id'], 'field': record['field'], 'category': record['category'], 'status': 'unable_to_confirm'})
            return report

        # Re-evaluate with the exact same rules and code path that produced the original findings.
        policy = Policy.from_requirements(plan['policy']['requirements'])
        rescan_findings = policy.evaluate_findings(banner, kex)
        by_field: Dict[str, List[Dict[str, Any]]] = {}
        for finding in rescan_findings:
            by_field.setdefault(str(finding['mismatched_field']), []).append(finding)

        plan_finding_fields = {finding['id']: finding['field'] for finding in plan.get('findings', [])}
        covered_fields: Set[str] = set()

        for entry in plan.get('entries', []):
            check_results: List[Dict[str, Any]] = []
            statuses: List[str] = []
            for finding_id in entry.get('finding_ids', []):
                field = plan_finding_fields.get(finding_id, '')
                covered_fields.add(field)
                if not Remediation._field_available(field, banner, kex):
                    status = 'unable_to_confirm'
                    diff: Optional[Dict[str, Any]] = None
                elif field in by_field:
                    status = 'not_converged'
                    diff = Remediation._finding_diff(by_field[field][0])
                else:
                    status = 'converged'
                    diff = None
                statuses.append(status)
                check_results.append({'finding_id': finding_id, 'field': field, 'status': status, 'diff': diff})

            if 'not_converged' in statuses:
                entry_status = 'not_converged'
            elif 'unable_to_confirm' in statuses:
                entry_status = 'unable_to_confirm'
            else:
                entry_status = 'converged'

            report['entries'].append({
                'id': entry['id'],
                'category': entry['category'],
                'action': entry.get('action'),
                'directive': entry.get('directive'),
                'status': entry_status,
                'checks': check_results,
            })

        for record in plan.get('insufficient_basis', []):
            field = record['field']
            covered_fields.add(field)
            if not Remediation._field_available(field, banner, kex):
                status = 'unable_to_confirm'
            elif field in by_field:
                status = 'not_converged'
            else:
                status = 'converged'
            report['insufficient_basis'].append({'id': record['id'], 'field': field, 'category': record['category'], 'status': status})

        for field in sorted(by_field):
            if field in covered_fields:
                continue
            report['unplanned'].append({'field': field, 'diff': Remediation._finding_diff(by_field[field][0])})

        all_statuses = [entry['status'] for entry in report['entries']] + [record['status'] for record in report['insufficient_basis']]
        if 'not_converged' in all_statuses or len(report['unplanned']) > 0:
            report['status'] = 'not_converged'
        elif 'unable_to_confirm' in all_statuses:
            report['status'] = 'unable_to_confirm'
        elif len(plan.get('entries', [])) == 0 and len(plan.get('insufficient_basis', [])) == 0:
            report['status'] = 'no_action_needed'
        else:
            report['status'] = 'converged'

        return report


    @staticmethod
    def verification_to_json(report: Dict[str, Any]) -> str:
        return json.dumps(report, indent=2, sort_keys=True)


    @staticmethod
    def verification_to_text(report: Dict[str, Any]) -> str:
        lines: List[str] = []
        target = report.get('target', {})
        lines.append('# SSH remediation verification')
        lines.append('Target: %s:%s' % (target.get('host', ''), target.get('port', '')))
        if report.get('policy') is not None:
            lines.append('Policy: %s' % report['policy'])
        lines.append('Fingerprint match: %s' % ('yes' if report.get('fingerprint_match') else 'no'))
        if report.get('reason'):
            lines.append('Scan error: %s' % report['reason'])
        lines.append('Result: %s' % str(report['status']).upper().replace('_', ' '))

        for entry in report.get('entries', []):
            lines.append('')
            lines.append('[%s] %s: %s' % (entry['id'], entry.get('directive') or entry.get('category'), entry['status']))
            for check in entry.get('checks', []):
                if check['status'] == 'converged':
                    lines.append('  - %s (%s): no longer reported' % (check['finding_id'], check['field']))
                elif check['status'] == 'unable_to_confirm':
                    lines.append('  - %s (%s): unable to confirm (negotiation data unavailable)' % (check['finding_id'], check['field']))
                else:
                    diff = check.get('diff') or {}
                    lines.append('  - %s (%s): still reported; expected=%s actual=%s' % (check['finding_id'], check['field'], ', '.join(diff.get('expected_required', [])), ', '.join(diff.get('actual', []))))

        for record in report.get('insufficient_basis', []):
            lines.append('')
            lines.append('[%s] %s: %s' % (record['id'], record['field'], record['status']))

        if len(report.get('unplanned', [])) > 0:
            lines.append('')
            lines.append('# unplanned findings (%d)' % len(report['unplanned']))
            for finding in report['unplanned']:
                diff = finding.get('diff') or {}
                lines.append('[?] %s: expected=%s actual=%s' % (finding['field'], ', '.join(diff.get('expected_required', [])), ', '.join(diff.get('actual', []))))

        return '\n'.join(lines) + '\n'
