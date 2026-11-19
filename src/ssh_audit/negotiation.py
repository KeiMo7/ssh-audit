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

   Negotiation analysis engine.

   This module is strictly additive: it never alters the per-algorithm
   findings produced by the rest of ssh-audit.  Instead it answers a separate
   question -- "what can actually be negotiated with this target, and how bad
   is that?" -- by combining three evidence sources:

     1. the algorithm names the peer declared in its KEXINIT message;
     2. the algorithm database (weakness reasons and version conditions);
     3. the algorithms that were actually exercised during live tests
        (host-key tests and Diffie-Hellman group-exchange tests).

   Every conclusion carries a reason code and an evidence source, and every
   recommendation points back to the algorithm and finding that produced it.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ssh_audit.algorithm import Algorithm
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB


# The client preference lists that ssh-audit sends during a normal audit
# (see SSH_Socket.send_kexinit()).  They are duplicated here deliberately so
# that negotiation analysis never depends on a network socket.  The lists
# represent the "client" side of the simulated negotiation.
def _default_client_preferences() -> Dict[str, List[str]]:
    return {
        'kex': [
            'mlkem768x25519-sha256', 'sntrup761x25519-sha512',
            'curve25519-sha256', 'curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
            'diffie-hellman-group14-sha256',
        ],
        'key': [
            'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa',
            'ecdsa-sha2-nistp256', 'ssh-ed25519',
        ],
        'enc': [
            'chacha20-poly1305@openssh.com',
            'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
            'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com',
        ],
        'mac': [
            'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com',
            'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
            'hmac-sha1-etm@openssh.com',
            'umac-64@openssh.com', 'umac-128@openssh.com',
            'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1',
        ],
    }


DEFAULT_CLIENT_PREFERENCES: Dict[str, List[str]] = _default_client_preferences()

# Stable processing/output order of the algorithm categories.
ALGORITHM_TYPES: Tuple[str, ...] = ('kex', 'key', 'enc', 'mac')

# Ciphers that provide authenticated encryption (AEAD).  When one of these is
# negotiated, the SSH transport does not run a separate MAC, so the peer's MAC
# list cannot turn into a reachable weakness on that connection.
AEAD_CIPHERS = frozenset([
    'chacha20-poly1305@openssh.com',
    'aes128-gcm@openssh.com',
    'aes256-gcm@openssh.com',
])


class ReasonCode(Enum):
    '''Stable machine-readable reason codes.  The human-readable text of a
    finding always comes from the algorithm database; these codes only
    classify *why* a conclusion was reached.'''

    # Version availability (scenario 1, 8).
    VERSION_AVAILABLE = 'version-available'
    VERSION_REMOVED = 'version-removed'
    VERSION_DISABLED = 'version-disabled'
    VERSION_UNKNOWN_NO_FILTER = 'version-unknown-no-filter'
    VERSION_NOT_APPLICABLE = 'version-not-applicable'

    # Reachability (scenario 2, 3, 7).
    NEGOTIATED_BY_DEFAULT = 'negotiated-by-default'
    NEGOTIABLE_IF_PEER_PREFERS = 'negotiable-if-peer-prefers'
    DECLARED_NOT_NEGOTIABLE = 'declared-not-negotiable'
    MAC_SHADOWED_BY_AEAD = 'mac-shadowed-by-aead'
    MAC_NEGOTIABLE_WITHOUT_AEAD = 'mac-negotiable-without-aead'

    # Evidence (scenario 6).
    EVIDENCE_DECLARED_ONLY = 'evidence-declared-only'
    EVIDENCE_HANDSHAKE_TESTED = 'evidence-handshake-tested'

    # Unknown algorithms (failure/degradation rule 4).
    UNKNOWN_ALGORITHM = 'unknown-algorithm'

    # Observed key material (scenario 4, 5).
    OBSERVED_KEY_SIZE = 'observed-key-size'
    OBSERVED_DH_MODULUS = 'observed-dh-modulus'
    HOSTKEY_SIGNATURE_MAPPING = 'hostkey-signature-mapping'


class Reachability(Enum):
    '''Reachability grading of a weakness (scenario 7).'''

    NEGOTIATED = 'negotiated'                       # A normal client lands on this.
    PEER_FORCED = 'peer-forced'                     # Reachable only if the peer insists.
    DECLARED_UNREACHABLE = 'declared-unreachable'   # Declared, but no client preference reaches it.
    NOT_A_WEAKNESS = 'not-a-weakness'               # Rated good, or shadowed by AEAD.


class Availability(Enum):
    '''Whether a declared algorithm can actually exist on the target version.'''

    AVAILABLE = 'available'
    REMOVED = 'removed'
    DISABLED_BY_DEFAULT = 'disabled-by-default'
    UNKNOWN_VERSION = 'unknown-version'
    UNKNOWN_ALGORITHM = 'unknown-algorithm'


class TestState(Enum):
    '''State of the live handshake tests for this audit.'''

    COMPLETED = 'completed'
    NOT_ATTEMPTED = 'not-attempted'     # No handshake could be completed.
    INCOMPLETE = 'incomplete'           # Connection dropped part-way through.


class Severity(Enum):
    '''The existing three grading levels; their meaning and priority are unchanged.'''

    FAIL = 'fail'
    WARN = 'warn'
    INFO = 'info'


# Info-note prefixes in the database that imply an algorithm was removed from,
# or disabled by default in, a specific release.  Used as a secondary signal
# alongside the version lists (the version lists remain the primary signal).
_REMOVED_INFO_PREFIXES = ('removed since', 'removed in')
_DISABLED_INFO_PREFIXES = ('disabled in', 'deprecated in')


@dataclass
class Finding:
    '''One weakness/observation attached to an algorithm.'''

    severity: Severity
    reason_code: ReasonCode
    text: str
    evidence: ReasonCode
    version_condition: str

    def to_dict(self) -> Dict[str, str]:
        return {
            'severity': self.severity.value,
            'reason_code': self.reason_code.value,
            'text': self.text,
            'evidence': self.evidence.value,
            'version_condition': self.version_condition,
        }


@dataclass
class AlgorithmResult:
    '''The full verdict for a single declared algorithm.'''

    alg_type: str
    name: str
    availability: Availability
    availability_reason: ReasonCode
    evidence: ReasonCode
    reachability: Reachability
    version_condition: str
    findings: List[Finding] = field(default_factory=list)
    key_size: Optional[int] = None

    @property
    def is_weakness(self) -> bool:
        return any(f.severity in (Severity.FAIL, Severity.WARN) for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        ret: Dict[str, Any] = {
            'algorithm': self.name,
            'availability': self.availability.value,
            'availability_reason': self.availability_reason.value,
            'evidence': self.evidence.value,
            'reachability': self.reachability.value,
            'version_condition': self.version_condition,
            'findings': [f.to_dict() for f in self.findings],
        }
        if self.key_size is not None:
            ret['key_size'] = self.key_size
        return ret


@dataclass
class Recommendation:
    '''A recommendation that always traces back to a concrete algorithm/finding.'''

    action: str               # 'del' | 'chg'
    alg_type: str
    name: str
    severity: Severity
    reason_code: ReasonCode
    reason_text: str
    reachability: Reachability

    def to_dict(self) -> Dict[str, str]:
        return {
            'action': self.action,
            'algorithm_type': self.alg_type,
            'algorithm': self.name,
            'severity': self.severity.value,
            'reason_code': self.reason_code.value,
            'reason': self.reason_text,
            'reachability': self.reachability.value,
        }


@dataclass
class NegotiationReport:
    protocol_versions: List[str]
    version_range: str
    version_uncertain: bool
    test_state: TestState
    test_state_note: str
    peer_preferences: Dict[str, List[str]]
    selected: Dict[str, Dict[str, str]]
    algorithms: Dict[str, List[AlgorithmResult]]
    host_key_signatures: List[Dict[str, Any]]
    recommendations: List[Recommendation]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'protocol_versions': list(self.protocol_versions),
            'version_range': self.version_range,
            'version_uncertain': self.version_uncertain,
            'test_state': self.test_state.value,
            'test_state_note': self.test_state_note,
            'peer_preferences': {k: list(v) for k, v in self.peer_preferences.items()},
            'selected': {k: dict(v) for k, v in self.selected.items()},
            'algorithms': {t: [a.to_dict() for a in results] for t, results in self.algorithms.items()},
            'host_key_signatures': [dict(m) for m in self.host_key_signatures],
            'recommendations': [r.to_dict() for r in self.recommendations],
        }


def _gss_normalize(alg_type: str, name: str) -> str:
    '''Normalize variable GSS algorithm names to the database wildcard form.'''
    if alg_type == 'kex' and name.startswith('gss-'):
        return name[0:name.rindex('-')] + '-*'
    return name


def _db_lookup(alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]], alg_type: str, name: str) -> Optional[List[List[Optional[str]]]]:
    return alg_db[alg_type].get(_gss_normalize(alg_type, name))


def select_preferred(peer_pref: List[str], server_list: List[str]) -> Optional[str]:
    '''Implements RFC 4253 section 7.1: the *client's* preference order
    decides, and the first client entry the server also offers is selected.

    The two lists may be in opposite orders; this still returns the most
    likely negotiated algorithm (scenario 2).
    '''
    server_set = set(server_list)
    for candidate in peer_pref:
        if candidate in server_set:
            return candidate
    return None


def _version_entries(desc: List[List[Optional[str]]]) -> List[str]:
    '''Returns the raw version strings recorded for an algorithm.'''
    versions = desc[0] if len(desc) > 0 else []
    return [v for v in (versions or []) if v]


def determine_availability(desc: Optional[List[List[Optional[str]]]], software: Optional[Software], for_server: bool) -> Tuple[Availability, ReasonCode, str]:
    '''Classifies whether an algorithm can actually be present on the target
    version (scenario 1).  Returns the availability, its reason code and a
    human-readable version condition.

    An unknown software/version never causes an algorithm to pass: when the
    version cannot be identified no version filtering is applied and the
    uncertainty is reported explicitly (hard constraint 4, degradation rule 2).
    '''
    if desc is None:
        return Availability.UNKNOWN_ALGORITHM, ReasonCode.VERSION_NOT_APPLICABLE, 'not present in algorithm database'

    if software is None:
        return Availability.UNKNOWN_VERSION, ReasonCode.VERSION_UNKNOWN_NO_FILTER, 'target version unknown; no version filtering applied'

    entries = _version_entries(desc)
    product = software.product

    applicable: List[Tuple[str, bool]] = []
    for entry in entries:
        for token in entry.split(','):
            ssh_product, ssh_version, is_client = Algorithm.get_ssh_version(token)
            if not ssh_version or ssh_product != product:
                continue
            if is_client and for_server:
                continue
            applicable.append((ssh_version, is_client))

    # The database has no version condition for this product.  This commonly
    # means the algorithm was never shipped by this product; report it rather
    # than silently treating it as available.
    if not applicable:
        condition = 'no {} version condition recorded in database'.format(product)
        return Availability.UNKNOWN_VERSION, ReasonCode.VERSION_NOT_APPLICABLE, condition

    # Primary signal: explicit end-version in the version list.
    if len(applicable) >= 2:
        v_from, _ = applicable[0]
        v_till, _ = applicable[1]
        if software.compare_version(v_till) > 0:
            return Availability.REMOVED, ReasonCode.VERSION_REMOVED, 'available in {} {}-{}; target is {}'.format(product, v_from, v_till, software.version)
        return Availability.AVAILABLE, ReasonCode.VERSION_AVAILABLE, 'available since {} {} (target {})'.format(product, v_from, software.version)

    v_from, _ = applicable[0]

    # Secondary signal: removal/deprecation info notes for this product.
    info_notes: List[str] = []
    if len(desc) > 3:
        info_notes = [t for t in desc[3] if t]
    for note in info_notes:
        lower = note.lower()
        if any(lower.startswith(p) for p in _REMOVED_INFO_PREFIXES):
            if product in note or product == Product.OpenSSH:
                # Extract the version number mentioned in the note, if any.
                tokens = [tok for tok in note.replace(':', ' ').split() if tok and tok[0].isdigit()]
                if tokens and software.compare_version(tokens[0]) > 0:
                    return Availability.REMOVED, ReasonCode.VERSION_REMOVED, '{}; target is {}'.format(note, software.version)
        if any(lower.startswith(p) for p in _DISABLED_INFO_PREFIXES):
            tokens = [tok for tok in note.replace(':', ' ').split() if tok and tok[0].isdigit()]
            if tokens and software.compare_version(tokens[0]) >= 0:
                return Availability.DISABLED_BY_DEFAULT, ReasonCode.VERSION_DISABLED, '{}; target is {}'.format(note, software.version)

    if software.compare_version(v_from) < 0:
        return Availability.REMOVED, ReasonCode.VERSION_REMOVED, 'first available in {} {}; target is {}'.format(product, v_from, software.version)
    return Availability.AVAILABLE, ReasonCode.VERSION_AVAILABLE, 'available since {} {} (target {})'.format(product, v_from, software.version)


def _is_aead(cipher_name: str) -> bool:
    return cipher_name in AEAD_CIPHERS


def _db_findings(desc: Optional[List[List[Optional[str]]]]) -> List[Tuple[Severity, str]]:
    '''Extracts the (severity, text) weakness notes from a database entry.'''
    if desc is None:
        return []
    ret: List[Tuple[Severity, str]] = []
    if len(desc) > 1:
        ret.extend((Severity.FAIL, t) for t in desc[1] if t)
    if len(desc) > 2:
        ret.extend((Severity.WARN, t) for t in desc[2] if t)
    return ret


def analyze(kex: Optional[SSH2_Kex],
            software: Optional[Software],
            for_server: bool = True,
            peer_preferences: Optional[Dict[str, List[str]]] = None,
            test_state: TestState = TestState.COMPLETED,
            test_state_note: str = '') -> NegotiationReport:
    '''Builds the full negotiation analysis report for one target.

    All ordering is explicit and deterministic: repeated calls on identical
    inputs produce byte-identical output (scenario 10).
    '''
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    alg_db = SSH2_KexDB.get_db()
    prefs = dict(DEFAULT_CLIENT_PREFERENCES)
    if peer_preferences is not None:
        for key, value in peer_preferences.items():
            prefs[key] = list(value)

    if kex is None:
        # Degradation rule 1: no handshake completed -> declared-list-only.
        # Respect an explicit caller override, but default to NOT_ATTEMPTED.
        effective_test_state = TestState.NOT_ATTEMPTED if test_state == TestState.COMPLETED else test_state
        effective_note = test_state_note
        return NegotiationReport(
            protocol_versions=[],
            version_range=_version_range(software),
            version_uncertain=software is None,
            test_state=effective_test_state,
            test_state_note=effective_note or 'handshake not completed; conclusions are based on declared lists only',
            peer_preferences=prefs,
            selected={},
            algorithms={},
            host_key_signatures=[],
            recommendations=[],
        )

    # The kex object records whether live tests were interrupted (degradation
    # rule 3); that takes precedence over the caller's default state.
    if kex.test_state == 'incomplete':
        effective_test_state = TestState.INCOMPLETE
        effective_note = kex.test_state_note or test_state_note or 'handshake tests were interrupted; partial results retained, untested items marked declared-only'
    else:
        effective_test_state = test_state
        effective_note = test_state_note

    declared_lists = {
        'kex': list(kex.kex_algorithms),
        'key': list(kex.key_algorithms),
        'enc': list(kex.server.encryption),
        'mac': list(kex.server.mac),
    }
    tested_host_keys = set(kex.host_keys().keys())
    tested_dh_moduli = dict(kex.dh_modulus_sizes())

    # Scenario 2: most likely negotiated algorithm per category.
    selected: Dict[str, Dict[str, str]] = {}
    for alg_type in ALGORITHM_TYPES:
        chosen = select_preferred(prefs.get(alg_type, []), declared_lists[alg_type])
        if chosen is not None:
            basis = 'RFC 4253: first entry of the client preference list that the server also offers'
            selected[alg_type] = {'algorithm': chosen, 'basis': basis}

    # Whether an AEAD cipher is reachable with the simulated client.
    server_ciphers = set(declared_lists['enc'])
    aead_reachable = any(c in server_ciphers for c in prefs['enc'] if _is_aead(c))
    non_aead_client_ciphers = [c for c in prefs['enc'] if not _is_aead(c)]
    non_aead_negotiable = select_preferred(non_aead_client_ciphers, declared_lists['enc']) is not None

    all_results: Dict[str, List[AlgorithmResult]] = {}
    recommendations: List[Recommendation] = []

    for alg_type in ALGORITHM_TYPES:
        results: List[AlgorithmResult] = []
        chosen_name = selected.get(alg_type, {}).get('algorithm')

        for name in declared_lists[alg_type]:
            desc = _db_lookup(alg_db, alg_type, name)
            availability, avail_reason, version_condition = determine_availability(desc, software, for_server)

            # Scenario 6: separate declared support from handshake-tested support.
            if alg_type == 'key' and name in tested_host_keys:
                evidence = ReasonCode.EVIDENCE_HANDSHAKE_TESTED
            elif alg_type == 'kex' and name in tested_dh_moduli:
                evidence = ReasonCode.EVIDENCE_HANDSHAKE_TESTED
            else:
                evidence = ReasonCode.EVIDENCE_DECLARED_ONLY

            db_weaknesses = _db_findings(desc)
            if desc is None:
                # Degradation rule 4: unknown algorithms are listed separately,
                # never silently passed as safe.
                db_weaknesses = [(Severity.WARN, SSH2_KexDB.FAIL_UNKNOWN)]

            # Observed key material (scenario 4: judge each observed length separately).
            key_size: Optional[int] = None
            if alg_type == 'kex' and name in tested_dh_moduli:
                key_size = tested_dh_moduli[name]
            elif alg_type == 'key' and name in kex.host_keys():
                key_size = kex.host_keys()[name].get('hostkey_size')  # type: ignore[assignment]

            findings: List[Finding] = []

            # Availability itself is recorded as a finding (info-level) so the
            # version condition is always explainable.
            findings.append(Finding(
                severity=Severity.INFO,
                reason_code=avail_reason,
                text=version_condition,
                evidence=evidence,
                version_condition=version_condition,
            ))

            # Scenario 1: removed / disabled-by-default items are not counted
            # as reachable weaknesses.
            version_blocks = availability in (Availability.REMOVED, Availability.DISABLED_BY_DEFAULT)

            for severity, text in db_weaknesses:
                if desc is None:
                    reason_code = ReasonCode.UNKNOWN_ALGORITHM
                else:
                    reason_code = ReasonCode.EVIDENCE_HANDSHAKE_TESTED if evidence == ReasonCode.EVIDENCE_HANDSHAKE_TESTED else ReasonCode.EVIDENCE_DECLARED_ONLY
                findings.append(Finding(
                    severity=severity,
                    reason_code=reason_code,
                    text=text,
                    evidence=evidence,
                    version_condition=version_condition,
                ))

            # Reachability grading (scenario 7), with AEAD shadowing for MACs (scenario 3).
            reachability = _grade_reachability(
                alg_type, name, chosen_name, prefs, declared_lists,
                aead_reachable, non_aead_negotiable, version_blocks,
                bool(db_weaknesses),
            )

            # Attach the observed modulus/key size as its own explainable finding.
            if key_size is not None:
                size_reason = ReasonCode.OBSERVED_DH_MODULUS if alg_type == 'kex' else ReasonCode.OBSERVED_KEY_SIZE
                findings.append(Finding(
                    severity=Severity.INFO,
                    reason_code=size_reason,
                    text='observed {} bits during handshake test'.format(key_size),
                    evidence=ReasonCode.EVIDENCE_HANDSHAKE_TESTED,
                    version_condition=version_condition,
                ))

            result = AlgorithmResult(
                alg_type=alg_type,
                name=name,
                availability=availability,
                availability_reason=avail_reason,
                evidence=evidence,
                reachability=reachability,
                version_condition=version_condition,
                findings=findings,
                key_size=key_size,
            )
            results.append(result)

            # Scenario 9: recommendations map 1:1 to reachable/peer-forced
            # weaknesses.  Unreachable and version-blocked items generate none.
            if result.is_weakness and reachability in (Reachability.NEGOTIATED, Reachability.PEER_FORCED):
                worst = _worst_text(db_weaknesses)
                if worst is not None:
                    recommendations.append(Recommendation(
                        action='del',
                        alg_type=alg_type,
                        name=name,
                        severity=worst[0],
                        reason_code=ReasonCode.NEGOTIATED_BY_DEFAULT if reachability == Reachability.NEGOTIATED else ReasonCode.NEGOTIABLE_IF_PEER_PREFERS,
                        reason_text=worst[1],
                        reachability=reachability,
                    ))

        all_results[alg_type] = results

    host_key_signatures = _host_key_signature_mapping(kex, tested_host_keys, alg_db, software)

    # Deterministic ordering (scenario 10): recommendations sorted by a total key.
    recommendations.sort(key=lambda r: (r.alg_type, r.name, r.action, r.reason_text))

    return NegotiationReport(
        protocol_versions=_protocol_versions(kex),
        version_range=_version_range(software),
        version_uncertain=software is None,
        test_state=effective_test_state,
        test_state_note=effective_note,
        peer_preferences=prefs,
        selected=selected,
        algorithms=all_results,
        host_key_signatures=host_key_signatures,
        recommendations=recommendations,
    )


def _grade_reachability(alg_type: str,
                        name: str,
                        chosen_name: Optional[str],
                        prefs: Dict[str, List[str]],
                        declared_lists: Dict[str, List[str]],
                        aead_reachable: bool,
                        non_aead_negotiable: bool,
                        version_blocks: bool,
                        has_db_weakness: bool) -> Reachability:
    '''Computes the reachability grade of an algorithm's weakness.'''
    if not has_db_weakness:
        return Reachability.NOT_A_WEAKNESS

    # MACs are special: with an authenticated-encryption cipher negotiated, no
    # standalone MAC participates in the exchange (scenario 3).
    if alg_type == 'mac':
        if aead_reachable and not non_aead_negotiable:
            return Reachability.NOT_A_WEAKNESS
        if aead_reachable and non_aead_negotiable:
            # Reachable only when the peer picks a non-AEAD cipher first.
            if name == chosen_name:
                return Reachability.NEGOTIATED
            if name in prefs.get('mac', []) and name in declared_lists['mac']:
                return Reachability.PEER_FORCED
            return Reachability.DECLARED_UNREACHABLE
        # No AEAD in play: normal grading applies.

    if version_blocks:
        # Declared, but the target version cannot actually offer it.
        return Reachability.DECLARED_UNREACHABLE

    if name == chosen_name:
        return Reachability.NEGOTIATED
    if name in prefs.get(alg_type, []) and name in declared_lists[alg_type]:
        return Reachability.PEER_FORCED
    return Reachability.DECLARED_UNREACHABLE


def _host_key_signature_mapping(kex: SSH2_Kex, tested_host_keys: set, alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]], software: Optional[Software]) -> List[Dict[str, Any]]:
    '''Scenario 5: maps each offered host-key type to the signature algorithms
    that can actually be used with it.'''
    mapping: List[Dict[str, Any]] = []

    # All RSA host-key types share one RSA key; the usable signatures are the
    # RSA family members the server actually offers.
    rsa_offered = [n for n in kex.key_algorithms if n in ('ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512')]

    for name in kex.key_algorithms:
        tested = name in tested_host_keys
        if name in ('ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'):
            signatures = sorted(rsa_offered)
            key_type = 'ssh-rsa (RSA family shares one host key)'
        elif name.startswith('ecdsa-sha2-'):
            signatures = [name]
            key_type = name
        elif name.startswith('ssh-ed25519') or name.startswith('sk-ssh-ed25519'):
            signatures = [name]
            key_type = name
        elif name.startswith('ssh-dss'):
            signatures = [name]
            key_type = name
        else:
            signatures = [name]
            key_type = name

        in_db = _db_lookup(alg_db, 'key', name) is not None
        mapping.append({
            'host_key_type': name,
            'key_type': key_type,
            'usable_signatures': signatures,
            'handshake_tested': tested,
            'known_algorithm': in_db,
            'reason_code': ReasonCode.HOSTKEY_SIGNATURE_MAPPING.value,
        })

    mapping.sort(key=lambda m: (m['host_key_type'], tuple(m['usable_signatures'])))
    return mapping


def _worst_text(weaknesses: List[Tuple[Severity, str]]) -> Optional[Tuple[Severity, str]]:
    for severity in (Severity.FAIL, Severity.WARN):
        for sev, text in weaknesses:
            if sev == severity:
                return sev, text
    return None


def _protocol_versions(kex: SSH2_Kex) -> List[str]:
    # ssh-audit's KEXINIT path only covers SSHv2; SSHv1 (if enabled) is flagged
    # separately from the banner.  The applicability interval is stated here.
    return ['2.0']


def _version_range(software: Optional[Software]) -> str:
    if software is None:
        return 'version unknown; conclusions are not version-filtered'
    return '{} {} and later-compatible observations on this target'.format(software.product, software.version)
