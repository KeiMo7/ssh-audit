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

   Rendering of the negotiation analysis report.  This is a separate output
   section and a separate JSON key: existing consumers see unchanged output
   unless negotiation analysis is explicitly requested (--negotiation).
"""
from typing import Any, Dict

from ssh_audit.negotiation import (
    AlgorithmResult,
    Availability,
    NegotiationReport,
    Reachability,
    Severity,
    TestState,
)
from ssh_audit.outputbuffer import OutputBuffer


# Reachability -> explanation shown in the text section.
_REACHABILITY_TEXT = {
    Reachability.NEGOTIATED: 'weakness is reachable: negotiated with a default client preference',
    Reachability.PEER_FORCED: 'weakness reachable only if the peer forces this algorithm',
    Reachability.DECLARED_UNREACHABLE: 'declared but not reachable by the analyzed client preferences',
    Reachability.NOT_A_WEAKNESS: 'not a reachable weakness',
}

_AVAILABILITY_TEXT = {
    Availability.AVAILABLE: 'available on this version',
    Availability.REMOVED: 'removed / unavailable on this version',
    Availability.DISABLED_BY_DEFAULT: 'present but disabled by default on this version',
    Availability.UNKNOWN_VERSION: 'version unknown; not filtered',
    Availability.UNKNOWN_ALGORITHM: 'unknown algorithm; not in database',
}

_TEST_STATE_TEXT = {
    TestState.COMPLETED: 'handshake tests completed',
    TestState.NOT_ATTEMPTED: 'handshake not completed; declared-list-only (unverified)',
    TestState.INCOMPLETE: 'handshake tests interrupted; partial results retained',
}


def _severity_color(out: OutputBuffer, severity: Severity) -> Any:
    if severity == Severity.FAIL:
        return out.fail
    if severity == Severity.WARN:
        return out.warn
    return out.good


def output_negotiation(out: OutputBuffer, report: NegotiationReport, is_json_output: bool) -> None:
    '''Renders the '# negotiation analysis' section (text mode only; JSON is
    emitted through build_struct).  Does not change the program exit code.'''
    if is_json_output:
        return

    with out:
        out.info('(neg) protocol version applicability: {}'.format(', '.join(report.protocol_versions) if report.protocol_versions else 'none observed'))
        out.info('(neg) version range: {}'.format(report.version_range))
        if report.version_uncertain:
            out.warn('(neg) target version could not be identified: no version filtering applied; availability is uncertain')
        state_fn = out.warn if report.test_state != TestState.COMPLETED else out.good
        note = ' ({})'.format(report.test_state_note) if report.test_state_note else ''
        state_fn('(neg) test state: {}{}'.format(_TEST_STATE_TEXT[report.test_state], note))

        # Scenario 2: most likely negotiated combination.
        for alg_type in ('kex', 'key', 'enc', 'mac'):
            if alg_type in report.selected:
                entry = report.selected[alg_type]
                out.good('(neg) likely negotiated {:>3}: {} -- {}'.format(alg_type, entry['algorithm'], entry['basis']))

        # Per-algorithm verdicts, grouped in stable category order.
        for alg_type in ('kex', 'key', 'enc', 'mac'):
            for result in report.algorithms.get(alg_type, []):
                _output_algorithm(out, alg_type, result)

        # Scenario 5: host-key / signature mapping.
        for mapping in report.host_key_signatures:
            tested = 'handshake-tested' if mapping['handshake_tested'] else 'declared only'
            known = 'known' if mapping['known_algorithm'] else 'UNKNOWN'
            out.info('(neg) host key {}: signatures [{}] ({}, {})'.format(
                mapping['host_key_type'], ', '.join(mapping['usable_signatures']), tested, known))

        # Scenario 9: recommendations, each traceable to an algorithm/reason.
        for rec in report.recommendations:
            fn = _severity_color(out, rec.severity)
            fn('(neg) recommendation: {} {} ({}) -- {} [{}]'.format(
                rec.action, rec.name, rec.alg_type, rec.reason_text, _REACHABILITY_TEXT[rec.reachability]))

    if not out.is_section_empty():
        out.head('# negotiation analysis')
        out.flush_section()
        out.sep()


def _output_algorithm(out: OutputBuffer, alg_type: str, result: AlgorithmResult) -> None:
    size_suffix = ''
    if result.key_size is not None:
        size_suffix = ' ({} bits observed)'.format(result.key_size)

    availability_fn = out.good
    if result.availability in (Availability.REMOVED, Availability.DISABLED_BY_DEFAULT):
        availability_fn = out.info
    elif result.availability in (Availability.UNKNOWN_VERSION, Availability.UNKNOWN_ALGORITHM):
        availability_fn = out.warn

    availability_fn('(neg) ({}) {}{}: {} [{}]'.format(
        alg_type, result.name, size_suffix,
        _AVAILABILITY_TEXT[result.availability], result.availability_reason.value))

    # Reachability line only for algorithms that carry a weakness.
    if result.is_weakness:
        reach = result.reachability
        fn = out.fail if reach == Reachability.NEGOTIATED else (out.warn if reach == Reachability.PEER_FORCED else out.info)
        fn('(neg)        {} -> {} [{}]'.format(result.name, _REACHABILITY_TEXT[reach], reach.value))

    # Scenario 6 / hard constraint 2: every finding shows reason code + evidence.
    for finding in result.findings:
        fn = _severity_color(out, finding.severity)
        fn('(neg)        [{}] {} (evidence: {}, {})'.format(
            finding.severity.value, finding.text, finding.evidence.value, finding.reason_code.value))


def build_negotiation_struct(report: NegotiationReport) -> Dict[str, Any]:
    '''Returns the JSON-serialisable negotiation structure (new top-level key).'''
    return report.to_dict()
