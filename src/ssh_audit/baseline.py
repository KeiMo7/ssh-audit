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

Historical baseline comparisons, regression detection and exception handling.

Design notes
------------
* The baseline is a machine-readable scan result produced by a previous run
  (see build_struct() in ssh_audit.py), optionally carrying a 'scan_meta'
  block.  It is never another policy file.
* Differences are produced first, independently of the strict/lenient mode.
  The mode only decides whether a given difference counts as a regression;
  this keeps comparison decoupled from policy evaluation.
* Regression direction is always security-negative.  Hardening (removing a
  weak algorithm, increasing a key length) is explicitly never a regression.
* Algorithm strength is taken from the existing SSH2_KexDB knowledge base
  (fail/warn/info levels).  No separate rating system is maintained here.
* Exceptions are scoped per target, algorithm type and algorithm, and always
  carry an expiry instant with an explicit timezone.  Global/permanent
  exemptions are rejected at load time.
"""
import json

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, cast

from ssh_audit import exitcodes
from ssh_audit.banner import Banner
from ssh_audit.globals import VERSION
from ssh_audit.software import Software
from ssh_audit.ssh2_kexdb import SSH2_KexDB


# Bumped when the baseline document format changes in an incompatible way.  Documents carrying an unknown version are refused instead of being guessed at.
BASELINE_FORMAT_VERSION = 1

# The four algorithm sections that every complete scan document contains, in a fixed order so that output ordering is repeatable.
ALGORITHM_SECTIONS: Tuple[str, ...] = ('kex', 'key', 'enc', 'mac')

MODE_STRICT = 'strict'
MODE_LENIENT = 'lenient'
VALID_MODES = (MODE_STRICT, MODE_LENIENT)

# Comparison statuses.
STATUS_NO_BASELINE = 'no_baseline'
STATUS_INCOMPARABLE = 'incomparable'
STATUS_COMPARED = 'compared'

# Difference / regression type identifiers.
DIFF_WEAK_ALG_ADDED = 'weak_algorithm_added'
DIFF_WARN_ALG_ADDED = 'warning_algorithm_added'
DIFF_ALG_ADDED = 'algorithm_added'
DIFF_STRONG_ALG_REMOVED = 'strong_algorithm_removed'
DIFF_WARN_ALG_REMOVED = 'warning_algorithm_removed'
DIFF_WEAK_ALG_REMOVED = 'weak_algorithm_removed'
DIFF_REORDER = 'reorder'
DIFF_KEY_SIZE_DECREASED = 'key_size_decreased'
DIFF_KEY_SIZE_INCREASED = 'key_size_increased'
DIFF_FINGERPRINT_CHANGED = 'fingerprint_changed'
DIFF_BANNER_CHANGED = 'banner_changed'


class BaselineError(Exception):
    '''Raised when a baseline or exception document cannot be parsed or is from an unsupported format.  Messages are intended to be actionable for operators.'''


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_expiry(value: Any, context: str) -> datetime:
    '''Parses an ISO-8601 expiry timestamp and requires an explicit timezone so date-boundary and local timezone differences cannot shift exception behavior.'''
    if not isinstance(value, str) or len(value) == 0:
        raise BaselineError("%s: 'expires' must be a non-empty ISO-8601 string with an explicit timezone (example: 2026-12-31T23:59:59+00:00)." % context)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as e:
        raise BaselineError("%s: could not parse 'expires' value %r as ISO-8601: %s" % (context, value, str(e))) from e
    if parsed.tzinfo is None:
        raise BaselineError("%s: 'expires' value %r has no timezone; declare the registration timezone explicitly (example: 2026-12-31T23:59:59+00:00)." % (context, value))
    return parsed


def get_alg_rating(alg_type: str, algorithm: str, stored_notes: Optional[Dict[str, Any]] = None) -> Tuple[bool, bool]:
    '''Returns (has_fail, has_warn) for an algorithm, reusing the SSH2_KexDB knowledge base.  Stored notes from the scan documents are only used as a fallback for algorithms the current knowledge base does not know; completely unknown algorithms are treated as failures, matching the existing output logic.'''

    # Normalize GSS key exchange names the same way output_algorithm() does (i.e.: 'gss-gex-sha1-<base64>' => 'gss-gex-sha1-*').
    lookup_name = algorithm
    if alg_type == 'kex' and lookup_name.startswith('gss-'):
        lookup_name = "%s-*" % lookup_name[0:lookup_name.rindex('-')]

    db = SSH2_KexDB.get_db()
    desc = db.get(alg_type, {}).get(lookup_name)
    if desc is not None:
        has_fail = len(desc) > 1 and len(desc[1]) > 0
        has_warn = len(desc) > 2 and len(desc[2]) > 0
    elif isinstance(stored_notes, dict):
        has_fail = len(stored_notes.get('fail', [])) > 0
        has_warn = len(stored_notes.get('warn', [])) > 0
    else:
        # Unknown algorithm: build_struct() annotates these with FAIL_UNKNOWN.
        has_fail, has_warn = True, False
    return has_fail, has_warn


def is_complete_scan(scan: Any) -> bool:
    '''Returns True if a scan document contains all four algorithm sections.  Missing sections mean the scan did not finish, so their absence must never be interpreted as an algorithm being removed.'''
    if not isinstance(scan, dict):
        return False
    for section in ALGORITHM_SECTIONS:
        if not isinstance(scan.get(section), list):
            return False
    return True


def _section_map(scan: Dict[str, Any], section: str) -> Dict[str, Dict[str, Any]]:
    '''Indexes a scan section by algorithm name.  Duplicate names cannot occur in a real kexinit, but last-write-wins keeps this deterministic regardless.'''
    ret: Dict[str, Dict[str, Any]] = {}
    for entry in scan.get(section, []) or []:
        if isinstance(entry, dict) and 'algorithm' in entry:
            ret[cast(str, entry['algorithm'])] = entry
    return ret


def _section_order(scan: Dict[str, Any], section: str) -> List[str]:
    return [cast(str, entry['algorithm']) for entry in scan.get(section, []) or [] if isinstance(entry, dict) and 'algorithm' in entry]


def _software_identity(scan: Dict[str, Any]) -> str:
    '''Extracts a stable software product identity (e.g.: 'OpenSSH', 'Dropbear SSH') from a scan document.  Returns '' when no identity can be determined.'''
    banner = scan.get('banner')
    if isinstance(banner, dict):
        raw = banner.get('raw')
        if isinstance(raw, str) and len(raw) > 0:
            parsed_banner = Banner.parse(raw)
            if parsed_banner is not None:
                software = Software.parse(parsed_banner)
                if software is not None:
                    return software.product
        software_field = banner.get('software')
        if isinstance(software_field, str) and len(software_field) > 0:
            # banner.software looks like 'OpenSSH_8.4p1' or 'Dropbear_2022.82'; the portion before the first underscore identifies the product family.
            return software_field.split('_', 1)[0]
    return ''


def _fingerprint_map(scan: Dict[str, Any]) -> Dict[str, str]:
    '''Returns the SHA256 fingerprint of each host key type.'''
    ret: Dict[str, str] = {}
    for entry in scan.get('fingerprints', []) or []:
        if isinstance(entry, dict) and entry.get('hash_alg') == 'SHA256' and 'hostkey' in entry and 'hash' in entry:
            ret[cast(str, entry['hostkey'])] = cast(str, entry['hash'])
    return ret


def build_scan_meta(target: str, complete: bool, now: Optional[datetime] = None) -> Dict[str, Any]:
    '''Builds the 'scan_meta' block that marks a scan document as a usable baseline.'''
    if now is None:
        now = _utcnow()
    return {
        'baseline_format_version': BASELINE_FORMAT_VERSION,
        'generated_at': now.isoformat(),
        'ssh_audit_version': VERSION,
        'target': target,
        'complete': bool(complete),
    }


class Baseline:
    '''A validated historical scan document used as the comparison baseline.'''

    def __init__(self, scan: Dict[str, Any], meta: Optional[Dict[str, Any]] = None, source_path: Optional[str] = None) -> None:
        self.scan = scan
        self.meta = meta if meta is not None else {}
        self.source_path = source_path

    @property
    def generated_at(self) -> Optional[str]:
        value = self.meta.get('generated_at')
        return value if isinstance(value, str) else None

    @classmethod
    def load(cls, path: str) -> 'Baseline':
        '''Loads and validates a baseline file.  Corrupt JSON, unknown format versions, lists of scans, and documents missing the algorithm sections are rejected with an actionable BaselineError.'''
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = f.read()
        except FileNotFoundError as e:
            raise BaselineError("baseline file not found: %s" % path) from e
        except PermissionError as e:
            raise BaselineError("insufficient permissions to read baseline file %s: %s" % (path, str(e))) from e
        except OSError as e:
            raise BaselineError("could not read baseline file %s: %s" % (path, str(e))) from e

        try:
            document = json.loads(raw)
        except json.JSONDecodeError as e:
            raise BaselineError("baseline file %s is not valid JSON (line %d, column %d).  Use a machine-readable scan result produced with -j/--json as the baseline; re-run the scan and save its JSON output to recreate it." % (path, e.lineno, e.colno)) from e

        # Multi-target scans emit a JSON array; only per-target scan objects are valid baselines.
        if isinstance(document, list):
            raise BaselineError("baseline file %s contains a JSON array of multiple targets.  Save the JSON object of an individual target scan (one object per invocation without -T/--targets) and use that as the baseline." % path)
        if not isinstance(document, dict):
            raise BaselineError("baseline file %s does not contain a JSON object scan result.  Re-run the scan with -j/--json and save its output to recreate the baseline." % path)

        meta = document.get('scan_meta')
        if meta is not None:
            if not isinstance(meta, dict):
                raise BaselineError("baseline file %s has an invalid 'scan_meta' block (expected an object).  Re-run the scan with -j/--json to recreate the baseline." % path)
            version = meta.get('baseline_format_version')
            if version != BASELINE_FORMAT_VERSION:
                raise BaselineError("baseline file %s uses unsupported baseline format version %r (supported version: %d).  Re-run the scan with -j/--json to generate a baseline in the current format." % (path, version, BASELINE_FORMAT_VERSION))
        # Documents without a scan_meta block are legacy scan results: accepted as format version 1, provided they actually contain complete algorithm sections.

        if not is_complete_scan(document):
            missing = [section for section in ALGORITHM_SECTIONS if not isinstance(document.get(section), list)]
            raise BaselineError("baseline file %s is missing required algorithm section(s) %s, so it cannot be used for comparison.  Re-run the scan with -j/--json to recreate a complete baseline." % (path, ', '.join(missing)))

        return cls(document, meta if isinstance(meta, dict) else {}, path)


class ExceptionRegistry:
    '''Loads, validates and deterministically merges registered exceptions.'''

    def __init__(self, entries: Optional[List[Dict[str, Any]]] = None, conflicts: Optional[List[Dict[str, Any]]] = None, source_path: Optional[str] = None) -> None:
        # Keyed by (target, alg_type, algorithm) -> normalized entry dict.
        self._entries: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.conflicts: List[Dict[str, Any]] = conflicts if conflicts is not None else []
        self.source_path = source_path
        for entry in entries or []:
            self._add(entry)

    @property
    def entries(self) -> List[Dict[str, Any]]:
        # Sorted for repeatable output.
        return [self._entries[key] for key in sorted(self._entries)]

    def _add(self, raw_entry: Dict[str, Any]) -> None:
        context = "exception entry %r" % raw_entry
        if not isinstance(raw_entry, dict):
            raise BaselineError("each exception entry must be a JSON object; got %r." % raw_entry)

        target = raw_entry.get('target')
        alg_type = raw_entry.get('type')
        algorithm = raw_entry.get('algorithm')
        reason = raw_entry.get('reason')
        if not isinstance(target, str) or len(target) == 0:
            raise BaselineError("%s: 'target' must be a non-empty string; global exemptions are not allowed." % context)
        if alg_type not in ALGORITHM_SECTIONS:
            raise BaselineError("%s: 'type' must be one of %s." % (context, ', '.join(ALGORITHM_SECTIONS)))
        if not isinstance(algorithm, str) or len(algorithm) == 0:
            raise BaselineError("%s: 'algorithm' must be a non-empty string." % context)
        if not isinstance(reason, str) or len(reason) == 0:
            raise BaselineError("%s: 'reason' must be a non-empty string explaining the exception." % context)

        expires = _parse_expiry(raw_entry.get('expires'), context)
        entry = {
            'target': target,
            'type': alg_type,
            'algorithm': algorithm,
            'reason': reason,
            'expires': expires.isoformat(),
        }
        key = (target, alg_type, algorithm)
        if key in self._entries:
            existing = self._entries[key]
            # Deterministic conflict resolution: the entry with the later expiry wins; ties are broken by reason text.  Both registrations are reported.
            winner = entry if (entry['expires'], entry['reason']) > (existing['expires'], existing['reason']) else existing
            self.conflicts.append({
                'target': target,
                'type': alg_type,
                'algorithm': algorithm,
                'kept': winner,
                'discarded': existing if winner is entry else entry,
            })
            self._entries[key] = winner
        else:
            self._entries[key] = entry

    @classmethod
    def load(cls, path: str) -> 'ExceptionRegistry':
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = f.read()
        except FileNotFoundError as e:
            raise BaselineError("exceptions file not found: %s" % path) from e
        except PermissionError as e:
            raise BaselineError("insufficient permissions to read exceptions file %s: %s" % (path, str(e))) from e
        except OSError as e:
            raise BaselineError("could not read exceptions file %s: %s" % (path, str(e))) from e

        try:
            document = json.loads(raw)
        except json.JSONDecodeError as e:
            raise BaselineError("exceptions file %s is not valid JSON (line %d, column %d)." % (path, e.lineno, e.colno)) from e

        if not isinstance(document, dict) or not isinstance(document.get('exceptions'), list):
            raise BaselineError("exceptions file %s must be a JSON object with an 'exceptions' array, e.g.: {\"exceptions\": [{\"target\": \"host:22\", \"type\": \"kex\", \"algorithm\": \"diffie-hellman-group14-sha1\", \"reason\": \"legacy device, ticket OPS-123\", \"expires\": \"2026-12-31T23:59:59+00:00\"}]}." % path)

        return cls(document['exceptions'], source_path=path)

    @staticmethod
    def _target_matches(exception_target: str, scan_target: str) -> bool:
        if exception_target == scan_target:
            return True
        # Also allow a bare host registration to match a 'host:port' scan target.
        if ':' in scan_target:
            host_only = scan_target.rsplit(':', 1)[0]
            if exception_target == host_only:
                return True
        return False

    def match(self, scan_target: str, alg_type: str, algorithm: str, now: datetime) -> Optional[Dict[str, Any]]:
        '''Returns the active (unexpired) exception matching this target/type/algorithm, or None.'''
        for entry in self._entries.values():
            if entry['type'] != alg_type or entry['algorithm'] != algorithm:
                continue
            if not self._target_matches(entry['target'], scan_target):
                continue
            expires = datetime.fromisoformat(entry['expires'])
            if now < expires:
                return entry
        return None

    def expired_entries(self, now: datetime) -> List[Dict[str, Any]]:
        '''Returns all registrations whose expiry has passed; these no longer suppress regressions.'''
        expired = []
        for entry in self._entries.values():
            if now >= datetime.fromisoformat(entry['expires']):
                expired.append(entry)
        return sorted(expired, key=lambda e: (e['target'], e['type'], e['algorithm']))


def _make_diff(diff_type: str, section: str, algorithm: str, is_regression: bool, detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    diff: Dict[str, Any] = {
        'type': diff_type,
        'section': section,
        'algorithm': algorithm,
        'is_regression': bool(is_regression),
    }
    if detail:
        diff.update(detail)
    return diff


def _incomparable_result(reason: str, mode: str, incomplete: bool = False, baseline: Optional[Baseline] = None) -> Dict[str, Any]:
    return {
        'status': STATUS_INCOMPARABLE,
        'comparable': False,
        'mode': mode,
        'incomplete': bool(incomplete),
        'reason': reason,
        'baseline': _baseline_summary(baseline),
        'diffs': [],
        'regressions': [],
        'regression_count': 0,
        'exceptions_applied': [],
        'expired_exceptions': [],
        'exception_conflicts': [],
        'notes': [],
    }


def _baseline_summary(baseline: Optional[Baseline]) -> Optional[Dict[str, Any]]:
    if baseline is None:
        return None
    return {
        'source': baseline.source_path,
        'generated_at': baseline.generated_at,
        'meta': baseline.meta,
    }


def compare_scans(baseline_scan: Dict[str, Any], current_scan: Dict[str, Any], mode: str = MODE_STRICT, exceptions: Optional[ExceptionRegistry] = None, target: str = '', now: Optional[datetime] = None, baseline: Optional[Baseline] = None) -> Dict[str, Any]:
    '''Computes the full difference between two scan documents and classifies regressions.

    The output dict is deterministic for identical inputs: every list is in a
    fixed sorted order, and the only externally-supplied clock is 'now'.
    '''
    if mode not in VALID_MODES:
        raise ValueError("comparison mode must be one of %s, got %r" % (', '.join(VALID_MODES), mode))
    if now is None:
        now = _utcnow()
    if exceptions is None:
        exceptions = ExceptionRegistry()

    # A partial current scan must never be treated as algorithms being removed.
    if not is_complete_scan(current_scan):
        return _incomparable_result('current scan is incomplete (one or more algorithm sections are missing); refusing to compare so missing data is not mistaken for removed algorithms', mode, incomplete=True, baseline=baseline)

    scan_target = target or cast(str, current_scan.get('target', ''))
    diffs: List[Dict[str, Any]] = []
    notes: List[str] = []

    # Software identity change makes the two scans fundamentally incomparable.  A same-product version change is still comparable.
    old_identity = _software_identity(baseline_scan)
    new_identity = _software_identity(current_scan)
    if old_identity and new_identity and old_identity != new_identity:
        return _incomparable_result('software identity changed from %r to %r; algorithm sets are not comparable across different software products' % (old_identity, new_identity), mode, baseline=baseline)

    old_banner = (baseline_scan.get('banner') or {}).get('raw') if isinstance(baseline_scan.get('banner'), dict) else None
    new_banner = (current_scan.get('banner') or {}).get('raw') if isinstance(current_scan.get('banner'), dict) else None
    if isinstance(old_banner, str) and isinstance(new_banner, str) and old_banner != new_banner:
        notes.append('banner changed from %r to %r (same software product; algorithm comparison continues)' % (old_banner, new_banner))
        diffs.append(_make_diff(DIFF_BANNER_CHANGED, 'banner', '', False, {'old_banner': old_banner, 'new_banner': new_banner}))

    # Host key fingerprints: a replaced key makes its size comparison inconclusive.
    old_fingerprints = _fingerprint_map(baseline_scan)
    new_fingerprints = _fingerprint_map(current_scan)
    inconclusive_key_sizes = set()
    for hostkey_type in sorted(set(old_fingerprints) & set(new_fingerprints)):
        if old_fingerprints[hostkey_type] != new_fingerprints[hostkey_type]:
            inconclusive_key_sizes.add(hostkey_type)
            diffs.append(_make_diff(DIFF_FINGERPRINT_CHANGED, 'key', hostkey_type, False, {'note': 'host key was replaced; key size comparison for this type is inconclusive'}))

    for section in ALGORITHM_SECTIONS:
        old_entries = _section_map(baseline_scan, section)
        new_entries = _section_map(current_scan, section)
        old_order = _section_order(baseline_scan, section)
        new_order = _section_order(current_scan, section)
        old_set, new_set = set(old_entries), set(new_entries)

        # --- Additions -----------------------------------------------------
        for algorithm in sorted(new_set - old_set):
            has_fail, has_warn = get_alg_rating(section, algorithm, new_entries[algorithm].get('notes'))
            if has_fail:
                diffs.append(_make_diff(DIFF_WEAK_ALG_ADDED, section, algorithm, True, {'detail': 'newly offered algorithm is rated as a failure by the algorithm knowledge base'}))
            elif has_warn:
                # Warning-level additions only count as regressions in strict mode.
                diffs.append(_make_diff(DIFF_WARN_ALG_ADDED, section, algorithm, mode == MODE_STRICT, {'detail': 'newly offered algorithm carries warnings'}))
            else:
                # Adding a strong algorithm is neutral/hardening.
                diffs.append(_make_diff(DIFF_ALG_ADDED, section, algorithm, False))

        # --- Removals ------------------------------------------------------
        for algorithm in sorted(old_set - new_set):
            has_fail, has_warn = get_alg_rating(section, algorithm, old_entries[algorithm].get('notes'))
            if has_fail:
                # Removing a weak algorithm is hardening.
                diffs.append(_make_diff(DIFF_WEAK_ALG_REMOVED, section, algorithm, False, {'detail': 'weak algorithm removed (hardening)'}))
            elif has_warn:
                diffs.append(_make_diff(DIFF_WARN_ALG_REMOVED, section, algorithm, mode == MODE_STRICT, {'detail': 'algorithm carrying warnings was removed'}))
            else:
                # Losing a strong algorithm degrades security in every mode.
                diffs.append(_make_diff(DIFF_STRONG_ALG_REMOVED, section, algorithm, True, {'detail': 'strong algorithm is no longer offered'}))

        # --- Reordering of the common algorithms ---------------------------
        common = old_set & new_set
        common_old_order = [a for a in old_order if a in common]
        common_new_order = [a for a in new_order if a in common]
        if common_old_order != common_new_order:
            # Reordering is always reported; it only counts as a regression in strict mode, matching policy subset/reordering semantics.
            diffs.append(_make_diff(DIFF_REORDER, section, '', mode == MODE_STRICT, {'old_order': common_old_order, 'new_order': common_new_order}))

        # --- Key / modulus size changes ------------------------------------
        for algorithm in sorted(common):
            old_entry, new_entry = old_entries[algorithm], new_entries[algorithm]
            for size_field in ('keysize', 'casize'):
                old_size = old_entry.get(size_field)
                new_size = new_entry.get(size_field)
                if not isinstance(old_size, int) or not isinstance(new_size, int) or old_size == new_size:
                    continue
                if algorithm in inconclusive_key_sizes:
                    notes.append('%s %s changed for %s, but its host key fingerprint changed as well; skipping size regression.' % (section, size_field, algorithm))
                    continue
                if new_size < old_size:
                    diffs.append(_make_diff(DIFF_KEY_SIZE_DECREASED, section, algorithm, True, {'size_field': size_field, 'old_size': old_size, 'new_size': new_size}))
                else:
                    # Larger keys are hardening, consistent with allow_larger_keys in policy evaluation.
                    diffs.append(_make_diff(DIFF_KEY_SIZE_INCREASED, section, algorithm, False, {'size_field': size_field, 'old_size': old_size, 'new_size': new_size}))

    # Deterministic overall ordering.
    diffs.sort(key=lambda d: (ALGORITHM_SECTIONS.index(d['section']) if d['section'] in ALGORITHM_SECTIONS else len(ALGORITHM_SECTIONS), d['type'], d['algorithm']))

    # --- Apply exceptions ---------------------------------------------------
    exceptions_applied: List[Dict[str, Any]] = []
    regressions: List[Dict[str, Any]] = []
    for diff in diffs:
        # Non-regressions (hardening, neutral changes, lenient-mode reorderings) need no exception handling.
        if not diff['is_regression']:
            continue
        # Regressions without a concrete algorithm (e.g.: strict-mode reordering) cannot be matched by a scoped exception and always count.
        if not diff['algorithm']:
            regressions.append(diff)
            continue
        entry = exceptions.match(scan_target, diff['section'], diff['algorithm'], now)
        if entry is not None:
            diff['exception'] = {'reason': entry['reason'], 'expires': entry['expires'], 'target': entry['target']}
            diff['is_regression'] = False
            exceptions_applied.append({
                'type': diff['type'],
                'section': diff['section'],
                'algorithm': diff['algorithm'],
                'reason': entry['reason'],
                'expires': entry['expires'],
            })
        else:
            regressions.append(diff)

    return {
        'status': STATUS_COMPARED,
        'comparable': True,
        'mode': mode,
        'incomplete': False,
        'reason': None,
        'baseline': _baseline_summary(baseline),
        'diffs': diffs,
        'regressions': regressions,
        'regression_count': len(regressions),
        'exceptions_applied': sorted(exceptions_applied, key=lambda e: (e['section'], e['algorithm'], e['type'])),
        'expired_exceptions': exceptions.expired_entries(now),
        'exception_conflicts': exceptions.conflicts,
        'notes': sorted(notes),
    }


def no_baseline_result(mode: str) -> Dict[str, Any]:
    '''Cold-start result: no historical scan exists yet, so there is nothing to regress against.'''
    return {
        'status': STATUS_NO_BASELINE,
        'comparable': False,
        'mode': mode,
        'incomplete': False,
        'reason': 'no baseline available; recording this scan as the initial baseline',
        'baseline': None,
        'diffs': [],
        'regressions': [],
        'regression_count': 0,
        'exceptions_applied': [],
        'expired_exceptions': [],
        'exception_conflicts': [],
        'notes': [],
    }


def resolve_exit_code(result: Dict[str, Any]) -> int:
    '''Maps a comparison result onto the extended exit code semantics.'''
    status = result.get('status')
    if status == STATUS_INCOMPARABLE:
        return exitcodes.INCOMPARABLE
    if status == STATUS_NO_BASELINE:
        return exitcodes.GOOD
    if result.get('regression_count', 0) > 0:
        return exitcodes.REGRESSION
    if len(result.get('exceptions_applied', [])) > 0:
        return exitcodes.EXCEPTION_ONLY
    return exitcodes.GOOD
