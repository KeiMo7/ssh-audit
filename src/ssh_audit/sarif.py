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
import atexit
import hashlib
import json
import os
import re
import tempfile
import threading

from typing import Callable, Dict, List, Optional, Set, TextIO
from urllib.parse import quote_from_bytes


SARIF_VERSION = '2.1.0'
SARIF_SCHEMA = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json'
SARIF_SCHEMA_SHORT = 'https://json.schemastore.org/sarif-2.1.0.json'

# This is the single source of truth for finding severity.  Changing an entry
# here changes both result.level and the rule's defaultConfiguration.level.
SEVERITY_MAP: Dict[str, str] = {
    'fail': 'error',
    'warn': 'warning',
    'info': 'note',
}

RESULT_FLUSH_INTERVAL = 64
COPY_CHUNK_SIZE = 64 * 1024
MAX_ARTIFACT_URI_LENGTH = 2048
EXTERNAL_ARTIFACT_PREFIX = 'external/'
RULE_PREFIX = 'SSH-AUDIT-'
FINGERPRINT_KEY = 'ssh-audit/v1'
ABSOLUTE_PATH_RE = re.compile(r'(?<![A-Za-z0-9+.-])(?:[A-Za-z]:[\\/]|/(?:home|tmp|var|private|Users|root)/)[^\s,;)"\']*')


class SarifValidationError(ValueError):
    '''A SARIF self-check failure that identifies the failing JSON pointer.'''

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f'{path}: {message}')


def _safe_text(value: object) -> str:
    '''Returns UTF-8-safe text without lone surrogates.'''

    return str(value).encode('utf-8', 'backslashreplace').decode('utf-8')


def _redact_absolute_paths(value: object) -> str:
    '''Redacts filesystem paths that must not appear in shared SARIF output.'''

    return ABSOLUTE_PATH_RE.sub('<path>', _safe_text(value))


def _safe_target(value: object) -> str:
    text = _safe_text(value)
    if text.startswith('unix://'):
        digest = _sha256_hex(os.fsencode(text[7:]))[:16]
        return 'unix-socket-' + digest
    return _redact_absolute_paths(text)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fallback_artifact_uri(path: str) -> str:
    '''Returns a deterministic, root-relative URI for paths that cannot be represented safely.'''

    raw = os.fsencode(os.path.abspath(path))
    return '%s%s.target' % (EXTERNAL_ARTIFACT_PREFIX, _sha256_hex(raw))


def _location_int(location: Dict[str, object], field: str) -> int:
    value = location.get(field)
    if not isinstance(value, int):
        raise SarifValidationError('/runs/0/results/locations/0/physicalLocation/region/' + field, 'must be a positive integer')
    return value


def artifact_uri(path: str, repo_root: str) -> str:
    '''
    Converts a filesystem path to a root-relative, percent-encoded SARIF URI.

    Absolute paths under the repository root are made relative.  Paths outside
    the root, Windows paths on non-Windows hosts, non-UTF-8 paths, and paths
    whose encoded URI would be too long are replaced by a deterministic
    "external/<sha256>.target" URI.  The returned value never contains an
    absolute path, drive letter, or temporary directory name.
    '''

    path_text = os.fspath(path)
    root_text = os.path.abspath(os.fspath(repo_root))

    if re.match(r'^(?:[A-Za-z]:[\\/]|\\\\)', path_text):
        return _fallback_artifact_uri(path_text)

    try:
        absolute = os.path.abspath(path_text)
        relative = os.path.relpath(absolute, root_text)
    except (OSError, ValueError):
        return _fallback_artifact_uri(path_text)

    if os.path.isabs(relative) or relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return _fallback_artifact_uri(path_text)

    relative_posix = relative.replace(os.sep, '/')
    try:
        encoded = quote_from_bytes(os.fsencode(relative_posix), safe='/._~-')
    except (OSError, UnicodeError):
        return _fallback_artifact_uri(path_text)

    if len(encoded) == 0 or len(encoded) > MAX_ARTIFACT_URI_LENGTH:
        return _fallback_artifact_uri(path_text)
    return encoded


def synthetic_target_uri(host: str, port: int, client: bool = False) -> str:
    '''Returns a stable relative URI for a target that has no source list file.'''

    target = _safe_text('%s:%d' % (host, port))
    kind = 'client' if client else 'server'
    slug = re.sub(r'[^A-Za-z0-9._-]+', '-', target).strip('-')[:64]
    digest = _sha256_hex(target.encode('utf-8'))[:16]
    if len(slug) == 0:
        slug = kind
    return 'ssh-audit-targets/%s-%s-%s.target' % (kind, slug, digest)


def find_repository_root(start: Optional[str] = None) -> str:
    '''Finds the nearest enclosing Git work tree, falling back to the starting directory.'''

    current = os.path.abspath(start if start is not None else os.getcwd())
    while True:
        if os.path.exists(os.path.join(current, '.git')):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return os.path.abspath(start if start is not None else os.getcwd())
        current = parent


def _rule_token(token: str) -> str:
    text = _safe_text(token)
    safe = re.sub(r'[^A-Za-z0-9]+', '-', text).strip('-').upper()
    if len(safe) == 0:
        safe = 'ALGORITHM-' + _sha256_hex(text.encode('utf-8'))[:12].upper()
    elif len(safe) > 160:
        digest = _sha256_hex(text.encode('utf-8'))[:12].upper()
        safe = '%s-%s' % (safe[:145].rstrip('-'), digest)
    return safe


def stable_rule_id(category: str, algorithm: str) -> str:
    '''
    Builds a stable, human-readable rule ID.

    The ID depends only on the category and algorithm identifier.  It never
    contains a host, filesystem path, timestamp, or random value.
    '''

    return '%s%s-%s' % (RULE_PREFIX, _rule_token(category), _rule_token(algorithm))


def _validate_artifact_uri(uri: str, path: str) -> None:
    if not isinstance(uri, str) or len(uri) == 0:
        raise SarifValidationError(path, 'must be a non-empty string')
    if uri.startswith('/') or uri.startswith('\\'):
        raise SarifValidationError(path, 'must be relative')
    if re.match(r'^[A-Za-z]:', uri):
        raise SarifValidationError(path, 'must not contain a drive letter')
    if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', uri):
        raise SarifValidationError(path, 'must not be an absolute URI')
    if '\\' in uri:
        raise SarifValidationError(path, 'must use forward slashes')
    if any(part == '..' for part in uri.split('/')):
        raise SarifValidationError(path, 'must not traverse outside the repository root')
    if re.search(r'%(?![0-9A-Fa-f]{2})', uri):
        raise SarifValidationError(path, 'contains an invalid percent escape')
    if len(uri) > MAX_ARTIFACT_URI_LENGTH:
        raise SarifValidationError(path, 'exceeds the maximum artifact URI length')


def validate_result(result: Dict[str, object], path: str) -> None:
    '''Performs the runtime SARIF subset self-check for one result.'''

    if not isinstance(result, dict):
        raise SarifValidationError(path, 'must be an object')

    rule_id = result.get('ruleId')
    if not isinstance(rule_id, str) or len(rule_id) == 0:
        raise SarifValidationError(path + '/ruleId', 'must be a non-empty string')
    if '\\' in rule_id or '/' in rule_id:
        raise SarifValidationError(path + '/ruleId', 'must not contain paths')

    if result.get('level') not in ('error', 'warning', 'note', 'none'):
        raise SarifValidationError(path + '/level', 'must be one of error, warning, note, or none')

    message = result.get('message')
    if not isinstance(message, dict) or not isinstance(message.get('text'), str) or len(str(message.get('text'))) == 0:
        raise SarifValidationError(path + '/message/text', 'must be a non-empty string')
    if ABSOLUTE_PATH_RE.search(str(message.get('text'))) is not None:
        raise SarifValidationError(path + '/message/text', 'must not contain an absolute filesystem path')

    baseline_state = result.get('baselineState')
    if baseline_state is not None and baseline_state not in ('new', 'unchanged', 'updated', 'absent'):
        raise SarifValidationError(path + '/baselineState', 'must be new, unchanged, updated, or absent')

    properties = result.get('properties')
    if isinstance(properties, dict):
        target = properties.get('target')
        if isinstance(target, str) and ABSOLUTE_PATH_RE.search(target) is not None:
            raise SarifValidationError(path + '/properties/target', 'must not contain an absolute filesystem path')

    locations = result.get('locations')
    if not isinstance(locations, list) or len(locations) == 0:
        raise SarifValidationError(path + '/locations', 'must contain at least one location')

    for location_index, location in enumerate(locations):
        location_path = '%s/locations/%d' % (path, location_index)
        if not isinstance(location, dict):
            raise SarifValidationError(location_path, 'must be an object')
        physical = location.get('physicalLocation')
        if not isinstance(physical, dict):
            raise SarifValidationError(location_path + '/physicalLocation', 'must be an object')
        artifact = physical.get('artifactLocation')
        if not isinstance(artifact, dict):
            raise SarifValidationError(location_path + '/physicalLocation/artifactLocation', 'must be an object')
        uri = artifact.get('uri')
        if not isinstance(uri, str):
            raise SarifValidationError(location_path + '/physicalLocation/artifactLocation/uri', 'must be a string')
        _validate_artifact_uri(uri, location_path + '/physicalLocation/artifactLocation/uri')

        region = physical.get('region')
        if not isinstance(region, dict):
            raise SarifValidationError(location_path + '/physicalLocation/region', 'must be an object')
        for field in ('startLine', 'startColumn', 'endLine', 'endColumn'):
            value = region.get(field)
            if not isinstance(value, int) or value < 1:
                raise SarifValidationError(location_path + '/physicalLocation/region/' + field, 'must be a positive integer')
        start_line = int(region['startLine'])
        start_column = int(region['startColumn'])
        end_line = int(region['endLine'])
        end_column = int(region['endColumn'])
        if end_line < start_line:
            raise SarifValidationError(location_path + '/physicalLocation/region/endLine', 'must not precede startLine')
        if end_line == start_line and end_column < start_column:
            raise SarifValidationError(location_path + '/physicalLocation/region/endColumn', 'must not precede startColumn')


def _load_json_file(path: str, pointer: str) -> Dict[str, object]:
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as err:
        raise SarifValidationError(pointer, 'cannot read baseline SARIF: %s' % err) from err
    if not isinstance(data, dict):
        raise SarifValidationError(pointer, 'baseline SARIF root must be an object')
    return data


class SarifWriter:
    '''
    Writes SARIF incrementally.

    Results are serialized one at a time to a spool file.  At finalization the
    rules and invocation metadata are written to a temporary output file, the
    spool is copied in fixed-size chunks, and the output is atomically renamed.
    A failure or exception therefore cannot leave a truncated JSON document.
    '''

    def __init__(self, output_path: str, repo_root: Optional[str] = None, baseline_path: Optional[str] = None, tool_version: str = '') -> None:
        self.output_path = os.path.abspath(output_path)
        self.repo_root = os.path.abspath(repo_root if repo_root is not None else os.getcwd())
        self.tool_version = tool_version
        self._lock = threading.RLock()
        self._rules: List[Dict[str, object]] = []
        self._rule_indexes: Dict[str, int] = {}
        self._artifacts: Dict[str, Dict[str, object]] = {}
        self._invocations: List[Dict[str, object]] = []
        self._next_invocation = 0
        self._result_count = 0
        self._pending_flush = 0
        self._finished = False
        self._spool_path: Optional[str] = None
        self._temp_output_path: Optional[str] = None
        self._baseline_enabled = False
        self._baseline_fingerprints: Set[str] = set()

        output_dir = os.path.dirname(self.output_path)
        if len(output_dir) == 0:
            output_dir = os.getcwd()
        fd, self._spool_path = tempfile.mkstemp(prefix='.ssh-audit-sarif-results-', suffix='.ndjson', dir=output_dir)
        self._spool = os.fdopen(fd, 'w+', encoding='utf-8', newline='\n')
        fd, self._temp_output_path = tempfile.mkstemp(prefix='.ssh-audit-sarif-output-', suffix='.json', dir=output_dir)
        os.close(fd)

        effective_baseline = baseline_path
        if effective_baseline is None and os.path.exists(self.output_path):
            effective_baseline = self.output_path
        try:
            if effective_baseline is not None:
                if not os.path.exists(effective_baseline):
                    raise SarifValidationError('/runs/0/results', 'baseline file does not exist')
                self._baseline_enabled = True
                self._baseline_fingerprints = self._read_baseline(effective_baseline)
        except Exception:
            self.cleanup()
            raise

        atexit.register(self.cleanup)

    def _read_baseline(self, path: str) -> Set[str]:
        data = _load_json_file(path, '/runs/0/results')
        if data.get('version') != SARIF_VERSION:
            raise SarifValidationError('/version', 'baseline must be SARIF 2.1.0')
        runs = data.get('runs')
        if not isinstance(runs, list):
            raise SarifValidationError('/runs', 'must be an array')

        fingerprints: Set[str] = set()
        for run_index, run in enumerate(runs):
            run_path = '/runs/%d' % run_index
            if not isinstance(run, dict):
                raise SarifValidationError(run_path, 'must be an object')
            results = run.get('results', [])
            if not isinstance(results, list):
                raise SarifValidationError(run_path + '/results', 'must be an array')
            for result_index, result in enumerate(results):
                result_path = '%s/results/%d' % (run_path, result_index)
                if not isinstance(result, dict):
                    raise SarifValidationError(result_path, 'must be an object')
                result_fingerprints = result.get('fingerprints', {})
                if not isinstance(result_fingerprints, dict):
                    raise SarifValidationError(result_path + '/fingerprints', 'must be an object')
                fingerprint = result_fingerprints.get(FINGERPRINT_KEY)
                if isinstance(fingerprint, str) and len(fingerprint) > 0:
                    fingerprints.add(fingerprint)
        return fingerprints

    def _check_open(self) -> None:
        if self._finished:
            raise RuntimeError('SARIF writer is already finalized')

    def _ensure_rule(self, rule_id: str, category: str, algorithm: str, level: str) -> None:
        if rule_id in self._rule_indexes:
            return
        category_text = _safe_text(category)
        algorithm_text = _safe_text(algorithm)
        short = '%s finding for %s' % (category_text, algorithm_text)
        descriptor: Dict[str, object] = {
            'id': rule_id,
            'name': _rule_token(category_text).title() + 'Finding',
            'shortDescription': {'text': short},
            'helpUri': 'https://www.ssh-audit.com/',
            'defaultConfiguration': {'level': SEVERITY_MAP.get(level, 'warning')},
            'properties': {
                'category': category_text,
                'algorithm': algorithm_text,
            },
        }
        self._rule_indexes[rule_id] = len(self._rules)
        self._rules.append(descriptor)

    def _ensure_artifact(self, uri: str) -> None:
        if uri not in self._artifacts:
            self._artifacts[uri] = {
                'location': {'uri': uri},
                'roles': ['analysisTarget'],
            }

    def add_finding(self, category: str, algorithm: str, level: str, message: str, location: Dict[str, object], target: str = '') -> None:
        '''Validates and appends one finding to the on-disk result spool.'''

        if level not in SEVERITY_MAP:
            raise SarifValidationError('/runs/0/results', 'unsupported finding level: %s' % level)

        uri = str(location.get('artifact_uri', ''))
        start_line = _location_int(location, 'start_line')
        start_column = _location_int(location, 'start_column')
        end_line = _location_int(location, 'end_line')
        end_column = _location_int(location, 'end_column')

        with self._lock:
            self._check_open()
            rule_id = stable_rule_id(category, algorithm)
            self._ensure_rule(rule_id, category, algorithm, level)
            self._ensure_artifact(uri)

            message_text = _redact_absolute_paths(message)
            target_text = _safe_target(target)
            fingerprint_source = '\x00'.join([
                rule_id,
                uri,
                str(start_line),
                str(start_column),
                _safe_text(algorithm),
                message_text,
                target_text,
            ])
            fingerprint = _sha256_hex(fingerprint_source.encode('utf-8'))

            result: Dict[str, object] = {
                'ruleId': rule_id,
                'ruleIndex': self._rule_indexes[rule_id],
                'level': SEVERITY_MAP[level],
                'message': {'text': message_text},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': uri},
                        'region': {
                            'startLine': start_line,
                            'startColumn': start_column,
                            'endLine': end_line,
                            'endColumn': end_column,
                        },
                    },
                }],
                'fingerprints': {FINGERPRINT_KEY: fingerprint},
                'properties': {
                    'category': _safe_text(category),
                    'algorithm': _safe_text(algorithm),
                    'target': target_text,
                },
            }
            if self._baseline_enabled:
                result['baselineState'] = 'unchanged' if fingerprint in self._baseline_fingerprints else 'new'

            result_path = '/runs/0/results/%d' % self._result_count
            validate_result(result, result_path)
            if self._result_count > 0:
                self._spool.write(',')
            self._spool.write(json.dumps(result, ensure_ascii=True, separators=(',', ':')))
            self._spool.write('\n')
            self._result_count += 1
            self._pending_flush += 1
            if self._pending_flush >= RESULT_FLUSH_INTERVAL:
                self._spool.flush()
                self._pending_flush = 0

    def recorder(self, location: Dict[str, object], target: str = '') -> Callable[[str, str, str, str], None]:
        '''Returns a callback suitable for OutputBuffer.finding_recorder.'''

        def _record(category: str, algorithm: str, level: str, message: str) -> None:
            self.add_finding(category, algorithm, level, message, location, target)

        return _record

    def begin_invocation(self, command_line: str, target: str = '') -> int:
        '''Starts an invocation record and returns its ID.'''

        with self._lock:
            self._check_open()
            invocation_id = self._next_invocation
            self._next_invocation += 1
            invocation: Dict[str, object] = {
                'executionSuccessful': True,
                'commandLine': _safe_text(command_line),
                'workingDirectory': {'uri': '.'},
                'properties': {'target': _safe_target(target)},
            }
            self._invocations.append(invocation)
            return invocation_id

    def finish_invocation(self, invocation_id: int, success: bool, exit_code: Optional[int] = None, message: str = '') -> None:
        '''Completes one invocation with success/failure metadata.'''

        with self._lock:
            if invocation_id < 0 or invocation_id >= len(self._invocations):
                raise SarifValidationError('/runs/0/invocations', 'invalid invocation ID')
            invocation = self._invocations[invocation_id]
            invocation['executionSuccessful'] = bool(success)
            if exit_code is not None:
                invocation['exitCode'] = int(exit_code)
            if not success:
                notification: Dict[str, object] = {
                    'level': 'error',
                    'message': {'text': _redact_absolute_paths(message) if len(message) > 0 else 'ssh-audit execution failed'},
                }
                invocation['toolExecutionNotifications'] = [notification]

    def _validate_header(self) -> None:
        if self._result_count < 0:
            raise SarifValidationError('/runs/0/results', 'invalid result count')
        seen_rules: Set[str] = set()
        for index, rule in enumerate(self._rules):
            path = '/runs/0/tool/driver/rules/%d' % index
            rule_id = rule.get('id')
            if not isinstance(rule_id, str) or len(rule_id) == 0:
                raise SarifValidationError(path + '/id', 'must be a non-empty string')
            if rule_id in seen_rules:
                raise SarifValidationError(path + '/id', 'duplicate rule ID')
            seen_rules.add(rule_id)
            if not isinstance(rule.get('shortDescription'), dict):
                raise SarifValidationError(path + '/shortDescription', 'must be an object')
            default_config = rule.get('defaultConfiguration')
            if not isinstance(default_config, dict) or default_config.get('level') not in ('error', 'warning', 'note', 'none'):
                raise SarifValidationError(path + '/defaultConfiguration/level', 'must be a valid SARIF level')

        for index, artifact in enumerate(self._artifacts.values()):
            path = '/runs/0/artifacts/%d/location/uri' % index
            location = artifact.get('location')
            if not isinstance(location, dict) or not isinstance(location.get('uri'), str):
                raise SarifValidationError(path, 'must be a string')
            _validate_artifact_uri(str(location.get('uri')), path)

        for index, invocation in enumerate(self._invocations):
            path = '/runs/0/invocations/%d' % index
            if not isinstance(invocation.get('executionSuccessful'), bool):
                raise SarifValidationError(path + '/executionSuccessful', 'must be a boolean')
            properties = invocation.get('properties')
            if isinstance(properties, dict):
                target = properties.get('target')
                if isinstance(target, str) and ABSOLUTE_PATH_RE.search(target) is not None:
                    raise SarifValidationError(path + '/properties/target', 'must not contain an absolute filesystem path')
            notifications = invocation.get('toolExecutionNotifications', [])
            if isinstance(notifications, list):
                for notification_index, notification in enumerate(notifications):
                    message = notification.get('message') if isinstance(notification, dict) else None
                    text = message.get('text') if isinstance(message, dict) else None
                    if isinstance(text, str) and ABSOLUTE_PATH_RE.search(text) is not None:
                        raise SarifValidationError('%s/toolExecutionNotifications/%d/message/text' % (path, notification_index), 'must not contain an absolute filesystem path')

    def _write_header(self, handle: TextIO) -> None:
        driver: Dict[str, object] = {
            'name': 'ssh-audit',
            'fullName': 'ssh-audit SSH configuration auditor',
            'version': _safe_text(self.tool_version),
            'semanticVersion': _safe_text(self.tool_version).lstrip('v'),
            'informationUri': 'https://www.ssh-audit.com/',
            'rules': self._rules,
        }
        run: Dict[str, object] = {
            'tool': {'driver': driver},
            'artifacts': list(self._artifacts.values()),
            'invocations': self._invocations,
        }
        document_head: Dict[str, object] = {
            '$schema': SARIF_SCHEMA,
            'version': SARIF_VERSION,
        }
        head_text = json.dumps(document_head, ensure_ascii=True, separators=(',', ':'))
        run_text = json.dumps(run, ensure_ascii=True, separators=(',', ':'))
        handle.write(head_text[:-1])
        handle.write(',"runs":[')
        handle.write(run_text[:-1])
        handle.write(',"results":[')

    def finalize(self, success: bool = True, message: str = '') -> None:
        '''Copies the result spool into a complete SARIF document and atomically replaces the target.'''

        with self._lock:
            if self._finished:
                return
            try:
                self._check_open()
                self._spool.flush()
                self._spool.seek(0)
                if len(self._invocations) == 0:
                    invocation_id = self.begin_invocation('')
                    self.finish_invocation(invocation_id, success, None, message)
                self._validate_header()

                if self._temp_output_path is None:
                    raise RuntimeError('temporary SARIF output path is missing')
                with open(self._temp_output_path, 'w', encoding='utf-8', newline='\n') as handle:
                    self._write_header(handle)
                    while True:
                        chunk = self._spool.read(COPY_CHUNK_SIZE)
                        if len(chunk) == 0:
                            break
                        handle.write(chunk)
                    handle.write(']}]}\n')
                    handle.flush()
                    os.fsync(handle.fileno())

                os.replace(self._temp_output_path, self.output_path)
                self._temp_output_path = None
                self._finished = True
            except Exception:
                self.cleanup()
                raise
            finally:
                if self._finished:
                    self.cleanup()

    def cleanup(self) -> None:
        '''Removes temporary files.  Safe to call more than once.'''

        with self._lock:
            try:
                if not self._spool.closed:
                    self._spool.close()
            except OSError:
                pass

            for path in (self._spool_path, self._temp_output_path):
                if path is not None:
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        pass
            self._spool_path = None
            self._temp_output_path = None
