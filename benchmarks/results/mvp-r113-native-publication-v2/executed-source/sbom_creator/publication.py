"""Internal publication checkpoints; exported errors never contain paths or messages."""
import ctypes
import errno
import os
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

OPERATIONS = frozenset({'prepare_output', 'validate_catalogs', 'reconcile', 'validate_selection',
    'create_staging', 'write_artifact', 'build_provenance', 'convert_final',
    'validate_final_identity', 'annotate_dependencies', 'compare_build_image',
    'prepare_coverage', 'validate_final', 'split_inventory', 'commit_directory', 'cleanup_staging'})
CODES = frozenset({'PUBLICATION_PERMISSION_DENIED', 'PUBLICATION_OUTPUT_CONFLICT',
    'PUBLICATION_PATH_UNAVAILABLE', 'PUBLICATION_IO_ERROR', 'PUBLICATION_INVALID_DATA', 'PUBLICATION_FAILED'})
OS_REASONS = frozenset({'windows_sharing_violation', 'windows_lock_violation', 'access_denied',
    'not_found', 'file_exists', 'no_space', 'read_only', 'descriptor_limit', 'other', 'unspecified'})
ARTIFACTS = frozenset({'final.cdx.json', 'source.syft.json', 'image.syft.json', 'selected.syft.json',
    'decisions.json', 'coverage.json', 'provenance.json', 'summary.json', 'review.json',
    'os.cdx.json', 'full.cdx.json', 'direct-dependencies.json', 'java-direct-dependencies.json',
    'build.cdx.json', 'image.cdx.json', 'build-image-comparison.json',
    'image-original.syft.json', 'image-peer.cdx.json', 'image-identity-audit.json'})
ERROR_TYPES = frozenset({'PermissionError', 'FileExistsError', 'FileNotFoundError', 'OSError',
    'RuntimeError', 'ValueError', 'TypeError', 'ValidationError', 'TimeoutError', 'UnicodeError',
    'UnicodeDecodeError', 'JSONDecodeError', 'AttributeError', 'NotImplementedError',
    'MemoryError', 'RecursionError', 'OverflowError', 'DatabaseError', 'OperationalError',
    'AnalysisError', 'Exception'})


def error_type_name(error):
    try:
        name = type(error).__name__
    except Exception:  # noqa: BLE001 -- exception types themselves are not trusted data
        return 'Exception'
    return name if type(name) is str and name in ERROR_TYPES else 'Exception'


def error_code(error):
    for kind, code in ((PermissionError, 'PUBLICATION_PERMISSION_DENIED'),
                       (FileExistsError, 'PUBLICATION_OUTPUT_CONFLICT'),
                       (FileNotFoundError, 'PUBLICATION_PATH_UNAVAILABLE'),
                       (OSError, 'PUBLICATION_IO_ERROR'),
                       ((ValueError, TypeError), 'PUBLICATION_INVALID_DATA')):
        if isinstance(error, kind):
            return code
    return 'PUBLICATION_FAILED'


def os_reason(error):
    if not isinstance(error, OSError):
        return 'unspecified'
    try:
        windows, number = getattr(error, 'winerror', None), error.errno
    except Exception:  # noqa: BLE001 -- OS attributes may be overridden by a subclass
        return 'other'
    if type(windows) is int and windows in (32, 33):
        return {32: 'windows_sharing_violation', 33: 'windows_lock_violation'}[windows]
    if number is not None and type(number) is not int:
        return 'other'
    return {errno.EACCES: 'access_denied', errno.EPERM: 'access_denied', errno.ENOENT: 'not_found',
        errno.EEXIST: 'file_exists', errno.ENOSPC: 'no_space', errno.EROFS: 'read_only',
        errno.EMFILE: 'descriptor_limit', None: 'unspecified'}.get(number, 'other')


def safe_details(fields):
    """Only fixed internal vocabulary crosses API/CLI/log boundaries."""
    if type(fields) is not dict or len(fields) > 9:
        return {}
    allowed = {'publication_operation': OPERATIONS, 'publication_error_code': CODES,
        'publication_os_error': OS_REASONS, 'publication_artifact': ARTIFACTS,
        'diagnostics_status': frozenset({'complete', 'partial', 'unavailable'}),
        'cleanup_error_code': CODES, 'diagnostics_error_code': CODES, 'workspace_cleanup_error_code': CODES}
    result = {}
    for key, value in fields.items():
        if type(key) is not str:
            return {}
        if key == 'publication_committed':
            if type(value) is not bool:
                return {}
        elif key not in allowed or type(value) is not str or value not in allowed[key]:
            return {}
        result[key] = value
    return result


@dataclass
class PublicationState:
    operation: str = 'prepare_output'
    artifact: str | None = None
    committed: bool = False
    failure: dict | None = None
    cleanup_code: str | None = None
    diagnostics_code: str | None = None
    diagnostics_status: str = 'unavailable'
    refused_existing_output: bool = False

    def mark(self, operation, artifact=None):
        if operation not in OPERATIONS or artifact is not None and artifact not in ARTIFACTS:
            raise ValueError('Invalid internal publication checkpoint')
        self.operation, self.artifact = operation, artifact

    def capture(self, error):
        if self.failure is None:
            self.failure = {'operation': self.operation, 'artifact': self.artifact,
                'code': error_code(error), 'os_error': os_reason(error), 'error_type': error_type_name(error)}

    def details(self):
        failure = self.failure
        if failure is None:
            return {}
        result = {'publication_operation': failure['operation'], 'publication_error_code': failure['code'],
            'publication_os_error': failure['os_error'], 'publication_committed': self.committed,
            'diagnostics_status': self.diagnostics_status}
        if failure['artifact'] is not None:
            result['publication_artifact'] = failure['artifact']
        if self.cleanup_code:
            result['cleanup_error_code'] = self.cleanup_code
        if self.diagnostics_code:
            result['diagnostics_error_code'] = self.diagnostics_code
        return safe_details(result)


@contextmanager
def staging_directory(parent, state):
    state.mark('create_staging')
    temporary = tempfile.TemporaryDirectory(prefix='.publish-', dir=parent)
    try:
        try:
            yield Path(temporary.name)
        except Exception as error:
            state.capture(error)
            raise
    finally:
        if state.failure is None:
            state.mark('cleanup_staging')
        try:
            temporary.cleanup()
        except Exception as error:
            if state.failure is None:
                raise
            # Preserve the first failure and report the secondary cleanup fault.
            state.cleanup_code = error_code(error)


def commit_directory(source, destination):
    """Publish without replacing a racing empty directory; no power-loss claim."""
    if os.name == 'nt':
        os.rename(source, destination)
        return
    if not sys.platform.startswith('linux'):
        raise OSError('Atomic publication is unsupported on this platform')
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, 'renameat2', None)
    if rename is None:
        raise OSError('Atomic publication is unsupported on this filesystem')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        raise OSError(ctypes.get_errno(), 'Atomic publication failed')
