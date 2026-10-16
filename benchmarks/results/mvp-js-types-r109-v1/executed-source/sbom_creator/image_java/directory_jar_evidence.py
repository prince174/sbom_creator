"""Experimental bounded directory-credit cache; evictions never refund work.

At most 256 fingerprints stay in memory. An evicted directory is charged again
if encountered later. Byte/entry ledgers therefore remain conservative, with the
same pre-allocation limits and independent ZIP parsing on every witness.
"""
import zipfile
from collections import OrderedDict

from . import bounded_jar_evidence as frozen
from .stored_jar_evidence import JarFiles as StoredJarFiles
from .stored_jar_evidence import directory

GUARDS = {
    'ZIP directory byte ledger budget': 'ZIP_DIRECTORY_BYTES_TOTAL',
    'ZIP directory entry ledger budget': 'ZIP_DIRECTORY_ENTRIES_TOTAL',
    'ZIP directory budget': 'ZIP_DIRECTORY_SINGLE',
    'File view budget': 'FILE_VIEWS',
    'Content verification read budget': 'VERIFICATION_READ_BYTES',
    'Witness job deadline': 'WITNESS_DEADLINE',
    'Outer archive size budget': 'OUTER_ARCHIVE_BYTES',
    'Nested archive inflate budget': 'NESTED_INFLATE',
    'Nested archive depth': 'NESTED_DEPTH',
    'Disk copy budget': 'DISK_COPY_OR_SPOOL_COUNT',
    'Payload read budget': 'PAYLOAD_READ_BYTES',
    'Layer normalization budget': 'LAYER_NORMALIZATION_BYTES',
}


class JarFiles(StoredJarFiles):
    def __init__(self, archive, document, *, temporary=None):
        super().__init__(archive, document, temporary=temporary)
        self.indexes = OrderedDict()
        self.stats.update(directory_cache_entries=0, directory_cache_evictions=0,
                          directory_cache_hits=0, directory_charges=0, budget_guard_counts={})

    def archive(self, key, stream):
        if key in self.zips:
            return self.zips[key]
        entries, length, fingerprint = directory(stream)
        if fingerprint not in self.indexes:
            # Check before mutating the cache or allocating ZipFile. Rejected
            # archives cannot evict a useful entry or borrow an old credit.
            if length > frozen.MAX_INDEX_TOTAL-self.stats['index_bytes']:
                raise frozen.BudgetExceeded('ZIP directory byte ledger budget')
            if entries > frozen.MAX_ENTRIES-self.stats['zip_entries']:
                raise frozen.BudgetExceeded('ZIP directory entry ledger budget')
            if len(self.indexes) >= 256:
                self.indexes.popitem(last=False)
                self.stats['directory_cache_evictions'] += 1
            self.indexes[fingerprint] = None
            self.stats['index_bytes'] += length
            self.stats['zip_entries'] += entries
            self.stats['directory_charges'] += 1
            self.stats['directory_cache_entries'] = len(self.indexes)
        else:
            self.indexes.move_to_end(fingerprint)
            self.stats['directory_cache_hits'] += 1
        # Billing caches directory identity only, never a parser result. Every
        # archive still passes the frozen structural/member/path validation.
        archive = zipfile.ZipFile(stream)
        try:
            items = archive.infolist()
            self.stats['zip_parse_entries'] += len(items)
            if len(items) != entries or len({m.filename for m in items}) != len(items):
                raise ValueError('Ambiguous ZIP directory')
            if any(not frozen.safe_member(m) for m in items):
                raise ValueError('Unsafe ZIP member')
            self.zips[key] = archive
            return archive
        except BaseException:
            archive.close()
            raise

    def witness(self, artifact):
        try:
            return super().witness(artifact)
        except ValueError as error:
            code = GUARDS.get(str(error))
            if code:
                counts = self.stats['budget_guard_counts']
                counts[code] = counts.get(code, 0)+1
            raise
