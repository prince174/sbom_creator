"""Adversarial tests of bounded ZIP-directory credits, without reference input."""
import hashlib
import io
import json
import tarfile
import warnings
import zipfile

import pytest

from sbom_creator.acquire import Settings
from sbom_creator.image_java import bounded_jar_evidence as limits
from sbom_creator.image_java import directory_jar_evidence as candidate
from sbom_creator.image_java import seekable_jar_evidence as legacy


def small_zip(number=0):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr(f'{number:04d}.class', b'\xca\xfe\xba\xbe')
    return output.getvalue()


def parse(reader, raw):
    """One real parser allocation, followed by normal per-witness ZIP closure."""
    archive = reader.archive(('witness',), io.BytesIO(raw))
    try:
        return [member.filename for member in archive.infolist()]
    finally:
        archive.close()
        reader.zips.clear()


@pytest.fixture
def readers(tmp_path):
    # A valid image with no layers is enough to initialize independent readers;
    # each test exercises only their bounded archive() directory allocator.
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'diff_ids': []}}).encode()
    image = {'source': {'metadata': {'imageID': 'sha256:'+hashlib.sha256(config).hexdigest()}},
             'artifacts': [], 'files': []}
    path = tmp_path/'empty-image.tar'
    with tarfile.open(path, 'w') as archive:
        for name, raw in [('manifest.json', b'[{"Config":"config.json","Layers":[]}]'), ('config.json', config)]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    owned = []

    def factory(cls=candidate.JarFiles):
        reader = cls(path, image, temporary=tmp_path)
        owned.append(reader)
        return reader

    yield factory
    for reader in owned:
        for archive in reader.zips.values():
            archive.close()
        reader.close()


def test_more_than_256_small_directories_use_bounded_lru_without_raising_limits(readers):
    reader = readers()
    total = 0
    for number in range(270):
        raw = small_zip(number)
        _, length, _ = candidate.directory(io.BytesIO(raw))
        total += length
        assert parse(reader, raw) == [f'{number:04d}.class']
        assert len(reader.indexes) <= 256
    assert reader.stats['index_bytes'] == total < limits.MAX_INDEX_TOTAL
    assert reader.stats['zip_entries'] == 270 < limits.MAX_ENTRIES
    assert reader.stats['directory_charges'] == 270
    assert reader.stats['directory_cache_entries'] == 256
    assert reader.stats['directory_cache_evictions'] == 14


def test_evicted_directory_is_billed_again_and_does_not_refund_ledger(readers):
    reader = readers()
    first = small_zip(0)
    _, length, fingerprint = candidate.directory(io.BytesIO(first))
    for number in range(257):
        parse(reader, small_zip(number))
    assert fingerprint not in reader.indexes
    before = reader.stats['index_bytes'], reader.stats['zip_entries']
    parse(reader, first)
    assert reader.stats['index_bytes'] == before[0]+length
    assert reader.stats['zip_entries'] == before[1]+1
    assert reader.stats['directory_charges'] == 258
    assert reader.stats['directory_cache_evictions'] == 2
    assert len(reader.indexes) == 256


def test_retained_fingerprint_avoids_rebilling_but_is_parsed_again(readers):
    reader = readers()
    raw = small_zip()
    parse(reader, raw)
    before = reader.stats['index_bytes'], reader.stats['zip_entries']
    for _ in range(20):
        parse(reader, raw)
    assert (reader.stats['index_bytes'], reader.stats['zip_entries']) == before
    assert reader.stats['directory_charges'] == 1
    assert reader.stats['directory_cache_hits'] == 20
    assert reader.stats['zip_parse_entries'] == 21


def test_cache_hit_updates_lru_order_instead_of_fifo_eviction(readers):
    reader = readers()
    for number in range(256):
        parse(reader, small_zip(number))
    first = candidate.directory(io.BytesIO(small_zip(0)))[2]
    second = candidate.directory(io.BytesIO(small_zip(1)))[2]
    parse(reader, small_zip(0))
    parse(reader, small_zip(256))
    assert first in reader.indexes
    assert second not in reader.indexes
    assert len(reader.indexes) == 256


@pytest.mark.parametrize('counter,limit,reason', [
    ('index_bytes', limits.MAX_INDEX_TOTAL, 'ZIP directory byte ledger budget'),
    ('zip_entries', limits.MAX_ENTRIES, 'ZIP directory entry ledger budget')])
def test_exhausted_ledger_rejects_before_zipfile_allocation_without_cache_mutation(readers, monkeypatch, counter, limit, reason):
    reader = readers()
    for number in range(256):
        parse(reader, small_zip(number))
    raw = small_zip(999)
    before = list(reader.indexes), reader.stats['directory_cache_evictions']
    reader.stats[counter] = limit

    def unexpected_allocation(*args, **kwargs):
        pytest.fail('ZipFile allocated after the directory ledger was exhausted')

    monkeypatch.setattr(candidate.zipfile, 'ZipFile', unexpected_allocation)
    with pytest.raises(limits.BudgetExceeded, match=reason):
        reader.archive(('rejected',), io.BytesIO(raw))
    assert (list(reader.indexes), reader.stats['directory_cache_evictions']) == before
    assert reader.stats[counter] == limit


def test_evicted_duplicate_cannot_borrow_credit_when_ledger_is_full(readers, monkeypatch):
    reader = readers()
    raw = small_zip(0)
    fingerprint = candidate.directory(io.BytesIO(raw))[2]
    for number in range(257):
        parse(reader, small_zip(number))
    assert fingerprint not in reader.indexes
    reader.stats['index_bytes'] = limits.MAX_INDEX_TOTAL

    def unexpected_allocation(*args, **kwargs):
        pytest.fail('An evicted duplicate bypassed the full ledger')

    monkeypatch.setattr(candidate.zipfile, 'ZipFile', unexpected_allocation)
    with pytest.raises(limits.BudgetExceeded, match='byte ledger budget'):
        reader.archive(('rejected',), io.BytesIO(raw))
    assert fingerprint not in reader.indexes


def test_single_oversized_directory_is_rejected_before_zipfile_allocation(readers, monkeypatch):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for number in range(33):
            info = zipfile.ZipInfo(f'{number}.class')
            info.comment = b'x'*65_535
            archive.writestr(info, b'\xca\xfe\xba\xbe')
    raw = output.getvalue()
    reader = readers()

    def unexpected_allocation(*args, **kwargs):
        pytest.fail('ZipFile allocated before checking the per-directory limit')

    monkeypatch.setattr(candidate.zipfile, 'ZipFile', unexpected_allocation)
    with pytest.raises(limits.BudgetExceeded, match='ZIP directory budget'):
        reader.archive(('rejected',), io.BytesIO(raw))
    assert not reader.indexes
    assert reader.stats['index_bytes'] == 0


@pytest.mark.parametrize('kind', ['duplicate', 'traversal'])
def test_cached_directory_never_caches_structural_or_path_acceptance(readers, kind):
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(output, 'w') as archive:
            for _ in range(2 if kind == 'duplicate' else 1):
                archive.writestr('X.class' if kind == 'duplicate' else '../X.class', b'\xca\xfe\xba\xbe')
    raw = output.getvalue()
    reader = readers()
    for _ in range(3):
        with pytest.raises(ValueError, match='Ambiguous ZIP directory|Unsafe ZIP member'):
            reader.archive(('rejected',), io.BytesIO(raw))
    assert reader.stats['directory_charges'] == 1
    assert reader.stats['directory_cache_hits'] == 2
    assert reader.stats['zip_parse_entries'] == (6 if kind == 'duplicate' else 3)
    assert not reader.zips


def test_legacy_default_keeps_prior_directory_capacity_policy(readers):
    assert Settings().java_nested_windows is False
    reader = readers(legacy.JarFiles)
    for number in range(256):
        parse(reader, small_zip(number))
    with pytest.raises(limits.BudgetExceeded, match='Unique ZIP directory budget'):
        parse(reader, small_zip(256))
    assert len(reader.indexes) == 256
    assert reader.stats['zip_entries'] == 256


def test_guard_diagnostics_only_record_fixed_known_enums(readers, monkeypatch):
    reader = readers()
    parent = candidate.StoredJarFiles

    def fixed_guard(*args):
        raise limits.BudgetExceeded('ZIP directory entry ledger budget')

    monkeypatch.setattr(parent, 'witness', fixed_guard)
    for _ in range(3):
        with pytest.raises(limits.BudgetExceeded):
            reader.witness({})
    assert reader.stats['budget_guard_counts'] == {'ZIP_DIRECTORY_ENTRIES_TOTAL': 3}

    def untrusted_text(*args):
        raise ValueError('secret-and-image-controlled-path')

    monkeypatch.setattr(parent, 'witness', untrusted_text)
    with pytest.raises(ValueError, match='secret-and-image-controlled-path'):
        reader.witness({})
    assert reader.stats['budget_guard_counts'] == {'ZIP_DIRECTORY_ENTRIES_TOTAL': 3}
