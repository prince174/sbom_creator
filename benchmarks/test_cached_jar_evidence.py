from unittest.mock import patch

import bounded_jar_evidence as frozen
import pytest
from cached_jar_evidence import JarFiles
from test_bounded_jar_evidence import artifact, image, jar


def test_over_budget_layer_is_indexed_once_and_stays_unknown(tmp_path):
    archive, document = image(tmp_path, jar([('x.class', b'\xca\xfe\xba\xbe')]))
    files = JarFiles(archive, document)
    try:
        with patch.object(frozen, 'MAX_LAYER_BYTES', 1), patch.object(
                frozen.tarfile, 'open', wraps=frozen.tarfile.open) as opened:
            for _ in range(20):
                with pytest.raises(frozen.BudgetExceeded, match='Layer index'):
                    files.witness(artifact())
            assert opened.call_count == 1
        assert files.stats['layer_failure_hits'] == 19
        assert files.stats['copied_bytes'] == 0
        assert not files.opened
    finally:
        files.close()


def test_bad_archive_index_is_checked_once(tmp_path):
    archive, document = image(tmp_path, jar([('../bad.class', b'\xca\xfe\xba\xbe')]))
    files = JarFiles(archive, document)
    try:
        with patch.object(frozen, 'zip_index', wraps=frozen.zip_index) as indexed:
            for _ in range(20):
                with pytest.raises(ValueError, match='Unsafe ZIP'):
                    files.witness(artifact())
            assert indexed.call_count == 1
        assert files.stats['archive_failure_hits'] == 19
    finally:
        files.close()


def test_invalid_file_does_not_poison_valid_peer(tmp_path):
    archive, document = image(tmp_path, jar([('x.class', b'\xca\xfe\xba\xbe')]))
    files = JarFiles(archive, document)
    try:
        with pytest.raises(ValueError, match='No final regular'):
            files.source('/missing.jar')
        assert not files.failed_layers
        assert files.witness(artifact()) == '/app.jar:x.class'
        assert files.witness(artifact()) == '/app.jar:x.class'
    finally:
        files.close()


def test_success_matches_frozen_and_rejected_cache_is_bounded(tmp_path):
    archive, document = image(tmp_path, jar([('config.properties', b'x=y')]))
    new, old = JarFiles(archive, document), frozen.JarFiles(archive, document)
    try:
        assert new.witness(artifact()) == old.witness(artifact())
        new.failed_archives.update({(str(i),): (ValueError, 'bad') for i in range(256)})
        assert new.witness(artifact()) == old.witness(artifact())
        with pytest.raises(frozen.BudgetExceeded, match='cache budget'):
            new.archive(('other',), None)
        assert len(new.failed_archives) == 256
    finally:
        new.close()
        old.close()


def test_failed_file_after_index_does_not_retain_closed_layer(tmp_path):
    archive, document = image(tmp_path, jar([('x.class', b'\xca\xfe\xba\xbe')]))
    files = JarFiles(archive, document)
    try:
        metadata = files.files['/app.jar']['metadata']
        metadata['size'] += 1
        with pytest.raises(ValueError, match='metadata disagree'):
            files.source('/app.jar')
        assert not files.opened and not files.failed_layers
        metadata['size'] -= 1
        assert files.witness(artifact()) == '/app.jar:x.class'
    finally:
        files.close()
