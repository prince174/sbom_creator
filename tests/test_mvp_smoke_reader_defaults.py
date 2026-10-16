"""The installed default-adoption smoke must not silently pass a feature flag."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'benchmarks'))
from check_mvp_r110_container import package_hashes
from smoke_mvp_container import reader_environment


@pytest.mark.parametrize('nested,archive', [(False, False), (True, False), (False, True), (True, True)])
def test_historical_smoke_modes_remain_explicit_after_service_defaults_change(nested, archive):
    flags = reader_environment(nested_windows=nested, archive_components=archive)
    assert flags == ['--env', 'SBOM_JAVA_NESTED_WINDOWS=' + str(nested).lower(),
                     '--env', 'SBOM_JAVA_ARCHIVE_COMPONENTS=' + str(archive).lower()]


def test_default_adoption_smoke_omits_both_service_reader_environment_overrides():
    flags = reader_environment(reader_defaults=True)
    assert flags == ['--env', 'SMOKE_READER_DEFAULTS=true']
    assert not any(value.startswith(('SBOM_JAVA_NESTED_WINDOWS=', 'SBOM_JAVA_ARCHIVE_COMPONENTS='))
                   for value in flags)


@pytest.mark.parametrize('nested,archive', [(True, False), (False, True), (True, True)])
def test_default_adoption_cannot_be_combined_with_explicit_feature_enablement(nested, archive):
    with pytest.raises(ValueError, match='explicit reader overrides'):
        reader_environment(nested_windows=nested, archive_components=archive, reader_defaults=True)


def test_parent_executing_package_hashes_ignore_frozen_python_cache_records():
    source = {'sbom_creator/file' + str(index) + '.py': str(index) for index in range(47)}
    parent = {**source, 'sbom_creator/__pycache__/file0.cpython-311.pyc': 'not-shipped'}
    assert package_hashes(parent) == {key.removeprefix('sbom_creator/'): value
                                     for key, value in source.items()}


def test_incomplete_parent_package_freeze_cannot_build_an_unbound_container():
    source = {'src/sbom_creator/file' + str(index) + '.py': str(index) for index in range(46)}
    with pytest.raises(ValueError, match='47 frozen installed'):
        package_hashes(source)
