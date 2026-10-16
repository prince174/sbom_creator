from pathlib import Path

import pytest
from complex_reactor_recipe import literal_modules, recipe


def pom(root, name, *, packaging='jar', modules=(), profiles=''):
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'pom.xml').write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><artifactId>test</artifactId>'
        f'<packaging>{packaging}</packaging><modules>' + ''.join(f'<module>{m}</module>' for m in modules)
        + '</modules>' + profiles + '</project>')


def test_nested_modules_and_explicit_disabled_profile_scope(tmp_path):
    pom(tmp_path, '.', packaging='pom', modules=['first', 'nested'], profiles=(
        '<profiles><profile><id>all-modules</id><modules><module>not-selected</module>'
        '</modules></profile></profiles>'))
    pom(tmp_path, 'first')
    pom(tmp_path, 'nested', packaging='pom', modules=['second'])
    pom(tmp_path, 'nested/second')
    plan = literal_modules(tmp_path)
    assert [p['path'] for p in plan] == ['.', 'first', 'nested', 'nested/second']
    text = recipe(plan)
    assert '-P!all-modules' in text
    assert 'not-selected' not in text
    assert '-DoutputReactorProjects=false' in text
    assert 'maven-help-plugin:3.5.1:effective-pom' in text
    assert 'ReactorCollect /src/nested/second' in text
    assert '-Dmaven.test.skip=true' not in text  # Test fixtures must still compile.


@pytest.mark.parametrize('value', ['../outside', '/absolute', 'a;touch_bad', 'a/../b', 'same'])
def test_unsafe_and_duplicate_modules_rejected(tmp_path, value):
    children = [value, value] if value == 'same' else [value]
    pom(tmp_path, '.', packaging='pom', modules=children)
    if value == 'same':
        pom(tmp_path, 'same')
    with pytest.raises(ValueError, match='Unsafe|duplicate'):
        literal_modules(tmp_path)


def test_unreviewed_profile_not_silently_selected():
    with pytest.raises(ValueError, match='profile'):
        recipe([{'path': '.', 'packaging': 'pom'}], profile='release')


@pytest.mark.parametrize('name', ['../outside', 'a;touch_bad', '/absolute'])
def test_recipe_cannot_bypass_literal_path_validation(name):
    with pytest.raises(ValueError, match='Unsafe'):
        recipe([{'path': name, 'packaging': 'jar'}])


def test_no_root_version_or_static_artifact_filename_guess():
    text = recipe([{'path': '.', 'packaging': 'pom'}, {'path': 'a', 'packaging': 'jar'}])
    assert 'cp a/target' not in text
    helper = Path(__file__).with_name('ReactorCollect.java').read_text()
    assert 'text(build, "finalName")' in helper
    assert 'text(root, "version")' in helper
    assert 'disallow-doctype-decl' in helper
