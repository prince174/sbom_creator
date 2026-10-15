from build_java_mirror_pair import ORIGINAL_RECIPE, mirrored_recipe


def test_mirror_settings_survive_maven_cache_mount_and_keep_boot_recipe():
    project = {'id': 'java-example', 'expected_package': 'g:example', 'expected_version': '1', 'runtime_kind': 'spring-boot-jar'}
    original = ORIGINAL_RECIPE(project)
    mirrored = mirrored_recipe(project)
    assert '/opt/benchmark-settings.xml' in mirrored
    assert 'mvn -B' not in mirrored
    assert 'mvn -s /opt/benchmark-settings.xml -B' in mirrored
    assert 'cyclonedx-maven-plugin:2.9.3:makeBom' in mirrored
    assert original.split('FROM ', 2)[-1] == mirrored.split('FROM ', 2)[-1]
    assert '<mirrorOf>central</mirrorOf>' in mirrored
