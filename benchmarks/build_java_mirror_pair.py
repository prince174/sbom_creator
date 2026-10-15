"""External reference builder using an explicit public Maven mirror recipe.

Source checkout and analysis stay unchanged. This is not a production service
feature. All versions/platform/profiles are inherited from paired_java.
"""
import paired_java

ORIGINAL_RECIPE = paired_java.recipe
SETTINGS = ('<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"><mirrors><mirror>'
            '<id>benchmark-google-central</id><mirrorOf>central</mirrorOf>'
            '<url>https://maven-central.storage-download.googleapis.com/maven2/</url>'
            '</mirror></mirrors></settings>')


def mirrored_recipe(project):
    text = ORIGINAL_RECIPE(project)
    text = text.replace('mvn ', 'mvn -s /opt/benchmark-settings.xml ')
    marker = 'RUN mkdir /reference /application\n'
    if text.count(marker) != 1:
        raise ValueError('Expected one recipe initialization')
    return text.replace(marker, marker+"RUN printf '%s' '"+SETTINGS+"' > /opt/benchmark-settings.xml\n")


if __name__ == '__main__':
    paired_java.recipe = mirrored_recipe
    paired_java.main()
