FROM maven:3.9-eclipse-temurin-17 AS build
ENV MAVEN_OPTS=-XX:ActiveProcessorCount=2
WORKDIR /src
COPY src/ /src/
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -pl slf4j-api -am -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom -DoutputFormat=json -DoutputName=sbom -DincludeTestScope=false dependency:copy-dependencies -DincludeScope=runtime
RUN mkdir /jars && find /src/slf4j-api/target -maxdepth 1 -type f -name 'slf4j-api-*.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*test*.jar' ! -name '*obfus*.jar' -exec cp {} /jars/ \; && test "$(find /jars -type f | wc -l)" = 1 && if [ -d /src/slf4j-api/target/dependency ]; then find /src/slf4j-api/target/dependency -maxdepth 1 -type f -name '*.jar' -exec cp {} /jars/ \; ; fi
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -pl slf4j-api org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DoutputName=sbom -DincludeTestScope=false
RUN mkdir /reference && find . -name '*bom*.json' -path '*/target/*' -exec cp --parents {} /reference/ \;
FROM scratch AS export
COPY --from=build /reference/ /
