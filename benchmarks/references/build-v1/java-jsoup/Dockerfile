FROM maven:3.9-eclipse-temurin-17 AS build
ENV MAVEN_OPTS=-XX:ActiveProcessorCount=2
WORKDIR /src
COPY src/ /src/
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom -DoutputFormat=json -DoutputName=sbom -DincludeTestScope=false dependency:copy-dependencies -DincludeScope=runtime
RUN mkdir /jars && find . -path '*/target/*.jar' -type f ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*-tests.jar' ! -name 'original-*' -exec cp {} /jars/ \;
RUN mkdir /reference && find . -name sbom.json -path '*/target/*' -exec cp --parents {} /reference/ \;
FROM scratch AS export
COPY --from=build /reference/ /
