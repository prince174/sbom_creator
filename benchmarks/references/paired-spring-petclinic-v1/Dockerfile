FROM maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584 AS build
ENV MAVEN_OPTS=-XX:ActiveProcessorCount=2
WORKDIR /src
COPY src/ /src/
RUN mkdir /reference /application
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -f ./pom.xml -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DoutputName=sbom -DincludeTestScope=false -DincludeProvidedScope=false -DincludeSystemScope=false org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies -DincludeScope=runtime && test "$(find ./target -maxdepth 1 -name '*bom*.json' | wc -l)" = 1 && find ./target -maxdepth 1 -name '*bom*.json' -exec cp {} /reference/sbom.json \; && cp ./target/spring-petclinic-4.0.0-SNAPSHOT.jar /application/ && true
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -f ./pom.xml -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/effective-pom.xml && mvn -B -ntp -f ./pom.xml -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree -Dscope=runtime -DoutputType=json -DoutputFile=/reference/dependency-tree.json && mvn -B -ntp -f ./pom.xml -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true org.apache.maven.plugins:maven-help-plugin:3.5.1:active-profiles -Doutput=/reference/active-profiles.txt && mvn --version > /reference/maven-version.txt && sha256sum /application/*.jar > /reference/jars.sha256
FROM eclipse-temurin:17-jre-jammy@sha256:8993f1aed8b25fcea7a7047a7949c1866fa558fc6830d938c22c4f13b26be9d7 AS runtime
COPY --from=build /application /application
USER 65532:65532
CMD ["java", "-jar", "/application/spring-petclinic-4.0.0-SNAPSHOT.jar"]
