FROM maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584
ENV MAVEN_OPTS=-XX:ActiveProcessorCount=2
WORKDIR /fixture
COPY source/ /fixture/
RUN --mount=type=cache,target=/root/.m2 mkdir /reference && mvn -B -ntp -Pswitch package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DincludeTestScope=false org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/effective-pom.xml && cp target/bom.json /reference/sbom.json
RUN mvn --version > /reference/maven-version.txt
