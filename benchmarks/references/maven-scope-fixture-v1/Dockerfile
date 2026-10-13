FROM maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584
ENV MAVEN_OPTS=-XX:ActiveProcessorCount=2
WORKDIR /fixture
COPY inherited/ /fixture/inherited/
COPY override/ /fixture/override/
COPY profile/ /fixture/profile/
RUN mkdir -p /reference
RUN --mount=type=cache,target=/root/.m2 mkdir /reference/inherited && mvn -B -ntp -f inherited/child/pom.xml  package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DincludeTestScope=true org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/inherited/effective-pom.xml && cp inherited/child/target/bom.json /reference/inherited/sbom.json
RUN --mount=type=cache,target=/root/.m2 mkdir /reference/override && mvn -B -ntp -f override/child/pom.xml  package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DincludeTestScope=true org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/override/effective-pom.xml && cp override/child/target/bom.json /reference/override/sbom.json
RUN --mount=type=cache,target=/root/.m2 mkdir /reference/profile && mvn -B -ntp -f profile/child/pom.xml -Pswitch package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DincludeTestScope=true org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/profile/effective-pom.xml && cp profile/child/target/bom.json /reference/profile/sbom.json
RUN mvn --version > /reference/maven-version.txt
